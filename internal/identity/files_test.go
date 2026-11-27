package identity

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

// filesSSHWorker opens echoing terminals and Files sessions over a tiny
// folder, and counts both, so a test can show what never started.
type filesSSHWorker struct {
	terminals, files atomic.Int32
	mu               sync.Mutex
	modes            []terminalweb.FilesMode
}

func (w *filesSSHWorker) OpenSSH(ctx context.Context, t *targetguard.NamedTarget, pin []byte, user string, auth sshkey.Credential) (terminalweb.Stream, error) {
	w.terminals.Add(1)
	return echoSSHWorker{}.OpenSSH(ctx, t, pin, user, auth)
}
func (w *filesSSHWorker) OpenFiles(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, _ string, _ sshkey.Credential, mode terminalweb.FilesMode) (terminalweb.FilesStream, error) {
	w.files.Add(1)
	w.mu.Lock()
	w.modes = append(w.modes, mode)
	w.mu.Unlock()
	s := &folderStream{replies: make(chan terminalweb.FileReply, 16)}
	context.AfterFunc(ctx, func() { _ = s.Close() })
	return s, nil
}

type folderStream struct {
	mu      sync.Mutex
	closed  bool
	replies chan terminalweb.FileReply
}

func (s *folderStream) Send(r terminalweb.FileRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errRefused
	}
	if r.Op == terminalweb.OpList {
		s.replies <- terminalweb.FileReply{Kind: terminalweb.ReplyEntries, ID: r.ID, Entries: []terminalweb.FileEntry{{Name: []byte("notes.txt"), Kind: terminalweb.KindFile, Size: 5}}}
		s.replies <- terminalweb.FileReply{Kind: terminalweb.ReplyDone, ID: r.ID, Path: "/home/deploy"}
		return nil
	}
	s.replies <- terminalweb.FileReply{Kind: terminalweb.ReplyDone, ID: r.ID}
	return nil
}
func (s *folderStream) Upload([]byte) error                   { return nil }
func (s *folderStream) Cancel(uint32) error                   { return nil }
func (s *folderStream) Replies() <-chan terminalweb.FileReply { return s.replies }
func (s *folderStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.replies)
	}
	return nil
}

type filesLab struct {
	*adminLab
	worker  *filesSSHWorker
	origin  string
	https   *httptest.Server
	server  string // an SSH server alice added
	account string // its account, with bob on it
	bob     *custodyClient
}

func filesFixture(t *testing.T) *filesLab {
	t.Helper()
	store, _, _ := bootstrapped(t)
	https := httptest.NewUnstartedServer(nil)
	origin := "https://" + https.Listener.Addr().String()
	f := &adminLab{t: t, store: store, now: time.Now(), target: catalogSSHFixture(t)}
	_, _, codes := enrollFixture(t, store, "alice", f.now)
	worker := &filesSSHWorker{}
	l, e := NewRemoteLabWithLimits(origin, store, []RemoteTarget{f.target}, worker, nil, sessionlimits.Default(), TargetNetworks(serverNetworks, serverProtected))
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	t.Cleanup(func() { _ = l.Close() })
	https.Config.Handler = l
	https.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	https.StartTLS()
	t.Cleanup(https.Close)
	scans := &fixtureScans{keys: map[netip.AddrPort]ssh.PublicKey{}}
	f.l = l
	l.mu.Lock()
	l.now = func() time.Time { return f.now }
	l.remote.scan = scans.scan
	l.mu.Unlock()
	f.alice = &custodyClient{t: t, l: l}
	f.alice.login()
	f.alice.session("challenge")
	f.alice.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	f.alice.session("ready")
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	f.codes = codes[2:]
	server, _ := addServerFixture(t, f.alice, scans, "Build", "10.20.0.7:22")
	bob, b := f.person("bob", roleUser)
	account := accountFixture(t, l, server, "deploy", "", b.ID)
	return &filesLab{adminLab: f, worker: worker, origin: origin, https: https, server: server, account: account, bob: bob}
}

func (f *filesLab) card() accessRow {
	f.t.Helper()
	var rows []accessRow
	if json.Unmarshal(f.bob.expect("GET", "/api/access", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 {
		f.t.Fatal("access list malformed")
	}
	return rows[0]
}

func (f *filesLab) setFiles(value string) {
	f.t.Helper()
	f.alice.expect("POST", "/api/servers/"+f.server+"/files", inputJSON(map[string]string{"files": value}), 204)
}

// lease asks for a lease the way a page does, at path.
func (f *filesLab) lease(path string, status int) string {
	f.t.Helper()
	w := f.bob.expect("POST", path, inputJSON(map[string]string{"account": f.account}), status)
	var data struct{ Lease, Mode string }
	if status == 200 && (json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data.Lease) != 43) {
		f.t.Fatal("lease missing")
	}
	return data.Lease
}

// socket opens a socket at path and sends the page's proof with lease.
func (f *filesLab) socket(ctx context.Context, path, lease string) *websocket.Conn {
	f.t.Helper()
	header := http.Header{"Origin": []string{f.origin}, "Cookie": []string{f.bob.cookie.String()}}
	conn, _, e := websocket.Dial(ctx, strings.Replace(f.origin, "https:", "wss:", 1)+path, &websocket.DialOptions{HTTPClient: f.https.Client(), HTTPHeader: header})
	if e != nil {
		f.t.Fatalf("socket %s refused: %v", path, e)
	}
	if conn.Write(ctx, websocket.MessageText, []byte(inputJSON(map[string]string{"csrf": f.bob.csrf, "lease": lease}))) != nil {
		f.t.Fatal("proof write failed")
	}
	return conn
}

func TestFilesSwitchIsAnAdministratorsChoice(t *testing.T) {
	f := filesFixture(t)
	dave, _ := f.person("dave", roleAuditor)
	page := "/remote/files/" + f.account
	if f.card().Files != "" {
		t.Fatal("a new server allows files")
	}
	f.lease("/api/remote/files", 401)
	if w := f.bob.call("GET", page, ""); w.Code != 404 || strings.Contains(w.Body.String(), `data-owned-remote="files"`) {
		t.Fatalf("the Files page opened while files are off: %d", w.Code)
	}

	path := "/api/servers/" + f.server + "/files"
	for _, body := range []string{
		inputJSON(map[string]string{"files": "all"}), inputJSON(map[string]string{"files": ""}), inputJSON(map[string]string{"files": "Both"}),
		inputJSON(map[string]string{"files": "both", "server": "x"}), `{"files":true}`, `not json`,
	} {
		f.alice.expect("POST", path, body, 400)
	}
	for _, c := range []*custodyClient{f.bob, dave} {
		c.expect("POST", path, inputJSON(map[string]string{"files": "both"}), 403)
	}
	f.alice.expect("POST", "/api/servers/"+strings.Repeat("e", 32)+"/files", inputJSON(map[string]string{"files": "both"}), 404)
	if f.card().Files != "" {
		t.Fatal("a refused request changed the switch")
	}

	f.setFiles("download")
	if card := f.card(); card.Files != "download" || card.Trust != "verified" {
		t.Fatalf("card after download only: %+v", card)
	}
	if row, _ := serverRow(listServersView(t, f.alice), f.server); row.Files != "download" {
		t.Fatalf("server row: %+v", row)
	}
	if w := f.bob.call("GET", page, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `data-owned-remote="files"`) {
		t.Fatalf("the Files page did not open: %d", w.Code)
	}
	w := f.bob.expect("POST", "/api/remote/files", inputJSON(map[string]string{"account": f.account}), 200)
	if !strings.Contains(w.Body.String(), `"mode":"download"`) {
		t.Fatalf("grant: %s", w.Body.String())
	}
	f.bob.expect("POST", "/api/remote/files", inputJSON(map[string]string{"account": f.account, "mode": "both"}), 400)
	dave.expect("POST", "/api/remote/files", inputJSON(map[string]string{"account": f.account}), 403)

	// A change, like any server change, needs a fresh factor.
	f.advance(freshProof + time.Minute)
	f.alice.expect("POST", path, inputJSON(map[string]string{"files": "both"}), 428)
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": f.codes[0]}), 204)
	f.setFiles("both")
	if f.card().Files != "both" {
		t.Fatal("upload and download did not take")
	}
	f.setFiles("off")
	if f.card().Files != "" {
		t.Fatal("off did not take")
	}
	f.lease("/api/remote/files", 401)
	if list, _ := f.store.listServers(); !strings.Contains(func() string {
		for _, s := range list {
			if s.ID == f.server {
				return "files=" + s.Files + ";"
			}
		}
		return ""
	}(), "files=;") {
		t.Fatal("the stored record kept a setting after off")
	}
}

func TestFilesSettingBelongsToSSH(t *testing.T) {
	for _, c := range []struct {
		protocol, files string
		ok              bool
	}{{"ssh", "", true}, {"ssh", "download", true}, {"ssh", "both", true}, {"rdp", "", true}, {"rdp", "download", false}, {"rdp", "both", false}, {"ssh", "all", false}, {"ssh", "off", false}} {
		if validFilesSetting(c.protocol, c.files) != c.ok {
			t.Errorf("%s with %q: want %v", c.protocol, c.files, c.ok)
		}
	}
}

// A terminal's lease never opens Files, a Files lease never opens a
// terminal, and the Files socket opens what the server allows.
func TestFilesSocketTakesOnlyAFilesLease(t *testing.T) {
	f := filesFixture(t)
	f.setFiles("both")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	refused := func(conn *websocket.Conn) {
		t.Helper()
		if _, data, e := conn.Read(ctx); e == nil {
			t.Fatalf("the socket answered %q", data)
		}
	}
	refused(f.socket(ctx, "/api/remote/files-socket", f.lease("/api/remote/open", 200)))
	refused(f.socket(ctx, "/api/remote/socket", f.lease("/api/remote/files", 200)))
	if f.worker.files.Load() != 0 || f.worker.terminals.Load() != 0 {
		t.Fatal("a lease of the other kind started a worker")
	}

	conn := f.socket(ctx, "/api/remote/files-socket", f.lease("/api/remote/files", 200))
	_, data, e := conn.Read(ctx)
	var ready struct{ Type, Mode, Server, Account, Host string }
	if e != nil || json.Unmarshal(data, &ready) != nil || ready.Type != "ready" || ready.Mode != "both" || ready.Server != "Build" || ready.Account != "deploy" {
		t.Fatalf("ready = %q, %v", data, e)
	}
	if conn.Write(ctx, websocket.MessageText, []byte(`{"type":"list","id":1,"path":""}`)) != nil {
		t.Fatal("write failed")
	}
	if _, data, e = conn.Read(ctx); e != nil || !strings.Contains(string(data), `"name":"notes.txt"`) {
		t.Fatalf("entries = %q, %v", data, e)
	}
	if _, data, e = conn.Read(ctx); e != nil || !strings.Contains(string(data), `"type":"done"`) {
		t.Fatalf("done = %q, %v", data, e)
	}

	// Changing the switch ends the open Files session, and says why.
	f.setFiles("download")
	if _, data, e = conn.Read(ctx); e != nil || string(data) != `{"type":"ended","reason":"access-changed"}` {
		t.Fatalf("after the switch changed: %q, %v", data, e)
	}
	f.worker.mu.Lock()
	modes := append([]terminalweb.FilesMode(nil), f.worker.modes...)
	f.worker.mu.Unlock()
	if len(modes) != 1 || modes[0] != terminalweb.FilesBoth {
		t.Fatalf("the worker opened %v", modes)
	}
	// The new session opens with the new mode.
	conn = f.socket(ctx, "/api/remote/files-socket", f.lease("/api/remote/files", 200))
	if _, data, e = conn.Read(ctx); e != nil || !strings.Contains(string(data), `"mode":"download"`) {
		t.Fatalf("ready after the change = %q, %v", data, e)
	}
}

// A Files lease granted before the server was switched off opens nothing.
func TestFilesLeaseIsCheckedAgainAtRedeem(t *testing.T) {
	f := filesFixture(t)
	f.setFiles("both")
	lease := f.lease("/api/remote/files", 200)
	f.setFiles("off")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := f.socket(ctx, "/api/remote/files-socket", lease)
	if _, data, e := conn.Read(ctx); e == nil {
		t.Fatalf("a lease from before the switch went off answered %q", data)
	}
	if f.worker.files.Load() != 0 {
		t.Fatal("a stale lease started a Files worker")
	}

	// The redeem checks the mode itself, not only through the reload that
	// drops a changed lease: here the mode moves under a lease that stayed.
	f.setFiles("both")
	lease = f.lease("/api/remote/files", 200)
	f.l.mu.Lock()
	info := f.l.remote.accounts[f.account]
	info.files = "download"
	f.l.remote.accounts[f.account] = info
	f.l.mu.Unlock()
	conn = f.socket(ctx, "/api/remote/files-socket", lease)
	if _, data, e := conn.Read(ctx); e == nil {
		t.Fatalf("a lease for another mode answered %q", data)
	}
	if f.worker.files.Load() != 0 {
		t.Fatal("a lease for another mode started a Files worker")
	}
}
