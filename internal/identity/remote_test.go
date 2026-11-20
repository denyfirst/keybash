package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
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
	"github.com/denyfirst/keybash/web"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// fixtureRDPWorker plays Keybash's RDP proxy: each desktop it opens is a
// fixtureMessages, and it can hold a desktop at setup until released.
type fixtureRDPWorker struct {
	calls    atomic.Int32
	started  chan struct{}
	release  chan struct{}
	closed   chan struct{}
	once     sync.Once             // closed is closed once, however many desktops a test opens
	messages chan *fixtureMessages // each desktop opened, for the test to inspect
	expected string
}

func (f *fixtureRDPWorker) OpenBrowserRDP(ctx context.Context, r RDPRequest) (terminalweb.MessageStream, error) {
	if r.Password != f.expected || r.Username != "synthetic-user" || r.Target.Hostname() != "rdp.invalid" {
		return nil, errRefused
	}
	f.calls.Add(1)
	if f.started != nil {
		close(f.started)
	}
	if f.release != nil {
		<-f.release
	}
	m := newFixtureMessages()
	go func() {
		<-ctx.Done()
		_ = m.Close()
		if f.closed != nil {
			f.once.Do(func() { close(f.closed) })
		}
	}()
	if f.messages != nil {
		f.messages <- m
	}
	return m, nil
}

// terminalWorker plays the SSH worker: an echo terminal for the account
// "deploy", counted, which can be held at setup until released and says when
// its context ends.
type terminalWorker struct {
	calls            atomic.Int32
	started, release chan struct{}
	closed           chan struct{}
	once             sync.Once // closed is closed once, however many terminals a test opens
}

func (w *terminalWorker) OpenSSH(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, user string, _ sshkey.Credential) (terminalweb.Stream, error) {
	if user != "deploy" {
		return nil, errRefused
	}
	w.calls.Add(1)
	if w.started != nil {
		close(w.started)
	}
	if w.release != nil {
		<-w.release
	}
	left, right := net.Pipe()
	go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
	go func() { <-ctx.Done(); _ = left.Close(); w.once.Do(func() { close(w.closed) }) }()
	return fixtureRemoteStream{left}, nil
}

type fixtureRemoteStream struct{ net.Conn }

func (fixtureRemoteStream) ReadStderr([]byte) (int, error) { return 0, io.EOF }
func (fixtureRemoteStream) Resize(uint32, uint32) error    { return nil }
func remoteTargetFixture(t *testing.T) RemoteTarget {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal("fixture key failed")
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"rdp.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal("fixture cert failed")
	}
	ip := netip.MustParseAddr("10.34.0.8")
	policy, e := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 3389)}, nil)
	if e != nil {
		t.Fatal("fixture policy failed")
	}
	target, e := targetguard.NewNamedTarget(policy, "rdp.invalid", 3389, []netip.Addr{ip})
	if e != nil {
		t.Fatal("fixture target failed")
	}
	return RemoteTarget{strings.Repeat("a", 32), "Synthetic desktop", "rdp", target, der}
}
func remoteFixture(t *testing.T, origin string) (*Lab, *Store, *custodyClient, string, *fixtureRDPWorker) {
	return remoteFixtureWithLimits(t, origin, sessionlimits.Default())
}

func remoteFixtureWithLimits(t *testing.T, origin string, limits sessionlimits.Limits) (*Lab, *Store, *custodyClient, string, *fixtureRDPWorker) {
	t.Helper()
	store, _, _ := bootstrapped(t)
	_, _, codes := enrollFixture(t, store, "alice", time.Now())
	target := remoteTargetFixture(t)
	worker := &fixtureRDPWorker{expected: "Synthetic remote password", closed: make(chan struct{}), messages: make(chan *fixtureMessages, 4)}
	l, e := NewRemoteLabWithLimits(origin, store, []RemoteTarget{target}, nil, worker, limits)
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	t.Cleanup(func() { _ = l.Close() })
	openTo(t, l, mustLookup(t, store, "alice").ID)
	c := &custodyClient{t: t, l: l}
	c.login()
	c.session("challenge")
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	c.session("ready")
	c.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	a, _ := store.lookup("alice")
	credential, e := store.putCredential(a.ID, Credential{Name: "Synthetic remote", Kind: "password", Username: "synthetic-user", Secret: worker.expected})
	if e != nil {
		t.Fatal("fixture credential failed")
	}
	w := c.expect("POST", "/api/connections", inputJSON(map[string]string{"name": "Synthetic connection", "target": target.ID, "credential": credential, "approval": approvalFingerprint(target)}), 200)
	var record struct{ ID string }
	if json.Unmarshal(w.Body.Bytes(), &record) != nil || !validID(record.ID) {
		t.Fatal("connection creation failed")
	}
	return l, store, c, record.ID, worker
}
func grantFixture(t *testing.T, c *custodyClient, record string) string {
	t.Helper()
	w := c.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 200)
	var data struct{ Lease string }
	if json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data.Lease) != 43 {
		t.Fatal("lease missing")
	}
	return data.Lease
}
func TestOwnedRemoteLeaseOwnershipReplayExpiryAndRevocation(t *testing.T) {
	l, store, c, record, worker := remoteFixture(t, "https://127.0.0.1:8443")
	a, _ := store.lookup("alice")
	raw := grantFixture(t, c, record)
	id, _ := tokenID(c.cookie.Value)
	// A second browser belonging to the SAME account cannot redeem this lease.
	l.mu.Lock()
	otherRaw, e := l.issueLocked("alice", "")
	if e != nil {
		l.mu.Unlock()
		t.Fatal("fixture rotation failed")
	}
	otherID, _ := tokenID(otherRaw)
	l.sessions[otherID].stage = "ready"
	l.sessions[otherID].reauthUntil = l.now().Add(time.Minute)
	if _, _, _, _, e = l.redeemRemoteLocked(otherID, raw); e == nil {
		l.mu.Unlock()
		t.Fatal("other browser consumed lease")
	}
	lease, _, credential, ctx, e := l.redeemRemoteLocked(id, raw)
	if e != nil || credential.Secret != worker.expected {
		l.mu.Unlock()
		t.Fatal("valid lease refused")
	}
	if _, _, _, _, e = l.redeemRemoteLocked(id, raw); e == nil {
		l.mu.Unlock()
		t.Fatal("lease replay accepted")
	}
	l.mu.Unlock()
	c.expect("DELETE", "/api/session", "{}", 204)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("logout did not revoke remote context")
	}
	if !lease.active {
		t.Fatal("lease never activated")
	}
	if rows, e := store.listConnections(a.ID); e != nil || len(rows) != 1 {
		t.Fatal("connection persistence failed")
	}
	if _, e = store.readConnection(strings.Repeat("b", 32), record); e == nil {
		t.Fatal("cross-account connection read accepted")
	}
	if worker.calls.Load() != 0 {
		t.Fatal("authorization-only calls started worker")
	}
}
func TestOwnedRemoteExpiryLimitsAndDelete(t *testing.T) {
	l, _, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	now := time.Now()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	raw := grantFixture(t, c, record)
	_ = grantFixture(t, c, record)
	c.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 503)
	advance(l, &now, 31*time.Second)
	id, _ := tokenID(c.cookie.Value)
	l.mu.Lock()
	if _, _, _, _, e := l.redeemRemoteLocked(id, raw); e == nil {
		l.mu.Unlock()
		t.Fatal("expired lease accepted")
	}
	l.mu.Unlock()
	raw = grantFixture(t, c, record)
	l.mu.Lock()
	_, _, _, ctx, e := l.redeemRemoteLocked(id, raw)
	l.mu.Unlock()
	if e != nil {
		t.Fatal("valid renewed lease refused")
	}
	c.expect("DELETE", "/api/connections/"+record, "{}", 204)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("connection deletion did not revoke")
	}
	c.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 401)
}

// terminalFixture is remoteFixture for an SSH server: alice, ready and freshly
// proved, owns one connection to it, with a password for "deploy".
func terminalFixture(t *testing.T, origin string, worker SSHWorker) (*Lab, *custodyClient, string) {
	t.Helper()
	store, _, _ := bootstrapped(t)
	_, _, codes := enrollFixture(t, store, "alice", time.Now())
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	ip := netip.MustParseAddr("10.34.0.9")
	policy, e := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 22)}, nil)
	if e != nil {
		t.Fatal(e)
	}
	named, e := targetguard.NewNamedTarget(policy, "ssh.invalid", 22, []netip.Addr{ip})
	if e != nil {
		t.Fatal(e)
	}
	target := RemoteTarget{strings.Repeat("c", 32), "Synthetic SSH", "ssh", named, hostSigner.PublicKey().Marshal()}
	l, e := NewRemoteLab(origin, store, []RemoteTarget{target}, worker, nil)
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	t.Cleanup(func() { _ = l.Close() })
	openTo(t, l, mustLookup(t, store, "alice").ID)
	c := &custodyClient{t: t, l: l}
	c.login()
	c.session("challenge")
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	c.session("ready")
	c.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	a, _ := store.lookup("alice")
	credential, e := store.putCredential(a.ID, Credential{Name: "Synthetic login", Kind: "password", Username: "deploy", Secret: "Synthetic remote password"})
	if e != nil {
		t.Fatal("fixture credential failed")
	}
	w := c.expect("POST", "/api/connections", inputJSON(map[string]string{"name": "Synthetic terminal", "target": target.ID, "credential": credential, "approval": approvalFingerprint(target)}), 200)
	var record struct{ ID string }
	if json.Unmarshal(w.Body.Bytes(), &record) != nil || !validID(record.ID) {
		t.Fatal("connection creation failed")
	}
	return l, c, record.ID
}

func TestOwnedRemoteSocketEchoLogoutAndLateSetup(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "late"}[late], func(t *testing.T) {
			server, origin := tlsFixture(t)
			worker := &terminalWorker{closed: make(chan struct{})}
			l, c, record := terminalFixture(t, origin, worker)
			startTLS(t, server, l)
			if late {
				worker.started = make(chan struct{})
				worker.release = make(chan struct{})
			}
			raw := grantFixture(t, c, record)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			header := http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}
			socket, _, e := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/socket", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: header})
			if e != nil {
				t.Fatal("valid socket refused")
			}
			defer socket.CloseNow()
			proof := inputJSON(map[string]string{"csrf": c.csrf, "lease": raw})
			if socket.Write(ctx, websocket.MessageText, []byte(proof)) != nil {
				t.Fatal("proof write failed")
			}
			if late {
				<-worker.started
				c.expect("DELETE", "/api/session", "{}", 204)
				close(worker.release)
			} else {
				_, data, e := socket.Read(ctx)
				if e != nil || string(data) != `{"type":"ready"}` {
					t.Fatal("worker ready missing")
				}
				if socket.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","columns":130,"rows":27}`)) != nil {
					t.Fatal("resize write failed")
				}
				if socket.Write(ctx, websocket.MessageBinary, []byte("synthetic input")) != nil {
					t.Fatal("input refused")
				}
				_, data, e = socket.Read(ctx)
				if e != nil || len(data) < 5 || string(data[4:]) != "synthetic input" {
					t.Fatal("authorized stream did not echo exact bytes")
				}
				c.expect("DELETE", "/api/session", "{}", 204)
				// The page is told why; the relay stops the stream before saying
				// it (TestRelaySaysWhyTheSessionEnded), and the worker is waited
				// for below.
				_, data, e = socket.Read(ctx)
				if e != nil || string(data) != `{"type":"ended","reason":"signed-out"}` {
					t.Fatalf("signed-out reason missing: %q", data)
				}
			}
			if _, _, e = socket.Read(ctx); e == nil {
				t.Fatal("revoked socket remained readable")
			}
			select {
			case <-worker.closed:
			case <-ctx.Done():
				t.Fatal("worker did not observe revocation")
			}
			if worker.calls.Load() != 1 {
				t.Fatal("unexpected worker launch count")
			}
		})
	}
}

// Signing out ends a desktop as it ends a terminal, open or still starting:
// the page's socket ends, and so does the proxy's context.
func TestOwnedDesktopEndsOnSignOutOpenOrStarting(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "starting"}[late], func(t *testing.T) {
			server, origin := tlsFixture(t)
			l, _, c, record, worker := remoteFixture(t, origin)
			startTLS(t, server, l)
			if late {
				worker.started = make(chan struct{})
				worker.release = make(chan struct{})
			}
			raw := grantFixture(t, c, record)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			socket, e := dialDesktop(ctx, server, origin, http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}})
			if e != nil {
				t.Fatal("valid socket refused")
			}
			defer socket.CloseNow()
			if socket.Write(ctx, websocket.MessageBinary, desktopRequest(t, c.csrf+"."+raw)) != nil {
				t.Fatal("the request could not be sent")
			}
			if late {
				<-worker.started
				c.expect("DELETE", "/api/session", "{}", 204)
				close(worker.release)
				if _, _, e := socket.Read(ctx); e == nil {
					t.Fatal("a desktop signed out during setup answered")
				}
			} else {
				<-worker.messages
				if socket.Write(ctx, websocket.MessageBinary, []byte("synthetic input")) != nil {
					t.Fatal("input refused")
				}
				if _, data, e := socket.Read(ctx); e != nil || string(data) != "synthetic input" {
					t.Fatal("the desktop did not pass exact bytes both ways")
				}
				c.expect("DELETE", "/api/session", "{}", 204)
				if code, text := closeCode(ctx, socket); code != 4003 || text != "signed-out" {
					t.Fatalf("signing out closed the desktop with %d %q", code, text)
				}
			}
			select {
			case <-worker.closed:
			case <-ctx.Done():
				t.Fatal("the proxy did not see the sign-out")
			}
			if worker.calls.Load() != 1 {
				t.Fatal("unexpected proxy launch count")
			}
		})
	}
}

// The session page is told which owned connection it serves through its body
// tag, whatever classes the design gives that tag. Without the mark the page
// falls back to the lab login, so an unmarked page is never served.
func TestOwnedRemotePageCarriesItsConnection(t *testing.T) {
	_, _, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	w := c.expect("GET", "/remote/rdp/"+record, "", 200)
	page := w.Body.String()
	start := strings.Index(page, "<body ")
	end := strings.Index(page[start:], ">")
	if start < 0 || end < 0 {
		t.Fatal("owned page has no body tag")
	}
	tag := page[start : start+end]
	if !strings.Contains(tag, `data-owned-remote="rdp"`) || !strings.Contains(tag, `data-connection="`+record+`"`) || !strings.Contains(tag, `class="session-page"`) || strings.Count(page, "data-owned-remote") != 1 {
		t.Fatalf("owned page body tag is not marked for its connection: %s", tag)
	}
	c.expect("GET", "/remote/ssh/"+record, "", 404)
}

// IronRDP's browser client is served exactly as vendored, with the type a
// browser compiles WebAssembly from, and only to a signed-in session. Its
// manifest, crate list and licences are not served.
func TestTheIronRDPModuleIsServedExactlyAsVendored(t *testing.T) {
	l, _, c, _, _ := remoteFixture(t, "https://127.0.0.1:8443")
	for path, kind := range map[string]string{
		"/vendor/ironrdp/ironrdp_web.js":      "text/javascript; charset=utf-8",
		"/vendor/ironrdp/ironrdp_web_bg.wasm": "application/wasm",
	} {
		w := c.expect("GET", path, "", 200)
		want, e := web.Assets.ReadFile(strings.TrimPrefix(path, "/"))
		if e != nil || w.Header().Get("Content-Type") != kind || !bytes.Equal(w.Body.Bytes(), want) {
			t.Fatalf("%s was served as %q, %d bytes", path, w.Header().Get("Content-Type"), w.Body.Len())
		}
		signedOut := custodyClient{t: t, l: l}
		if signedOut.call("GET", path, "").Code == 200 {
			t.Fatalf("%s served without a session", path)
		}
	}
	for _, path := range []string{"/vendor/ironrdp/manifest.json", "/vendor/ironrdp/CRATES.txt", "/vendor/ironrdp/IRONRDP-LICENSE-MIT", "/vendor/ironrdp/", "/vendor/ironrdp/ironrdp_web_bg.wasm/"} {
		if c.call("GET", path, "").Code == 200 {
			t.Fatalf("%s became public", path)
		}
	}
}

// The desktop page is the IronRDP page (BROWSER-RDP-PAGE.md, 3d), and only its
// policy lets WebAssembly compile: 'wasm-unsafe-eval' and nothing else is
// added, and no script may be evaluated. Its scripts are served from the
// gateway alone.
func TestOnlyTheDesktopPageMayCompileWebAssembly(t *testing.T) {
	_, _, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	w := c.expect("GET", "/remote/rdp/"+record, "", 200)
	policy := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "; script-src 'self' 'wasm-unsafe-eval'; ") || strings.Count(policy, "unsafe-eval") != 1 || strings.Contains(policy, "'unsafe-eval'") {
		t.Fatalf("the desktop page's policy: %s", policy)
	}
	if !strings.Contains(w.Body.String(), `<script type="module" src="/remote-desktop.mjs"></script>`) || strings.Contains(w.Body.String(), "guacamole") {
		t.Fatal("the desktop page is not the IronRDP page")
	}
	for _, path := range []string{"/remote-desktop.mjs", "/remote-desktop-input.mjs", "/remote-desktop-gfx.mjs", "/vendor/ironrdp/ironrdp_web.js", "/app.mjs"} {
		w := c.expect("GET", path, "", 200)
		if w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || strings.Contains(w.Header().Get("Content-Security-Policy"), "wasm") {
			t.Fatalf("%s was served as %q with %q", path, w.Header().Get("Content-Type"), w.Header().Get("Content-Security-Policy"))
		}
	}
}

func TestOwnedRemoteConstructorAndMalformedRequests(t *testing.T) {
	store, _, _ := bootstrapped(t)
	target := remoteTargetFixture(t)
	if l, e := NewRemoteLab("https://127.0.0.1:8443", store, []RemoteTarget{target}, nil, nil); e == nil {
		_ = l.Close()
		t.Fatal("RDP without trusted launcher admitted")
	}
	l, _, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	_ = l
	c.expect("POST", "/api/connections", `{"name":"bad","target":"`+target.ID+`","credential":"`+strings.Repeat("a", 32)+`","owner":"other"}`, 400)
	c.expect("POST", "/api/remote/open", `{"connection":"`+record+`","target":"attacker"}`, 400)
	c.expect("POST", "/api/remote/open", `{"connection":"`+record+`","connection":"`+record+`"}`, 400)
	c.expect("GET", "/remote/rdp/"+strings.Repeat("b", 32), "", 404)
}

func TestOwnedRemoteFreshStateCredentialDeletionAndOtherAccount(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	id, _ := tokenID(c.cookie.Value)
	a, _ := store.lookup("alice")
	row, e := store.readConnection(a.ID, record)
	if e != nil {
		t.Fatal("connection missing")
	}
	// Opening an approved connection needs a ready session, not fresh proof;
	// changing stored decisions still needs fresh proof.
	l.mu.Lock()
	saved := l.sessions[id].reauthUntil
	l.sessions[id].reauthUntil = time.Time{}
	l.mu.Unlock()
	staleRaw := grantFixture(t, c, record)
	l.mu.Lock()
	staleLease, _, _, _, e := l.redeemRemoteLocked(id, staleRaw)
	if e != nil {
		l.mu.Unlock()
		t.Fatal("a ready session without fresh proof could not open its own connection")
	}
	staleLease.cancel(nil)
	staleKey, _ := tokenID(staleRaw)
	delete(l.remote.leases, staleKey)
	l.mu.Unlock()
	// Trusting and creating need the ready session only, so these reach their
	// own checks (a stale revision, a wrong fingerprint) without changing
	// anything; deleting asks for fresh proof.
	c.expect("POST", "/api/connections/"+record+"/trust", inputJSON(map[string]string{"approval": row.Approval, "revision": "999"}), 409)
	c.expect("POST", "/api/connections", inputJSON(map[string]string{"name": "again", "target": row.Target, "credential": row.Credential, "approval": strings.Repeat("0", 64)}), 409)
	c.expect("DELETE", "/api/connections/"+record, "{}", 428)
	c.expect("DELETE", "/api/credentials/"+row.Credential, "{}", 428)
	l.mu.Lock()
	l.sessions[id].reauthUntil = saved
	l.mu.Unlock()
	// Readiness (current account revision) is still required on consumption.
	raw := grantFixture(t, c, record)
	l.mu.Lock()
	l.sessions[id].revision--
	if _, _, _, _, e = l.redeemRemoteLocked(id, raw); e == nil {
		l.mu.Unlock()
		t.Fatal("a session from an older account revision redeemed a lease")
	}
	l.sessions[id].revision++
	l.mu.Unlock()
	// This trusted fixture writes another account; HTTP cannot select an owner.
	if _, e := store.CreateAccount("bob", alicePassword); e != nil {
		t.Fatal("second fixture account failed")
	}
	_, _, codes := enrollFixture(t, store, "bob", time.Now())
	bob := &custodyClient{t: t, l: l}
	bob.expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": alicePassword}), 204)
	bob.session("challenge")
	bob.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	bob.session("ready")
	bob.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	bob.expect("POST", "/api/connections", inputJSON(map[string]string{"name": "other", "target": row.Target, "credential": row.Credential, "approval": row.Approval}), 403)
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 401)
	bob.expect("DELETE", "/api/connections/"+record, "{}", 404)
	// An issued but unconsumed grant cannot retain a deleted credential.
	activeRaw := grantFixture(t, c, record)
	l.mu.Lock()
	_, _, _, activeContext, activeError := l.redeemRemoteLocked(id, activeRaw)
	l.mu.Unlock()
	if activeError != nil {
		t.Fatal("active deletion fixture refused")
	}
	c.expect("DELETE", "/api/credentials/"+row.Credential, "{}", 204)
	select {
	case <-activeContext.Done():
	case <-time.After(time.Second):
		t.Fatal("credential deletion did not revoke active remote")
	}
	l.mu.Lock()
	if _, _, _, _, e = l.redeemRemoteLocked(id, raw); e == nil {
		l.mu.Unlock()
		t.Fatal("deleted credential retained launch authority")
	}
	l.mu.Unlock()
}

func TestOwnedConnectionEnvelopePersistenceAndOwnerBinding(t *testing.T) {
	store, key, dir := bootstrapped(t)
	a, _ := store.lookup("alice")
	credential, e := store.putCredential(a.ID, Credential{Name: "fixture", Kind: "password", Secret: "synthetic"})
	if e != nil {
		t.Fatal("fixture credential refused")
	}
	name := "Synthetic private connection canary 73"
	record, e := store.putConnection(a.ID, connection{Name: name, Target: strings.Repeat("a", 32), Credential: credential, Approval: strings.Repeat("b", 64), Fingerprint: identityFingerprint(remoteTargetFixture(t))})
	if e != nil {
		t.Fatal("valid connection refused")
	}
	_ = store.Close()
	store, e = openStore(dir, key)
	if e != nil {
		t.Fatal("connection store reopen refused")
	}
	defer store.Close()
	got, e := store.readConnection(a.ID, record)
	if e != nil || got.Name != name || got.Credential != credential {
		t.Fatal("encrypted connection did not persist")
	}
	data, e := os.ReadFile(filepath.Join(dir, "custody.db"))
	if e != nil || strings.Contains(string(data), name) {
		t.Fatal("connection metadata persisted plaintext")
	}
	if _, e := store.CreateAccount("bob", alicePassword); e != nil {
		t.Fatal("fixture second account refused")
	}
	b, _ := store.lookup("bob")
	if store.update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(connectionBucket)
		return bucket.Put(credentialKey(b.ID, record), append([]byte(nil), bucket.Get(credentialKey(a.ID, record))...))
	}) != nil {
		t.Fatal("rebind fixture failed")
	}
	if _, e = store.readConnection(b.ID, record); e == nil {
		t.Fatal("connection ciphertext owner rebind accepted")
	}
}

func TestOwnedRemoteChangedApprovalRefusesStoredConnection(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	raw := grantFixture(t, c, record)
	id, _ := tokenID(c.cookie.Value)
	a, _ := store.lookup("alice")
	row, _ := store.readConnection(a.ID, record)
	changed := remoteTargetFixture(t)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.remote.targets[row.Target] = changed // synthetic restart-equivalent approval replacement, never an HTTP knob.
	if _, e := l.grantRemoteLocked(id, record); e == nil {
		t.Fatal("changed approval silently retargeted stored connection")
	}
	if _, _, _, _, e := l.redeemRemoteLocked(id, raw); e == nil {
		t.Fatal("old grant survived changed target identity")
	}
}

func TestOwnedRemoteMFADowngradeStopsOutputAuthority(t *testing.T) {
	l, _, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	raw := grantFixture(t, c, record)
	id, _ := tokenID(c.cookie.Value)
	l.mu.Lock()
	_, _, _, ctx, e := l.redeemRemoteLocked(id, raw)
	l.mu.Unlock()
	if e != nil {
		t.Fatal("downgrade fixture lease refused")
	}
	c.expect("POST", "/api/mfa/reset", "{}", 204)
	c.session("enroll")
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("MFA downgrade retained remote output authority")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.remote.leases) != 0 {
		t.Fatal("downgraded session retained pending remote authority")
	}
}

type activityProbe struct{ refuse bool }

func (activityProbe) Read([]byte) (int, error)       { return 0, io.EOF }
func (activityProbe) ReadStderr([]byte) (int, error) { return 0, io.EOF }
func (p activityProbe) Write(b []byte) (int, error) {
	if p.refuse {
		return 0, errRefused
	}
	return len(b), nil
}
func (activityProbe) Resize(uint32, uint32) error { return nil }
func (activityProbe) Close() error                { return nil }

// A terminal's input keeps its sign-in alive only once the terminal took it.
func TestOwnedTerminalInputExtendsIdleOnlyWhenTaken(t *testing.T) {
	l, c, _ := terminalFixture(t, "https://127.0.0.1:8443", &terminalWorker{closed: make(chan struct{})})
	id, _ := tokenID(c.cookie.Value)
	now := time.Now()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	start := l.sessions[id].last
	ctx := l.sessions[id].ctx
	l.mu.Unlock()
	advance(l, &now, time.Minute)
	last := func() time.Time { l.mu.Lock(); defer l.mu.Unlock(); return l.sessions[id].last }
	stream := &remoteActivity{Stream: activityProbe{refuse: true}, l: l, id: id, ctx: ctx}
	_, _ = stream.Write([]byte("ls\r"))
	if !last().Equal(start) {
		t.Fatal("rejected input extended idle")
	}
	stream.Stream = activityProbe{}
	if _, e := stream.Write(nil); e != nil || !last().Equal(start) {
		t.Fatal("an empty write extended idle")
	}
	if _, e := stream.Write([]byte("ls\r")); e != nil {
		t.Fatal("valid user activity refused")
	}
	if !last().Equal(now) {
		t.Fatal("valid user activity did not refresh idle")
	}
}

// What the page sends by itself (graphics acknowledgements, every slow-path
// reply) does not keep a desktop signed in; the person's keys and mouse, the
// fast-path input, do.
func TestOnlyThePersonsInputKeepsADesktopSignedIn(t *testing.T) {
	server, origin := tlsFixture(t)
	l, _, c, record, worker := remoteFixture(t, origin)
	startTLS(t, server, l)
	id, _ := tokenID(c.cookie.Value)
	now := time.Now()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	raw := grantFixture(t, c, record)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, e := dialDesktop(ctx, server, origin, http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}})
	if e != nil {
		t.Fatal("valid socket refused")
	}
	defer socket.CloseNow()
	if socket.Write(ctx, websocket.MessageBinary, desktopRequest(t, c.csrf+"."+raw)) != nil {
		t.Fatal("the request could not be sent")
	}
	<-worker.messages
	last := func() time.Time { l.mu.Lock(); defer l.mu.Unlock(); return l.sessions[id].last }
	start := last()
	advance(l, &now, time.Minute)
	// The relay admits each message before the proxy gets it, so its echo
	// means the gateway has already counted it, or not.
	send := func(message []byte) {
		t.Helper()
		if socket.Write(ctx, websocket.MessageBinary, message) != nil {
			t.Fatal("a desktop message was refused")
		}
		if _, data, e := socket.Read(ctx); e != nil || !bytes.Equal(data, message) {
			t.Fatal("the desktop message did not come back")
		}
	}
	for _, reply := range [][]byte{
		{0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x64, 0x00, 0x07, 0x03, 0xeb}, // a slow-path PDU
		{0x03, 0x00, 0x00, 0x08, 0x02, 0xf0, 0x80, 0x00},
		{0x01, 0x02}, // neither fast-path input nor a TPKT
	} {
		send(reply)
	}
	if !last().Equal(start) {
		t.Fatal("what the page sent by itself extended idle")
	}
	send([]byte{0x04, 0x02, 0x00}) // fast-path input
	if !last().Equal(now) {
		t.Fatal("the person's input did not refresh idle")
	}
}

// When Windows renews its RDP certificate, the approved one expires. The lab
// still starts; only that server is unavailable, and every other one works.
func TestExpiredRDPCertificateDisablesOnlyItsServer(t *testing.T) {
	store, _, _ := bootstrapped(t)
	now := time.Now()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal("fixture key failed")
	}
	period := func(from, until time.Time) []byte {
		cert := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"rdp.invalid"}, NotBefore: from, NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if e != nil {
			t.Fatal("fixture cert failed")
		}
		return der
	}
	expired, future := remoteTargetFixture(t), remoteTargetFixture(t)
	expired.Identity = period(now.Add(-2*time.Hour), now.Add(-time.Hour))
	future.ID, future.Identity = strings.Repeat("b", 32), period(now.Add(time.Hour), now.Add(2*time.Hour))
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	ip := netip.MustParseAddr("10.34.0.9")
	policy, e := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 22)}, nil)
	if e != nil {
		t.Fatal(e)
	}
	named, e := targetguard.NewNamedTarget(policy, "ssh.invalid", 22, []netip.Addr{ip})
	if e != nil {
		t.Fatal(e)
	}
	sshTarget := RemoteTarget{strings.Repeat("c", 32), "Synthetic SSH", "ssh", named, hostSigner.PublicKey().Marshal()}
	worker := &recordingSSHWorker{}
	l, e := NewRemoteLab("https://127.0.0.1:8443", store, []RemoteTarget{expired, future, sshTarget}, worker, &fixtureRDPWorker{closed: make(chan struct{})})
	if e != nil {
		t.Fatal("one RDP certificate outside its period stopped the whole lab")
	}
	defer l.Close()
	for _, target := range []RemoteTarget{expired, future} {
		if describeTarget(target, now).Available || target.UsableAt(now) || acceptTargetProof(target, identityFingerprint(target), approvalFingerprint(target), now) {
			t.Fatal("an RDP server outside its certificate period is usable")
		}
	}
	if !describeTarget(sshTarget, now).Available || !sshTarget.UsableAt(now) || !acceptTargetProof(sshTarget, identityFingerprint(sshTarget), approvalFingerprint(sshTarget), now) {
		t.Fatal("another server became unavailable")
	}
	if !future.UsableAt(now.Add(90 * time.Minute)) {
		t.Fatal("a future certificate did not become usable in its period")
	}
	_, _ = l.openTerminal(context.Background(), sshTarget, Credential{Name: "fixture", Kind: "password", Username: "deploy", Secret: "Synthetic remote şifrə 1!"})
	if _, ok := worker.got.(*sshkey.Password); !ok {
		t.Fatal("the SSH server stopped working beside an expired RDP certificate")
	}
	// A certificate that is wrong apart from its period still stops the lab.
	wrong := remoteTargetFixture(t)
	wrong.Identity = []byte("not a certificate")
	if other, e := NewRemoteLab("https://127.0.0.1:8443", store, []RemoteTarget{wrong}, nil, &fixtureRDPWorker{closed: make(chan struct{})}); e == nil {
		_ = other.Close()
		t.Fatal("a malformed RDP certificate loaded")
	}
}

// Each way Keybash ends an open remote session gives the page its own reason:
// the idle limit, the sign-in's absolute life, signing out, and the access
// changing. The relay says only these fixed words.
func TestOwnedRemoteSessionsEndWithTheirReason(t *testing.T) {
	open := func(t *testing.T) (*Lab, *custodyClient, string, *time.Time, context.Context) {
		t.Helper()
		l, _, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
		now := time.Now()
		l.mu.Lock()
		l.now = func() time.Time { return now }
		l.mu.Unlock()
		raw := grantFixture(t, c, record)
		id, _ := tokenID(c.cookie.Value)
		l.mu.Lock()
		_, _, _, ctx, e := l.redeemRemoteLocked(id, raw)
		l.mu.Unlock()
		if e != nil {
			t.Fatal("valid lease refused")
		}
		return l, c, record, &now, ctx
	}
	ended := func(t *testing.T, ctx context.Context, want terminalweb.Reason) {
		t.Helper()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatalf("%s did not end the remote session", want)
		}
		if context.Cause(ctx) != want {
			t.Fatalf("got cause %v, want %s", context.Cause(ctx), want)
		}
	}
	t.Run("idle", func(t *testing.T) {
		l, _, _, now, ctx := open(t)
		advance(l, now, idleLife)
		l.mu.Lock()
		l.sweepLocked()
		l.mu.Unlock()
		ended(t, ctx, terminalweb.ReasonIdle)
	})
	t.Run("expired", func(t *testing.T) {
		l, c, _, now, ctx := open(t)
		id, _ := tokenID(c.cookie.Value)
		l.mu.Lock()
		l.sessions[id].created = now.Add(-absoluteLife)
		l.sweepLocked()
		l.mu.Unlock()
		ended(t, ctx, terminalweb.ReasonExpired)
	})
	t.Run("signed-out", func(t *testing.T) {
		_, c, _, _, ctx := open(t)
		c.expect("DELETE", "/api/session", "{}", 204)
		ended(t, ctx, terminalweb.ReasonSignedOut)
	})
	t.Run("access-changed", func(t *testing.T) {
		_, c, record, _, ctx := open(t)
		c.expect("DELETE", "/api/connections/"+record, "{}", 204)
		ended(t, ctx, terminalweb.ReasonAccessChanged)
	})
	t.Run("stopping", func(t *testing.T) {
		l, _, _, _, ctx := open(t)
		_ = l.Close()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("stopping the gateway did not end the remote session")
		}
		var reason terminalweb.Reason
		if errors.As(context.Cause(ctx), &reason) {
			t.Fatalf("stopping the gateway gave a reason: %s", reason)
		}
	})
}

// The native lab's guacd desktop sizes itself by Windows' scales, never past
// full HD times the scale, until step 3e3 removes it.
func TestDesktopBoundsAreWindowsScales(t *testing.T) {
	for dpi, want := range map[int][2]int{96: {1920, 1080}, 120: {2400, 1350}, 144: {2880, 1620}, 168: {3360, 1890}, 192: {3840, 2160}} {
		if w, h, ok := DesktopBounds(dpi); !ok || w != want[0] || h != want[1] || !DesktopSize(w, h, dpi) || DesktopSize(w+2, h, dpi) || DesktopSize(w, h+2, dpi) {
			t.Fatalf("bounds at %d DPI: %dx%d %v", dpi, w, h, ok)
		}
	}
	for _, size := range [][3]int{{200, 200, 96}, {1600, 900, 96}, {2880, 1800, 192}} {
		if !DesktopSize(size[0], size[1], size[2]) {
			t.Fatalf("%v refused", size)
		}
	}
	for _, size := range [][3]int{{1601, 900, 96}, {1600, 901, 96}, {198, 900, 96}, {1600, 198, 96}, {1922, 1080, 96}, {2880, 1800, 144}} {
		if DesktopSize(size[0], size[1], size[2]) {
			t.Fatalf("%v accepted", size)
		}
	}
	for _, dpi := range []int{0, 72, 95, 97, 100, 110, 200, 240, 288, 384} {
		if _, _, ok := DesktopBounds(dpi); ok || DesktopSize(1600, 900, dpi) {
			t.Fatalf("%d DPI accepted", dpi)
		}
	}
}

// The terminal socket opens terminals only. Its proof is exactly the page's
// CSRF value and lease, so the size the guacd page once sent opens nothing
// and leaves the lease unused; a desktop's lease is used up there without
// starting anything, and is gone from the desktop's own socket too.
func TestTheTerminalSocketOpensTerminalsOnly(t *testing.T) {
	server, origin := tlsFixture(t)
	l, _, c, record, worker := remoteFixture(t, origin)
	startTLS(t, server, l)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	header := http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}
	open := func(proof map[string]string) {
		t.Helper()
		socket, _, e := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/socket", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: header})
		if e != nil {
			t.Fatal("valid socket refused")
		}
		defer socket.CloseNow()
		if socket.Write(ctx, websocket.MessageText, []byte(inputJSON(proof))) != nil {
			t.Fatal("proof write failed")
		}
		if _, data, e := socket.Read(ctx); e == nil {
			t.Fatalf("the terminal socket answered %q", data)
		}
	}
	raw := grantFixture(t, c, record)
	key, _ := tokenID(raw)
	open(map[string]string{"csrf": c.csrf, "lease": raw, "size": "1600x900"})
	l.mu.Lock()
	unused := l.remote.leases[key] != nil && !l.remote.leases[key].active
	l.mu.Unlock()
	if !unused {
		t.Fatal("a proof with a size used the lease")
	}
	open(map[string]string{"csrf": c.csrf, "lease": raw})
	l.mu.Lock()
	left := len(l.remote.leases)
	l.mu.Unlock()
	if left != 0 {
		t.Fatal("a desktop's lease outlived the terminal socket")
	}
	socket, e := dialDesktop(ctx, server, origin, header)
	if e != nil {
		t.Fatal("valid socket refused")
	}
	defer socket.CloseNow()
	_ = socket.Write(ctx, websocket.MessageBinary, desktopRequest(t, c.csrf+"."+raw))
	if _, _, e := socket.Read(ctx); e == nil {
		t.Fatal("a lease used on the terminal socket opened a desktop")
	}
	if worker.calls.Load() != 0 {
		t.Fatal("the terminal socket started a desktop")
	}
}
