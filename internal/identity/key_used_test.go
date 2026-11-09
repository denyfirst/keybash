package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// A key made here is marked used once, and only such a key; the mark changes
// nothing else, and a record claiming it for another kind does not read.
func TestMadeKeyIsMarkedUsedOnce(t *testing.T) {
	store, _, _ := bootstrapped(t)
	a, _, _ := enrollFixture(t, store, "alice", time.Now())
	made, e := newGeneratedKey("Made key", "deploy")
	if e != nil {
		t.Fatal(e)
	}
	madeID, e := store.putCredential(a.ID, made)
	if e != nil {
		t.Fatal(e)
	}
	brought, e := store.putCredential(a.ID, Credential{Name: "Brought password", Kind: "password", Username: "deploy", Secret: "Synthetic remote password"})
	if e != nil {
		t.Fatal(e)
	}
	used := func(id string) bool {
		t.Helper()
		rows, e := store.listCredentials(a.ID)
		if e != nil {
			t.Fatal(e)
		}
		for _, row := range rows {
			if row.ID == id {
				return row.Used
			}
		}
		t.Fatal("record missing")
		return false
	}
	if used(madeID) {
		t.Fatal("a new key was marked used")
	}
	before, _ := store.readCredential(a.ID, madeID)
	for range 2 {
		if store.markKeyUsed(a.ID, madeID) != nil {
			t.Fatal("marking a made key failed")
		}
	}
	after, _ := store.readCredential(a.ID, madeID)
	if !used(madeID) || !after.Used || after.Secret != before.Secret || after.Public != before.Public || after.Name != before.Name || !after.Generated {
		t.Fatal("the mark changed more than itself, or did not hold")
	}
	if store.markKeyUsed(a.ID, brought) != errRefused || used(brought) {
		t.Fatal("a brought password was marked used")
	}
	if store.markKeyUsed(strings.Repeat("b", 32), madeID) == nil {
		t.Fatal("another account marked this key")
	}
	// A sealed record that claims the mark without being made here is refused.
	forged := Credential{ID: brought, Name: "Brought password", Kind: "password", Username: "deploy", Secret: "Synthetic remote password", Used: true}
	if e := store.update(func(tx *bolt.Tx) error {
		plain, e := json.Marshal(forged)
		if e != nil {
			return e
		}
		sealed, e := store.seal(tx, "credential", a.ID, brought, 2, plain)
		if e != nil {
			return e
		}
		return tx.Bucket(credentialBucket).Put(credentialKey(a.ID, brought), sealed)
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := store.readCredential(a.ID, brought); e == nil {
		t.Fatal("a used mark on a brought password was read")
	}
}

// openingSSHWorker opens a terminal that echoes, or refuses when told to.
type openingSSHWorker struct{ refuse atomic.Bool }

func (w *openingSSHWorker) OpenSSH(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, _ string, _ sshkey.Credential) (terminalweb.Stream, error) {
	if w.refuse.Load() {
		return nil, errRefused
	}
	left, right := net.Pipe()
	go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
	context.AfterFunc(ctx, func() { _ = left.Close() })
	return fixtureRemoteStream{left}, nil
}

// The mark comes from a terminal actually opening with the key, never from a
// refused one.
func TestMadeKeyIsUsedOnlyOnceItOpensATerminal(t *testing.T) {
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
	worker := &openingSSHWorker{}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	l, e := NewRemoteLab(origin, store, []RemoteTarget{target}, worker, nil)
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	defer l.Close()
	server.Config.Handler = l
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	openTo(t, l, mustLookup(t, store, "alice").ID)
	c := &custodyClient{t: t, l: l}
	c.login()
	c.session("challenge")
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	c.session("ready")
	c.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	var made struct{ ID string }
	if json.Unmarshal(c.expect("POST", "/api/credentials/generate", inputJSON(map[string]string{"name": "Made key", "username": "deploy"}), 200).Body.Bytes(), &made) != nil || !validID(made.ID) {
		t.Fatal("key generation failed")
	}
	var record struct{ ID string }
	w := c.expect("POST", "/api/connections", inputJSON(map[string]string{"name": "Synthetic terminal", "target": target.ID, "credential": made.ID, "approval": approvalFingerprint(target)}), 200)
	if json.Unmarshal(w.Body.Bytes(), &record) != nil || !validID(record.ID) {
		t.Fatal("connection creation failed")
	}
	used := func() bool {
		t.Helper()
		var rows []struct {
			ID   string
			Used bool
		}
		if json.Unmarshal(c.expect("GET", "/api/credentials", "", 200).Body.Bytes(), &rows) != nil {
			t.Fatal("credentials unreadable")
		}
		for _, row := range rows {
			if row.ID == made.ID {
				return row.Used
			}
		}
		t.Fatal("made key missing")
		return false
	}
	open := func() string {
		t.Helper()
		raw := grantFixture(t, c, record.ID)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		header := http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}
		socket, _, e := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/socket", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: header})
		if e != nil {
			t.Fatal("valid socket refused")
		}
		defer socket.CloseNow()
		if socket.Write(ctx, websocket.MessageText, []byte(inputJSON(map[string]string{"csrf": c.csrf, "lease": raw}))) != nil {
			t.Fatal("proof write failed")
		}
		_, data, e := socket.Read(ctx)
		if e != nil {
			return ""
		}
		return string(data)
	}
	// Nobody can claim the mark: the API takes no such field.
	c.expect("POST", "/api/credentials", `{"name":"x","kind":"password","username":"u","secret":"s","passphrase":"","used":true}`, 400)
	worker.refuse.Store(true)
	if got := open(); got != "" || used() {
		t.Fatalf("a refused terminal marked the key used (%q)", got)
	}
	worker.refuse.Store(false)
	if got := open(); got != `{"type":"ready"}` || !used() {
		t.Fatalf("an opened terminal did not mark the key used (%q)", got)
	}
}
