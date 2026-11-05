package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

var (
	serverNetworks  = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	serverProtected = []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}
)

func hostKeyFixture(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, e := ed25519.GenerateKey(rand.Reader)
	key, ke := ssh.NewPublicKey(public)
	if e != nil || ke != nil {
		t.Fatal("fixture host key failed")
	}
	return key
}

// echoSSHWorker stands in for the SSH manager: an echo stream that closes
// when its lease ends.
type echoSSHWorker struct{}

func (echoSSHWorker) OpenSSH(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, _ string, _ sshkey.Credential) (terminalweb.Stream, error) {
	left, right := net.Pipe()
	go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
	go func() { <-ctx.Done(); _ = left.Close() }()
	return fixtureRemoteStream{left}, nil
}

// fixtureScans answers scans from a table: the key each endpoint shows now.
type fixtureScans struct {
	mu    sync.Mutex
	keys  map[netip.AddrPort]ssh.PublicKey
	calls int
}

func (f *fixtureScans) set(endpoint string, key ssh.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[netip.MustParseAddrPort(endpoint)] = key
}
func (f *fixtureScans) scan(_ context.Context, target *targetguard.NamedTarget) (ssh.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	snapshot := target.Snapshot()
	key := f.keys[netip.AddrPortFrom(netip.MustParseAddr(snapshot.Addresses[0]), snapshot.Port)]
	if key == nil {
		return nil, errors.New("synthetic: nothing answers")
	}
	return key, nil
}

func catalogSSHFixture(t *testing.T) RemoteTarget {
	t.Helper()
	endpoint := netip.MustParseAddrPort("10.20.0.5:22")
	policy, e := targetguard.New([]netip.AddrPort{endpoint}, serverProtected)
	if e != nil {
		t.Fatal("fixture policy failed")
	}
	target, e := targetguard.NewAddressTarget(policy, endpoint.Addr(), endpoint.Port())
	if e != nil {
		t.Fatal("fixture target failed")
	}
	return RemoteTarget{strings.Repeat("c", 32), "Catalog box", "ssh", target, hostKeyFixture(t).Marshal()}
}

// serversFixture is a lab with one catalog SSH server and target networks,
// whose bootstrap administrator alice is ready and freshly proved. Scans are
// answered by the returned table.
func serversFixture(t *testing.T) (*adminLab, *fixtureScans) {
	t.Helper()
	return serversFixtureWith(t, TargetNetworks(serverNetworks, serverProtected))
}

// serversFixtureWith is serversFixture with these lab options instead.
func serversFixtureWith(t *testing.T, options ...Option) (*adminLab, *fixtureScans) {
	t.Helper()
	store, _, _ := bootstrapped(t)
	f := &adminLab{t: t, store: store, now: time.Now(), target: catalogSSHFixture(t)}
	_, _, codes := enrollFixture(t, store, "alice", f.now)
	l, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", store, []RemoteTarget{f.target}, echoSSHWorker{}, nil, sessionlimits.Default(), options...)
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	t.Cleanup(func() { _ = l.Close() })
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
	return f, scans
}

// addServerFixture adds a web server as an administrator would: scan, compare
// the fingerprint, add.
func addServerFixture(t *testing.T, c *custodyClient, scans *fixtureScans, name, endpoint string) (string, ssh.PublicKey) {
	t.Helper()
	key := hostKeyFixture(t)
	scans.set(endpoint, key)
	at := netip.MustParseAddrPort(endpoint)
	fields := map[string]string{"address": at.Addr().String(), "port": strings.TrimPrefix(endpoint, at.Addr().String()+":")}
	var shown struct{ Fingerprint, Algorithm string }
	if json.Unmarshal(c.expect("POST", "/api/servers/scan", inputJSON(fields), 200).Body.Bytes(), &shown) != nil || shown.Fingerprint != ssh.FingerprintSHA256(key) || shown.Algorithm != ssh.KeyAlgoED25519 {
		t.Fatal("scan did not show the server's fingerprint")
	}
	fields["name"], fields["fingerprint"] = name, shown.Fingerprint
	var made struct{ ID string }
	if json.Unmarshal(c.expect("POST", "/api/servers", inputJSON(fields), 200).Body.Bytes(), &made) != nil || !validID(made.ID) {
		t.Fatal("server was not added")
	}
	return made.ID, key
}

func listServersView(t *testing.T, c *custodyClient) serversView {
	t.Helper()
	var view serversView
	if json.Unmarshal(c.expect("GET", "/api/servers", "", 200).Body.Bytes(), &view) != nil {
		t.Fatal("servers unreadable")
	}
	return view
}
func serverRow(view serversView, id string) (serverView, bool) {
	at := slices.IndexFunc(view.Servers, func(row serverView) bool { return row.ID == id })
	if at < 0 {
		return serverView{}, false
	}
	return view.Servers[at], true
}

func TestServerRecordsAreCheckedOwnedAndKept(t *testing.T) {
	store, _, _ := bootstrapped(t)
	now := time.Now()
	alice := mustLookup(t, store, "alice")
	if _, e := store.CreateAccount("bob", bobPassword); e != nil {
		t.Fatal("fixture account failed")
	}
	bob := mustLookup(t, store, "bob")
	key := hostKeyFixture(t).Marshal()
	if _, e := store.addServer(bob.ID, "Web", "10.20.0.7", 22, key, now); e == nil {
		t.Fatal("a user added a server")
	}
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaPublic, _ := ssh.NewPublicKey(&ecdsaKey.PublicKey)
	for _, bad := range []struct {
		name, address string
		port          uint16
		key           []byte
	}{
		{"", "10.20.0.7", 22, key}, {" Web", "10.20.0.7", 22, key}, {"We\x00b", "10.20.0.7", 22, key}, {"We" + string(rune(0x202e)) + "b", "10.20.0.7", 22, key}, {strings.Repeat("w", 161), "10.20.0.7", 22, key},
		{"Web", "10.20.0.7 ", 22, key}, {"Web", "::ffff:10.20.0.7", 22, key}, {"Web", "fe80::1%eth0", 22, key}, {"Web", "010.20.0.7", 22, key}, {"Web", "web.example", 22, key}, {"Web", "10.20.0.0/24", 22, key},
		{"Web", "10.20.0.7", 0, key}, {"Web", "10.20.0.7", 22, ecdsaPublic.Marshal()}, {"Web", "10.20.0.7", 22, []byte("not a key")}, {"Web", "10.20.0.7", 22, append(slices.Clone(key), 0)}, {"Web", "10.20.0.7", 22, nil},
	} {
		if _, e := store.addServer(alice.ID, bad.name, bad.address, bad.port, bad.key, now); e == nil {
			t.Fatalf("malformed server accepted: %q %q %d", bad.name, bad.address, bad.port)
		}
	}
	if list, e := store.listServers(); e != nil || len(list) != 0 {
		t.Fatal("a refused server was stored")
	}
	id, e := store.addServer(alice.ID, "Web", "10.20.0.7", 22, key, now)
	if e != nil {
		t.Fatal("valid server refused")
	}
	if _, e = store.addServer(alice.ID, "Web again", "10.20.0.7", 22, hostKeyFixture(t).Marshal(), now); e != errDuplicate {
		t.Fatal("a second server at the same address and port was stored")
	}
	if _, e = store.addServer(alice.ID, "Web on 2222", "10.20.0.7", 2222, key, now); e != nil {
		t.Fatal("the same address on another port was refused")
	}
	list, e := store.listServers()
	if e != nil || len(list) != 2 {
		t.Fatal("servers not listed")
	}
	w := list[slices.IndexFunc(list, func(w webServer) bool { return w.ID == id })]
	if w.Name != "Web" || w.Address != "10.20.0.7" || w.Port != 22 || !bytes.Equal(w.HostKey, key) || len(w.Access) != 0 || w.AddedBy != alice.ID || w.Added != now.Unix() || w.Revision != 1 {
		t.Fatalf("stored server differs: %+v", w)
	}
	if store.renameServer(alice.ID, id, " padded") == nil || store.renameServer(bob.ID, id, "Bob's") == nil || store.renameServer(alice.ID, strings.Repeat("e", 32), "Gone") != errMissing {
		t.Fatal("a malformed, unauthorized or missing rename was accepted")
	}
	if store.renameServer(alice.ID, id, "Web server") != nil {
		t.Fatal("valid rename refused")
	}
	// Access lists stay sorted and hold only accounts that may reach servers.
	if _, e := store.CreateAccount("carol", bobPassword); e != nil {
		t.Fatal("fixture account failed")
	}
	if _, e := store.CreateAccount("dave", bobPassword); e != nil {
		t.Fatal("fixture account failed")
	}
	setRole(t, store, "dave", roleAuditor)
	carol, dave := mustLookup(t, store, "carol"), mustLookup(t, store, "dave")
	for _, person := range []string{carol.ID, bob.ID, alice.ID, bob.ID} {
		if store.setServerAccess(alice.ID, id, person, true) != nil {
			t.Fatal("valid grant refused")
		}
	}
	if store.setServerAccess(alice.ID, id, dave.ID, true) == nil || store.setServerAccess(alice.ID, id, strings.Repeat("f", 32), true) != errMissing || store.setServerAccess(bob.ID, id, bob.ID, true) == nil {
		t.Fatal("an auditor, a missing account or a user's own grant was accepted")
	}
	list, _ = store.listServers()
	w = list[slices.IndexFunc(list, func(w webServer) bool { return w.ID == id })]
	if len(w.Access) != 3 || !slices.IsSorted(w.Access) || !slices.Contains(w.Access, bob.ID) || slices.Contains(w.Access, dave.ID) {
		t.Fatalf("access list %v", w.Access)
	}
	if store.setServerAccess(alice.ID, id, alice.ID, false) != nil {
		t.Fatal("valid revoke refused")
	}
	other := hostKeyFixture(t).Marshal()
	if store.repinServer(alice.ID, id, ecdsaPublic.Marshal()) == nil || store.repinServer(alice.ID, id, other) != nil {
		t.Fatal("re-pinning did not take exactly an Ed25519 key")
	}
	// Deleting an account takes it off every list, in the same transaction.
	if store.deleteAccount(alice.ID, carol.ID) != nil {
		t.Fatal("fixture deletion failed")
	}
	list, _ = store.listServers()
	w = list[slices.IndexFunc(list, func(w webServer) bool { return w.ID == id })]
	if !slices.Equal(w.Access, []string{bob.ID}) || !bytes.Equal(w.HostKey, other) || w.Name != "Web server" {
		t.Fatalf("server after changes: %+v", w)
	}
	if store.deleteServer(bob.ID, id) == nil || store.deleteServer(alice.ID, id) != nil || store.deleteServer(alice.ID, id) != errMissing {
		t.Fatal("server deletion was not an administrator's, once")
	}
	if list, _ = store.listServers(); len(list) != 1 {
		t.Fatal("deleted server still listed")
	}
}

// A server record is sealed: its address is not on disk in the clear, and a
// changed or moved record does not load.
func TestServerRecordsAreSealed(t *testing.T) {
	store, _, _ := bootstrapped(t)
	alice := mustLookup(t, store, "alice")
	id, e := store.addServer(alice.ID, "Sealed canary", "10.20.0.7", 22, hostKeyFixture(t).Marshal(), time.Now())
	if e != nil {
		t.Fatal("valid server refused")
	}
	var sealed []byte
	if store.view(func(tx *bolt.Tx) error { sealed = bytes.Clone(tx.Bucket(serverBucket).Get([]byte(id))); return nil }) != nil || len(sealed) == 0 {
		t.Fatal("server record absent")
	}
	if bytes.Contains(sealed, []byte("10.20.0.7")) || bytes.Contains(sealed, []byte("Sealed canary")) {
		t.Fatal("server record in plaintext")
	}
	for _, change := range []func(*bolt.Bucket) error{
		func(b *bolt.Bucket) error { // another ID's key
			return b.Put([]byte(strings.Repeat("d", 32)), sealed)
		},
		func(b *bolt.Bucket) error { // one flipped byte
			changed := bytes.Clone(sealed)
			changed[len(changed)/2] ^= 1
			return b.Put([]byte(id), changed)
		},
	} {
		if store.update(func(tx *bolt.Tx) error { return change(tx.Bucket(serverBucket)) }) != nil {
			t.Fatal("fixture change failed")
		}
		if _, e := store.listServers(); e == nil {
			t.Fatal("a moved or changed server record loaded")
		}
		if store.update(func(tx *bolt.Tx) error {
			b := tx.Bucket(serverBucket)
			_ = b.Delete([]byte(strings.Repeat("d", 32)))
			return b.Put([]byte(id), sealed)
		}) != nil {
			t.Fatal("fixture restore failed")
		}
	}
	if list, e := store.listServers(); e != nil || len(list) != 1 {
		t.Fatal("the original record no longer loads")
	}
}

func TestServersPageIsForFreshAdministrators(t *testing.T) {
	f, scans := serversFixture(t)
	view := listServersView(t, f.alice)
	if !slices.Equal(view.Networks, []string{"10.20.0.0/24"}) || !view.Adding || len(view.Servers) != 1 || view.Servers[0].Source != "file" || view.Servers[0].ID != f.target.ID || !view.Servers[0].Available || view.Servers[0].Access != nil {
		t.Fatalf("servers view %+v", view)
	}
	bob, _ := f.person("bob", roleUser)
	dave, _ := f.person("dave", roleAuditor)
	scans.set("10.20.0.7:22", hostKeyFixture(t))
	scan := inputJSON(map[string]string{"address": "10.20.0.7", "port": "22"})
	for _, c := range []*custodyClient{bob, dave} {
		c.expect("GET", "/api/servers", "", 403)
		c.expect("POST", "/api/servers/scan", scan, 403)
		c.expect("POST", "/api/servers", inputJSON(map[string]string{"name": "x", "address": "10.20.0.7", "port": "22", "fingerprint": "SHA256:" + strings.Repeat("A", 43)}), 403)
	}
	// Listing needs the ready session; a scan, like any change, a fresh factor.
	f.advance(freshProof + time.Minute)
	listServersView(t, f.alice)
	f.alice.expect("POST", "/api/servers/scan", scan, 428)
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": f.codes[0]}), 204)
	if scans.calls != 0 {
		t.Fatal("a refused request scanned")
	}
	for _, malformed := range [][3]string{
		{"POST", "/api/servers/scan", `{"address":"10.20.0.7","port":"22","extra":"x"}`},
		{"POST", "/api/servers/scan", `{"address":"10.20.0.7","port":22}`},
		{"POST", "/api/servers/scan", `{"address":"10.20.0.7","port":"022"}`},
		{"POST", "/api/servers/scan", `{"address":"10.20.0.7","port":"65536"}`},
		{"POST", "/api/servers/scan", `{"address":"10.20.0.7","port":"0"}`},
		{"POST", "/api/servers/scan", `{"address":"10.20.0.7/32","port":"22"}`},
		{"POST", "/api/servers/scan", `{"address":"server.invalid","port":"22"}`},
		{"POST", "/api/servers", `{"name":" x","address":"10.20.0.7","port":"22","fingerprint":"SHA256:` + strings.Repeat("A", 43) + `"}`},
		{"POST", "/api/servers", `{"name":"x","address":"10.20.0.7","port":"22","fingerprint":"MD5:00"}`},
	} {
		f.alice.expect(malformed[0], malformed[1], malformed[2], 400)
	}
	for _, unknown := range [][2]string{{"GET", "/api/servers/scan"}, {"PUT", "/api/servers"}, {"POST", "/api/servers/x"}, {"POST", "/api/servers/" + f.target.ID + "/name/x"}, {"POST", "/api/servers/" + f.target.ID + "/open"}, {"GET", "/api/servers/" + f.target.ID}} {
		f.alice.expect(unknown[0], unknown[1], "{}", 404)
	}
	if scans.calls != 0 {
		t.Fatal("a malformed request scanned")
	}
}

func TestServerScansStayInsideTheTargetNetworks(t *testing.T) {
	f, scans := serversFixture(t)
	scan := func(address, port string, status int) {
		t.Helper()
		f.alice.expect("POST", "/api/servers/scan", inputJSON(map[string]string{"address": address, "port": port}), status)
	}
	for _, outside := range []string{"10.21.0.7", "10.99.0.7", "192.0.2.7", "127.0.0.1", "169.254.169.254", "168.63.129.16", "::1", "2001:db8::7"} {
		scan(outside, "22", 403)
	}
	scan("10.20.0.5", "22", 409) // the catalog server
	if scans.calls != 0 {
		t.Fatal("a refused address was scanned")
	}
	scan("10.20.0.9", "22", 502) // nothing answers
	key := hostKeyFixture(t)
	scans.set("10.20.0.5:2222", key)
	var shown struct{ Fingerprint string }
	if json.Unmarshal(f.alice.expect("POST", "/api/servers/scan", inputJSON(map[string]string{"address": "10.20.0.5", "port": "2222"}), 200).Body.Bytes(), &shown) != nil || shown.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatal("scan did not show the key")
	}
	// Scans are bounded per administrator and for the gateway.
	for range scanAttempts - 2 {
		scan("10.20.0.5", "2222", 200)
	}
	scan("10.20.0.5", "2222", 429)
	f.advance(time.Minute)
	f.l.mu.Lock()
	f.l.remote.scans = maxScans
	f.l.mu.Unlock()
	scan("10.20.0.5", "2222", 429)
	f.l.mu.Lock()
	f.l.remote.scans = 0
	f.l.mu.Unlock()
	scan("10.20.0.5", "2222", 200)
	// An installation that names no target networks adds nothing from the web.
	g, gs := serversFixtureWith(t)
	if view := listServersView(t, g.alice); view.Adding || len(view.Networks) != 0 {
		t.Fatal("an installation without target networks offered adding")
	}
	g.alice.expect("POST", "/api/servers/scan", inputJSON(map[string]string{"address": "10.20.0.7", "port": "22"}), 403)
	if gs.calls != 0 {
		t.Fatal("an installation without target networks scanned")
	}
}

func TestTargetNetworksOptionIsChecked(t *testing.T) {
	store, _, _ := bootstrapped(t)
	target := catalogSSHFixture(t)
	for _, options := range [][]Option{
		{TargetNetworks(nil, nil)},
		{TargetNetworks([]netip.Prefix{netip.MustParsePrefix("10.20.0.1/24")}, nil)},
		{TargetNetworks([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, serverProtected)},
		{TargetNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, nil)},
		{TargetNetworks(serverNetworks, []netip.Prefix{netip.MustParsePrefix("10.98.0.1/16")})},
		{TargetNetworks(serverNetworks, serverProtected), TargetNetworks(serverNetworks, serverProtected)},
	} {
		if l, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", store, []RemoteTarget{target}, echoSSHWorker{}, nil, sessionlimits.Default(), options...); e == nil {
			_ = l.Close()
			t.Fatal("invalid target networks accepted")
		}
	}
}

func TestServersAreAddedComparedRenamedRepinnedAndRemoved(t *testing.T) {
	f, scans := serversFixture(t)
	first := hostKeyFixture(t)
	scans.set("10.20.0.7:22", first)
	add := func(fingerprint string, status int) {
		t.Helper()
		f.alice.expect("POST", "/api/servers", inputJSON(map[string]string{"name": "Web", "address": "10.20.0.7", "port": "22", "fingerprint": fingerprint}), status)
	}
	// The key the server shows when it is added must be the one compared.
	add(ssh.FingerprintSHA256(hostKeyFixture(t)), 409)
	if list, _ := f.store.listServers(); len(list) != 0 {
		t.Fatal("a server whose key did not match was stored")
	}
	f.alice.expect("POST", "/api/servers", inputJSON(map[string]string{"name": "Web", "address": "10.21.0.7", "port": "22", "fingerprint": ssh.FingerprintSHA256(first)}), 403)
	id, key := addServerFixture(t, f.alice, scans, "Web", "10.20.0.8:22")
	add(ssh.FingerprintSHA256(first), 200)
	add(ssh.FingerprintSHA256(first), 409) // already listed
	row, ok := serverRow(listServersView(t, f.alice), id)
	if !ok || row.Source != "web" || !row.Available || row.Access == nil || len(row.Access) != 0 || row.Fingerprint != ssh.FingerprintSHA256(key) || row.Hostname != "10.20.0.8" || row.Port != 22 || row.AddedBy != mustLookup(t, f.store, "alice").ID {
		t.Fatalf("added server row %+v", row)
	}
	f.alice.expect("POST", "/api/servers/"+id+"/name", inputJSON(map[string]string{"name": "Build box"}), 204)
	f.alice.expect("POST", "/api/servers/"+id+"/name", inputJSON(map[string]string{"name": ""}), 400)
	f.alice.expect("POST", "/api/servers/"+f.target.ID+"/name", inputJSON(map[string]string{"name": "Renamed"}), 404)
	if row, _ = serverRow(listServersView(t, f.alice), id); row.Name != "Build box" {
		t.Fatal("rename not shown")
	}
	// Re-pinning reads the key again and takes it only as compared.
	next := hostKeyFixture(t)
	scans.set("10.20.0.8:22", next)
	var shown struct{ Fingerprint string }
	if json.Unmarshal(f.alice.expect("POST", "/api/servers/"+id+"/scan", "{}", 200).Body.Bytes(), &shown) != nil || shown.Fingerprint != ssh.FingerprintSHA256(next) {
		t.Fatal("re-scan did not show the new key")
	}
	f.alice.expect("POST", "/api/servers/"+id+"/key", inputJSON(map[string]string{"fingerprint": ssh.FingerprintSHA256(key)}), 409)
	f.alice.expect("POST", "/api/servers/"+f.target.ID+"/scan", "{}", 404)
	f.alice.expect("POST", "/api/servers/"+f.target.ID+"/key", inputJSON(map[string]string{"fingerprint": ssh.FingerprintSHA256(next)}), 404)
	f.alice.expect("POST", "/api/servers/"+id+"/key", inputJSON(map[string]string{"fingerprint": ssh.FingerprintSHA256(next)}), 204)
	if row, _ = serverRow(listServersView(t, f.alice), id); row.Fingerprint != ssh.FingerprintSHA256(next) {
		t.Fatal("re-pinned key not shown")
	}
	f.alice.expect("DELETE", "/api/servers/"+f.target.ID, "{}", 404)
	f.alice.expect("DELETE", "/api/servers/"+id, "{}", 204)
	f.alice.expect("DELETE", "/api/servers/"+id, "{}", 404)
	if _, ok = serverRow(listServersView(t, f.alice), id); ok {
		t.Fatal("removed server still listed")
	}
}

// Who may connect to a web server is its access list, administrators
// included. Taking a person off, changing the server's key or removing it
// ends that person's terminal at once.
func TestServerAccessListDecidesWhoConnects(t *testing.T) {
	f, scans := serversFixture(t)
	id, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	bob, b := f.person("bob", roleUser)
	credential, e := f.store.putCredential(b.ID, Credential{Name: "Synthetic SSH", Kind: "password", Username: "synthetic-user", Secret: "Synthetic remote password"})
	if e != nil {
		t.Fatal("fixture credential failed")
	}
	targets := func(c *custodyClient) []string {
		t.Helper()
		var list []struct{ ID string }
		if json.Unmarshal(c.expect("GET", "/api/targets", "", 200).Body.Bytes(), &list) != nil {
			t.Fatal("targets unreadable")
		}
		var ids []string
		for _, item := range list {
			ids = append(ids, item.ID)
		}
		return ids
	}
	for _, c := range []*custodyClient{bob, f.alice} {
		if slices.Contains(targets(c), id) || !slices.Contains(targets(c), f.target.ID) {
			t.Fatal("an unlisted person sees the server")
		}
		c.expect("GET", "/api/targets/"+id, "", 404)
	}
	// Even the right approval cannot make a connection before access.
	f.l.mu.Lock()
	hidden := f.l.remote.targets[id]
	f.l.mu.Unlock()
	connect := inputJSON(map[string]string{"name": "Bob's web", "target": id, "credential": credential, "approval": approvalFingerprint(hidden)})
	bob.expect("POST", "/api/connections", connect, 403)
	f.alice.expect("POST", "/api/servers/"+id+"/grant", inputJSON(map[string]string{"account": b.ID}), 204)
	if !slices.Contains(targets(bob), id) || slices.Contains(targets(f.alice), id) {
		t.Fatal("the access list did not decide who sees the server")
	}
	var record struct{ ID string }
	if json.Unmarshal(bob.expect("POST", "/api/connections", connect, 200).Body.Bytes(), &record) != nil || !validID(record.ID) {
		t.Fatal("a listed person could not connect")
	}
	bob.expect("GET", "/remote/ssh/"+record.ID, "", 200)
	trust := func() string {
		t.Helper()
		var rows []struct{ ID, Trust string }
		if json.Unmarshal(bob.expect("GET", "/api/connections", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 {
			t.Fatal("connections unreadable")
		}
		return rows[0].Trust
	}
	open := func() context.Context {
		t.Helper()
		raw := grantFixture(t, bob, record.ID)
		bid, _ := tokenID(bob.cookie.Value)
		f.l.mu.Lock()
		_, _, _, ctx, e := f.l.redeemRemoteLocked(bid, raw)
		f.l.mu.Unlock()
		if e != nil {
			t.Fatal("a listed person's lease was refused")
		}
		return ctx
	}
	ended := func(ctx context.Context, what string) {
		t.Helper()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatalf("%s did not end the open terminal", what)
		}
	}
	// Taking bob off ends his terminal and his pending leases.
	ctx := open()
	pending := grantFixture(t, bob, record.ID)
	f.alice.expect("POST", "/api/servers/"+id+"/revoke", inputJSON(map[string]string{"account": b.ID}), 204)
	ended(ctx, "taking the person off")
	bid, _ := tokenID(bob.cookie.Value)
	f.l.mu.Lock()
	if _, _, _, _, e := f.l.redeemRemoteLocked(bid, pending); e == nil {
		t.Fatal("a lease from before the change was redeemed")
	}
	f.l.mu.Unlock()
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record.ID}), 401)
	bob.expect("GET", "/remote/ssh/"+record.ID, "", 404)
	if trust() != "unavailable" {
		t.Fatal("a connection to a server taken away is not shown unavailable")
	}
	// Back on the list, the same connection works again.
	f.alice.expect("POST", "/api/servers/"+id+"/grant", inputJSON(map[string]string{"account": b.ID}), 204)
	if trust() != "verified" {
		t.Fatal("access given back did not restore the connection")
	}
	// A new key ends the terminal and needs bob's own approval.
	ctx = open()
	next := hostKeyFixture(t)
	scans.set("10.20.0.7:22", next)
	f.alice.expect("POST", "/api/servers/"+id+"/key", inputJSON(map[string]string{"fingerprint": ssh.FingerprintSHA256(next)}), 204)
	ended(ctx, "a new key")
	if trust() != "changed" {
		t.Fatal("a re-pinned server is not shown changed")
	}
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record.ID}), 401)
	var target struct{ Approval string }
	if json.Unmarshal(bob.expect("GET", "/api/targets/"+id, "", 200).Body.Bytes(), &target) != nil {
		t.Fatal("target unreadable")
	}
	var rows []struct{ Revision string }
	if json.Unmarshal(bob.expect("GET", "/api/connections", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 {
		t.Fatal("connections unreadable")
	}
	bob.expect("POST", "/api/connections/"+record.ID+"/trust", inputJSON(map[string]string{"approval": target.Approval, "revision": rows[0].Revision}), 204)
	if trust() != "verified" {
		t.Fatal("bob could not accept the new key")
	}
	// Removing the server ends the terminal and leaves the connection unavailable.
	ctx = open()
	f.alice.expect("DELETE", "/api/servers/"+id, "{}", 204)
	ended(ctx, "removing the server")
	if trust() != "unavailable" {
		t.Fatal("a connection to a removed server is not unavailable")
	}
	// Access goes only to existing people who may reach servers.
	id, _ = addServerFixture(t, f.alice, scans, "Second", "10.20.0.8:22")
	_, d := f.person("dave", roleAuditor)
	f.alice.expect("POST", "/api/servers/"+id+"/grant", inputJSON(map[string]string{"account": d.ID}), 403)
	f.alice.expect("POST", "/api/servers/"+id+"/grant", inputJSON(map[string]string{"account": strings.Repeat("9", 32)}), 404)
	f.alice.expect("POST", "/api/servers/"+id+"/grant", inputJSON(map[string]string{"account": "bob"}), 400)
	f.alice.expect("POST", "/api/servers/"+f.target.ID+"/grant", inputJSON(map[string]string{"account": b.ID}), 404)
}

// Web servers come back after a restart, and only inside the networks the
// gateway is given then.
func TestServersReloadInsideTheNetworksOfEachStart(t *testing.T) {
	f, scans := serversFixture(t)
	id, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	b := func() durableAccount { _, a := f.person("bob", roleUser); return a }()
	f.alice.expect("POST", "/api/servers/"+id+"/grant", inputJSON(map[string]string{"account": b.ID}), 204)
	_ = f.l.Close()
	for _, start := range []struct {
		options   []Option
		reachable bool
	}{
		{[]Option{TargetNetworks(serverNetworks, serverProtected)}, true},
		{[]Option{TargetNetworks([]netip.Prefix{netip.MustParsePrefix("10.20.0.5/32")}, serverProtected)}, false},
		{nil, false},
	} {
		l, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", f.store, []RemoteTarget{f.target}, echoSSHWorker{}, nil, sessionlimits.Default(), start.options...)
		if e != nil {
			t.Fatal("restart refused")
		}
		l.mu.Lock()
		_, reachable := l.mayUseLocked(b.ID, id)
		view, ve := l.serversViewLocked()
		l.mu.Unlock()
		_ = l.Close()
		row, listed := serverRow(view, id)
		if ve != nil || reachable != start.reachable || !listed || row.Available != start.reachable || !slices.Equal(row.Access, []string{b.ID}) {
			t.Fatalf("after restart: reachable %v, row %+v", reachable, row)
		}
	}
	// Once the server file lists the same address and port, the file's entry
	// is the one people reach; the web server stays listed, unreachable.
	endpoint := netip.MustParseAddrPort("10.20.0.7:22")
	policy, e := targetguard.New([]netip.AddrPort{endpoint}, serverProtected)
	if e != nil {
		t.Fatal("fixture policy failed")
	}
	named, e := targetguard.NewAddressTarget(policy, endpoint.Addr(), endpoint.Port())
	if e != nil {
		t.Fatal("fixture target failed")
	}
	copied := RemoteTarget{strings.Repeat("e", 32), "Catalog copy", "ssh", named, hostKeyFixture(t).Marshal()}
	both, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", f.store, []RemoteTarget{f.target, copied}, echoSSHWorker{}, nil, sessionlimits.Default(), TargetNetworks(serverNetworks, serverProtected))
	if e != nil {
		t.Fatal("restart refused")
	}
	both.mu.Lock()
	_, reachable := both.mayUseLocked(b.ID, id)
	view, _ := both.serversViewLocked()
	both.mu.Unlock()
	_ = both.Close()
	if row, _ := serverRow(view, id); reachable || row.Available {
		t.Fatal("a web server where the server file also answers is reachable")
	}
	// Without an SSH worker no web server is reachable.
	worker := &fixtureRDPWorker{expected: "x"}
	l, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", f.store, []RemoteTarget{remoteTargetFixture(t)}, nil, worker, sessionlimits.Default(), TargetNetworks(append(slices.Clone(serverNetworks), netip.MustParsePrefix("10.34.0.0/24")), serverProtected))
	if e != nil {
		t.Fatal("RDP-only restart refused")
	}
	defer l.Close()
	l.mu.Lock()
	_, reachable = l.mayUseLocked(b.ID, id)
	adding := l.remote.ssh != nil
	l.mu.Unlock()
	if reachable || adding {
		t.Fatal("a web server is reachable without an SSH worker")
	}
}

func TestBackupCarriesServersAndTheirAccess(t *testing.T) {
	s, key, _ := bootstrapped(t)
	now := time.Now()
	alice := mustLookup(t, s, "alice")
	id, e := s.addServer(alice.ID, "Backup canary server", "10.20.0.7", 22, hostKeyFixture(t).Marshal(), now)
	if e != nil || s.setServerAccess(alice.ID, id, alice.ID, true) != nil {
		t.Fatal("fixture server failed")
	}
	data := backupOf(t, s, now)
	if bytes.Contains(data, []byte("Backup canary server")) {
		t.Fatal("backup carries a server name in plaintext")
	}
	restored, _, summary, e := restoreStore(emptyDataDir(t), key, data, now)
	if e != nil || summary.Servers != 1 {
		t.Fatalf("backup with a server not restored: %+v", summary)
	}
	defer restored.Close()
	list, e := restored.listServers()
	if e != nil || len(list) != 1 || list[0].ID != id || !slices.Equal(list[0].Access, []string{alice.ID}) {
		t.Fatal("restored server differs")
	}
	// An access list naming an account that does not exist is not backed up.
	if s.update(func(tx *bolt.Tx) error {
		w, e := s.server(tx, id)
		if e != nil {
			return e
		}
		w.Access = []string{alice.ID, strings.Repeat("f", 32)}
		return s.saveServer(tx, w)
	}) != nil {
		t.Fatal("fixture change failed")
	}
	if _, e := s.Backup(io.Discard, now); e == nil {
		t.Fatal("a server listing a missing account was backed up")
	}
}

// readHostKey stops at a proven Ed25519 host key and reads a bounded amount.
func TestReadHostKeyTakesOnlyAProvenEd25519Key(t *testing.T) {
	// Both ends send their version first, so they need a buffered socket.
	serve := func(signer ssh.Signer) (ssh.PublicKey, error) {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal("fixture listener failed")
		}
		defer listener.Close()
		go func() {
			server, e := listener.Accept()
			if e != nil {
				return
			}
			defer server.Close()
			config := &ssh.ServerConfig{NoClientAuth: true}
			config.AddHostKey(signer)
			_, _, _, _ = ssh.NewServerConn(server, config)
		}()
		client, e := net.Dial("tcp", listener.Addr().String())
		if e != nil {
			t.Fatal("fixture dial failed")
		}
		defer client.Close()
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))
		return readHostKey(&cappedConn{Conn: client, left: 64 << 10})
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	edSigner, _ := ssh.NewSignerFromKey(private)
	key, e := serve(edSigner)
	if e != nil || !bytes.Equal(key.Marshal(), edSigner.PublicKey().Marshal()) {
		t.Fatal("an Ed25519 host key was not read")
	}
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaSigner, _ := ssh.NewSignerFromKey(ecdsaKey)
	if _, e = serve(ecdsaSigner); e == nil {
		t.Fatal("a server without an Ed25519 key was accepted")
	}
	// A server that sends without end is cut off after 64 KiB.
	client, server := net.Pipe()
	written := make(chan int)
	go func() { _, _ = io.Copy(io.Discard, server) }()
	go func() {
		defer server.Close()
		total := 0
		if n, e := server.Write([]byte("SSH-2.0-synthetic\r\n")); e == nil {
			total += n
		}
		header := make([]byte, 5)
		binary.BigEndian.PutUint32(header, 200<<10)
		header[4] = 4
		if n, e := server.Write(header); e == nil {
			total += n
		}
		chunk := make([]byte, 4096)
		for {
			n, e := server.Write(chunk)
			total += n
			if e != nil {
				break
			}
		}
		written <- total
	}()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, e = readHostKey(&cappedConn{Conn: client, left: 64 << 10}); e == nil {
		t.Fatal("an endless server was accepted")
	}
	_ = client.Close()
	if total := <-written; total > 64<<10 {
		t.Fatalf("read %d bytes from a server, over the bound", total)
	}
}
