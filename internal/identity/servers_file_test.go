package identity

import (
	"crypto/x509"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/denyfirst/keybash/internal/rdpcert"
	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/targetguard"
	bolt "go.etcd.io/bbolt"
)

func txID(t *testing.T, s *Store) int {
	t.Helper()
	id := -1
	if s.view(func(tx *bolt.Tx) error { id = tx.ID(); return nil }) != nil {
		t.Fatal("store unreadable")
	}
	return id
}

func policyFor(t *testing.T, endpoint string) *targetguard.Policy {
	t.Helper()
	policy, e := targetguard.New([]netip.AddrPort{netip.MustParseAddrPort(endpoint)}, serverProtected)
	if e != nil {
		t.Fatal("fixture policy failed")
	}
	return policy
}

// The servers in the operator's file move into the list once: the same IDs,
// so every connection keeps its approval, with exactly the people who already
// connect to each, and one removed on the page never comes back.
func TestServersFromTheFileMoveInOnce(t *testing.T) {
	store, _, _ := bootstrapped(t)
	alice := mustLookup(t, store, "alice")
	for _, name := range []string{"bob", "carol", "dave"} {
		if _, e := store.CreateAccount(name, bobPassword); e != nil {
			t.Fatal("fixture account failed")
		}
	}
	bob, dave := mustLookup(t, store, "bob"), mustLookup(t, store, "dave")
	literal, desktop := catalogSSHFixture(t), remoteTargetFixture(t)
	named, e := targetguard.NewNamedTarget(policyFor(t, "10.20.0.6:22"), "ssh.invalid", 22, []netip.Addr{netip.MustParseAddr("10.20.0.6")})
	if e != nil {
		t.Fatal("fixture target failed")
	}
	byName := RemoteTarget{strings.Repeat("d", 32), "Named box", "ssh", named, hostKeyFixture(t).Marshal()}
	// Before the upgrade bob connects to two of them, and dave, an auditor
	// now, kept a connection from before the role changed.
	for _, owner := range []durableAccount{bob, dave} {
		credential, e := store.putCredential(owner.ID, Credential{Name: "Synthetic", Kind: "password", Username: "synthetic-user", Secret: "Synthetic remote password"})
		if e != nil {
			t.Fatal("fixture credential failed")
		}
		for _, target := range []RemoteTarget{literal, desktop} {
			if owner.ID == dave.ID && target.ID == desktop.ID {
				continue
			}
			if _, e := store.putConnection(owner.ID, connection{Name: "Synthetic", Target: target.ID, Credential: credential, Approval: approvalFingerprint(target), Fingerprint: identityFingerprint(target)}); e != nil {
				t.Fatal("fixture connection failed")
			}
		}
	}
	setRole(t, store, "dave", roleAuditor)
	networks := TargetNetworks([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("10.34.0.0/24")}, serverProtected)
	start := func(targets ...RemoteTarget) *Lab {
		t.Helper()
		l, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", store, targets, echoSSHWorker{}, &fixtureRDPWorker{expected: "x"}, sessionlimits.Default(), networks)
		if e != nil {
			t.Fatal("start refused")
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	l := start(literal, desktop, byName)
	list, e := store.listServers()
	if e != nil || len(list) != 3 {
		t.Fatal("the file's servers did not move in")
	}
	access := map[string][]string{literal.ID: {bob.ID}, desktop.ID: {bob.ID}, byName.ID: nil}
	for _, w := range list {
		if !w.FromFile || w.AddedBy != "" || w.Removed || !slices.Equal(w.Access, access[w.ID]) {
			t.Fatalf("moved server %+v", w)
		}
	}
	// Each connection keeps the approval it had.
	l.mu.Lock()
	for _, target := range []RemoteTarget{literal, desktop, byName} {
		moved, ok := l.remote.targets[target.ID]
		if !ok || approvalFingerprint(moved) != approvalFingerprint(target) || moved.Name != target.Name || moved.Protocol != target.Protocol {
			l.mu.Unlock()
			t.Fatalf("%s moved with another identity", target.Name)
		}
	}
	_, bobReaches := l.mayUseLocked(bob.ID, literal.ID)
	_, daveReaches := l.mayUseLocked(dave.ID, literal.ID)
	l.mu.Unlock()
	if !bobReaches || daveReaches {
		t.Fatal("access after moving in is not exactly the connections before it")
	}
	// A server with a DNS name is reachable only while every pinned address
	// lies inside the networks of the start.
	_ = l.Close()
	narrow, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", store, []RemoteTarget{literal, desktop, byName}, echoSSHWorker{}, &fixtureRDPWorker{expected: "x"}, sessionlimits.Default(),
		TargetNetworks([]netip.Prefix{netip.MustParsePrefix("10.20.0.5/32"), netip.MustParsePrefix("10.34.0.8/32")}, serverProtected))
	if e != nil {
		t.Fatal("narrow start refused")
	}
	narrow.mu.Lock()
	_, namedReached := narrow.remote.targets[byName.ID]
	_, literalReached := narrow.remote.targets[literal.ID]
	narrow.mu.Unlock()
	_ = narrow.Close()
	if namedReached || !literalReached {
		t.Fatal("a server by name was reachable outside the networks")
	}
	// A start with the same file writes nothing.
	before := txID(t, store)
	l = start(literal, desktop, byName)
	if txID(t, store) != before {
		t.Fatal("a start with nothing new wrote to the store")
	}
	// Removed on the page, a server from the file stays a marker: it cannot
	// be changed, and the file does not bring it back.
	if store.deleteServer(alice.ID, byName.ID) != nil || store.deleteServer(alice.ID, byName.ID) != errMissing || store.renameServer(alice.ID, byName.ID, "Back") != errMissing || store.setServerAccess(alice.ID, byName.ID, bob.ID, true) != errMissing {
		t.Fatal("a removed server from the file can still be changed")
	}
	_ = l.Close()
	extra := catalogSSHFixture(t)
	extra.ID, extra.Name = strings.Repeat("e", 32), "Added to the file later"
	if extra.Target, e = targetguard.NewAddressTarget(policyFor(t, "10.20.0.9:22"), netip.MustParseAddr("10.20.0.9"), 22); e != nil {
		t.Fatal("fixture target failed")
	}
	l = start(literal, desktop, byName, extra)
	l.mu.Lock()
	_, back := l.remote.targets[byName.ID]
	view, _ := l.serversViewLocked(true)
	l.mu.Unlock()
	if _, listed := serverRow(view, byName.ID); back || listed {
		t.Fatal("a removed server came back from the file")
	}
	// One added to the file later moves in at the next start, open to nobody.
	if row, listed := serverRow(view, extra.ID); !listed || len(row.Access) != 0 || !row.Available {
		t.Fatalf("a server added to the file later: %+v", row)
	}
	list, _ = store.listServers()
	if !slices.ContainsFunc(list, func(w webServer) bool { return w.ID == byName.ID && w.Removed && len(w.Access) == 0 }) {
		t.Fatal("the removed server left no marker")
	}
}

// A record has one shape per kind of server; anything else does not load.
func TestServerRecordShapes(t *testing.T) {
	desktop := remoteTargetFixture(t)
	ssh := func() webServer {
		return webServer{ID: strings.Repeat("a", 32), Name: "Box", Protocol: "ssh", Address: "10.20.0.7", Port: 22, HostKey: hostKeyFixture(t).Marshal(), AddedBy: strings.Repeat("b", 32), Added: 1}
	}
	rdp := func() webServer {
		return webServer{ID: strings.Repeat("a", 32), Name: "Desk", Protocol: "rdp", Hostname: "rdp.invalid", Pins: []string{"10.34.0.8"}, Port: 3389, Certificate: desktop.Identity, Added: 1, FromFile: true}
	}
	if !ssh().valid() || !rdp().valid() {
		t.Fatal("valid shapes refused")
	}
	// At a literal address an RDP server's identity is its exact certificate,
	// so the certificate alone must be fit; it names no address.
	literal := func(der []byte) webServer {
		return webServer{ID: strings.Repeat("a", 32), Name: "Desk", Protocol: "rdp", Address: "10.34.0.8", Port: 3389, Certificate: der, AddedBy: strings.Repeat("b", 32), Added: 1}
	}
	if !literal(windowsLeaf(t, nil).Raw).valid() || !literal(desktop.Identity).valid() {
		t.Fatal("an RDP server at a literal address was refused")
	}
	for name, der := range map[string][]byte{
		"a CA":            windowsLeaf(t, func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }).Raw,
		"no server usage": windowsLeaf(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }).Raw,
		"no key usage":    windowsLeaf(t, func(c *x509.Certificate) { c.KeyUsage = 0 }).Raw,
		"not one at all":  []byte("not a certificate"),
		"too long":        make([]byte, rdpcert.MaxCertificate+1),
	} {
		if literal(der).valid() {
			t.Fatalf("an RDP server at a literal address with %s was accepted", name)
		}
	}
	repeated := []string{strings.Repeat("c", 32), strings.Repeat("c", 32)}
	for i, change := range []func(*webServer){
		func(w *webServer) { w.Removed = true },                          // removed, never from the file
		func(w *webServer) { w.FromFile = true },                         // from the file, yet added by someone
		func(w *webServer) { w.Hostname = "box.invalid" },                // a name and an address
		func(w *webServer) { w.Address, w.Hostname = "", "box.invalid" }, // a name without pins
		func(w *webServer) { w.Address = "" },                            // nowhere
		func(w *webServer) { w.Certificate = desktop.Identity },          // SSH with a certificate
		func(w *webServer) { w.Protocol = "telnet" },                     // unknown protocol
		func(w *webServer) { w.Access = repeated },                       // someone listed twice
	} {
		w := ssh()
		change(&w)
		if w.valid() {
			t.Fatalf("SSH shape %d accepted", i)
		}
	}
	for i, change := range []func(*webServer){
		func(w *webServer) { w.Hostname = "other.invalid" },                // a certificate for another name
		func(w *webServer) { w.Pins = []string{"10.34.0.9", "10.34.0.8"} }, // pins out of order
		func(w *webServer) { w.Pins = []string{"10.34.0.8", "10.34.0.8"} }, // a pin twice
		func(w *webServer) { w.Hostname = "RDP.invalid" },                  // not the stored form
		func(w *webServer) { w.HostKey = hostKeyFixture(t).Marshal() },     // RDP with a host key
		func(w *webServer) { w.Removed, w.Access = true, repeated[:1] },    // a marker with people on it
	} {
		w := rdp()
		change(&w)
		if w.valid() {
			t.Fatalf("RDP shape %d accepted", i)
		}
	}
}
