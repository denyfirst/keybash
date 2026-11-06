package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/rdpcert"
	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

var (
	windowsKey     *rsa.PrivateKey
	windowsKeyOnce sync.Once
)

// windowsLeaf is what Windows Server 2025 makes for itself: self-signed, its
// computer name as the common name, no alternative names, and key encipherment
// without digital signature, valid for six months.
func windowsLeaf(t *testing.T, change func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	windowsKeyOnce.Do(func() { windowsKey, _ = rsa.GenerateKey(rand.Reader, 2048) })
	if windowsKey == nil {
		t.Fatal("fixture key failed")
	}
	serial, e := rand.Int(rand.Reader, big.NewInt(1<<62))
	if e != nil {
		t.Fatal("fixture serial failed")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "SYNTHETIC-HOST"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(180 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if change != nil {
		change(template)
	}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &windowsKey.PublicKey, windowsKey)
	if e != nil {
		t.Fatal("fixture certificate failed")
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal("fixture certificate unreadable")
	}
	return cert
}

// fixtureCertificates answers certificate reads from a table: what each
// endpoint shows now, or why it cannot be read.
type fixtureCertificates struct {
	mu     sync.Mutex
	certs  map[netip.AddrPort]*x509.Certificate
	errs   map[netip.AddrPort]error
	calls  int
	onRead func()
}

func newFixtureCertificates() *fixtureCertificates {
	return &fixtureCertificates{certs: map[netip.AddrPort]*x509.Certificate{}, errs: map[netip.AddrPort]error{}}
}
func (f *fixtureCertificates) set(endpoint string, cert *x509.Certificate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at := netip.MustParseAddrPort(endpoint)
	f.certs[at] = cert
	delete(f.errs, at)
}
func (f *fixtureCertificates) fail(endpoint string, e error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[netip.MustParseAddrPort(endpoint)] = e
}
func (f *fixtureCertificates) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}
func (f *fixtureCertificates) scan(_ context.Context, target *targetguard.NamedTarget) (*x509.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.onRead != nil {
		f.onRead()
	}
	snapshot := target.Snapshot()
	at := netip.AddrPortFrom(netip.MustParseAddr(snapshot.Addresses[0]), snapshot.Port)
	if e := f.errs[at]; e != nil {
		return nil, e
	}
	if cert := f.certs[at]; cert != nil {
		return cert, nil
	}
	return nil, errors.New("synthetic: nothing answers")
}

// desktopWorker stands in for the RDP manager: an echo stream, counting who
// asked it to connect.
type desktopWorker struct {
	calls   atomic.Int32
	mu      sync.Mutex
	literal bool
	pinned  []byte
}

func (d *desktopWorker) OpenRDP(ctx context.Context, r RDPRequest) (terminalweb.Stream, error) {
	d.calls.Add(1)
	d.mu.Lock()
	d.literal, d.pinned = r.Target.Literal(), r.Certificate
	d.mu.Unlock()
	left, right := net.Pipe()
	go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
	go func() { <-ctx.Done(); _ = left.Close() }()
	return fixtureRemoteStream{left}, nil
}

// desktopFixture is a lab with an SSH and an RDP worker and target networks,
// watching certificates at an interval no test reaches, whose administrator
// alice is ready and freshly proved. Reads are answered by the returned table.
func desktopFixture(t *testing.T) (*adminLab, *fixtureCertificates, *desktopWorker) {
	t.Helper()
	return desktopFixtureAt(t, "https://127.0.0.1:8443")
}

func desktopFixtureAt(t *testing.T, origin string) (*adminLab, *fixtureCertificates, *desktopWorker) {
	t.Helper()
	store, _, _ := bootstrapped(t)
	f := &adminLab{t: t, store: store, now: time.Now(), target: catalogSSHFixture(t)}
	_, _, codes := enrollFixture(t, store, "alice", f.now)
	worker := &desktopWorker{}
	l, e := NewRemoteLabWithLimits(origin, store, []RemoteTarget{f.target}, echoSSHWorker{}, worker, sessionlimits.Default(), TargetNetworks(serverNetworks, serverProtected), WatchCertificates(24*time.Hour))
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	t.Cleanup(func() { _ = l.Close() })
	reads := newFixtureCertificates()
	f.l = l
	l.mu.Lock()
	l.now = func() time.Time { return f.now }
	l.remote.scanRDP = reads.scan
	l.mu.Unlock()
	f.alice = &custodyClient{t: t, l: l}
	f.alice.login()
	f.alice.session("challenge")
	f.alice.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	f.alice.session("ready")
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	f.codes = codes[2:]
	return f, reads, worker
}

func rdpFields(name, address, port, fingerprint string) string {
	fields := map[string]string{"protocol": "rdp", "address": address, "port": port}
	if name != "" {
		fields["name"], fields["fingerprint"] = name, fingerprint
	}
	return inputJSON(fields)
}

// addDesktop adds an RDP server as an administrator would: read it, bring the
// fingerprint from its console, add it.
func addDesktop(t *testing.T, f *adminLab, reads *fixtureCertificates, name, endpoint string) (string, *x509.Certificate) {
	t.Helper()
	cert := windowsLeaf(t, nil)
	reads.set(endpoint, cert)
	at := netip.MustParseAddrPort(endpoint)
	address, port := at.Addr().String(), strings.TrimPrefix(endpoint, at.Addr().String()+":")
	f.alice.expect("POST", "/api/servers/scan", rdpFields("", address, port, ""), 200)
	var made struct{ ID string }
	if json.Unmarshal(f.alice.expect("POST", "/api/servers", rdpFields(name, address, port, certificatePrint(cert)), 200).Body.Bytes(), &made) != nil || !validID(made.ID) {
		t.Fatal("RDP server was not added")
	}
	return made.ID, cert
}

// A desktop connection that belongs to a person on the server's list.
func desktopConnection(t *testing.T, f *adminLab, c *custodyClient, owner durableAccount, server string) string {
	t.Helper()
	f.alice.expect("POST", "/api/servers/"+server+"/grant", inputJSON(map[string]string{"account": owner.ID}), 204)
	credential, e := f.store.putCredential(owner.ID, Credential{Name: "Synthetic desktop", Kind: "password", Username: "synthetic-user", Secret: "Synthetic remote password"})
	if e != nil {
		t.Fatal("fixture credential failed")
	}
	f.l.mu.Lock()
	target := f.l.remote.targets[server]
	f.l.mu.Unlock()
	var record struct{ ID string }
	if json.Unmarshal(c.expect("POST", "/api/connections", inputJSON(map[string]string{"name": "Desk", "target": server, "credential": credential, "approval": approvalFingerprint(target)}), 200).Body.Bytes(), &record) != nil || !validID(record.ID) {
		t.Fatal("fixture connection failed")
	}
	return record.ID
}

func connectionTrust(t *testing.T, c *custodyClient) string {
	t.Helper()
	var rows []struct{ Trust string }
	if json.Unmarshal(c.expect("GET", "/api/connections", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 {
		t.Fatal("connections unreadable")
	}
	return rows[0].Trust
}

// A fingerprint is never handed out for RDP: an administrator can add a server
// only with the one they bring from its console, read again at that moment.
func TestRDPServersAreAddedOnlyWithTheConsoleFingerprint(t *testing.T) {
	f, reads, _ := desktopFixture(t)
	cert := windowsLeaf(t, nil)
	print := certificatePrint(cert)
	reads.set("10.20.0.8:3389", cert)
	// Reading says only that it can be used, and until when.
	shown := f.alice.expect("POST", "/api/servers/scan", rdpFields("", "10.20.0.8", "3389", ""), 200).Body.String()
	if strings.Contains(shown, strings.TrimPrefix(print, "SHA256:")) || strings.Contains(shown, "fingerprint") {
		t.Fatalf("a read handed out the fingerprint: %s", shown)
	}
	var read struct{ Expires int64 }
	if json.Unmarshal([]byte(shown), &read) != nil || read.Expires != cert.NotAfter.Unix() {
		t.Fatalf("a read did not say when the certificate ends: %s", shown)
	}
	add := func(fingerprint string, status int) {
		t.Helper()
		f.alice.expect("POST", "/api/servers", rdpFields("Desk", "10.20.0.8", "3389", fingerprint), status)
	}
	// Not what the server shows, in any form: nothing is stored.
	add(certificatePrint(windowsLeaf(t, nil)), 409)
	add("SHA256:"+strings.Repeat("0", 64), 409)
	add("SHA256:"+strings.Repeat("A", 43), 409)
	add(strings.ToUpper(print), 400)
	add(strings.TrimPrefix(print, "SHA256:"), 400)
	if list, _ := f.store.listServers(); len(list) != 1 {
		t.Fatal("a server whose fingerprint did not match was stored")
	}
	before := reads.count()
	add(print, 200)
	if reads.count() != before+1 {
		t.Fatal("adding did not read the certificate again")
	}
	// A server that changed between the console and the click is refused.
	reads.set("10.20.0.9:3389", windowsLeaf(t, nil))
	f.alice.expect("POST", "/api/servers", rdpFields("Other", "10.20.0.9", "3389", print), 409)
	add(print, 409) // already listed
	view := listServersView(t, f.alice)
	if !view.RDP || !view.SSH || !view.Adding {
		t.Fatalf("servers view %+v", view)
	}
	var row serverView
	for _, candidate := range view.Servers {
		if candidate.Name == "Desk" {
			row = candidate
		}
	}
	if row.Protocol != "rdp" || row.Hostname != "10.20.0.8" || row.Port != 3389 || row.Fingerprint != print || row.Certificate != "current" || row.Expires != cert.NotAfter.Unix() || !row.Available || len(row.Access) != 0 {
		t.Fatalf("added server row %+v", row)
	}
	// Nobody is on its list, not even the administrator who added it.
	f.alice.expect("GET", "/api/targets/"+row.ID, "", 404)
	// The stored record is exactly the certificate the server showed.
	list, e := f.store.listServers()
	if e != nil {
		t.Fatal("servers unreadable")
	}
	for _, w := range list {
		if w.ID == row.ID && (w.Address != "10.20.0.8" || w.Hostname != "" || string(w.Certificate) != string(cert.Raw) || len(w.HostKey) != 0) {
			t.Fatalf("stored server differs: %+v", w)
		}
	}
}

func TestRDPServersAreRefusedWhatCannotBeUsed(t *testing.T) {
	f, reads, _ := desktopFixture(t)
	scan := func(address string, status int) {
		t.Helper()
		f.alice.expect("POST", "/api/servers/scan", rdpFields("", address, "3389", ""), status)
	}
	// Outside the networks, or where a server already answers: never dialled.
	for _, outside := range []string{"10.21.0.7", "10.99.0.7", "127.0.0.1", "169.254.169.254"} {
		scan(outside, 403)
	}
	if reads.count() != 0 {
		t.Fatal("a refused address was read")
	}
	scan("10.20.0.8", 502) // nothing answers
	reads.fail("10.20.0.8:3389", rdpcert.ErrNegotiation)
	scan("10.20.0.8", 422) // it does not require NLA
	reads.fail("10.20.0.8:3389", rdpcert.ErrIdentity)
	scan("10.20.0.8", 422) // its handshake failed
	reads.fail("10.20.0.8:3389", rdpcert.ErrUnavailable)
	f.advance(time.Minute)
	scan("10.20.0.8", 502)
	for name, cert := range map[string]*x509.Certificate{
		"expired":   windowsLeaf(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }),
		"not yet":   windowsLeaf(t, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }),
		"a CA":      windowsLeaf(t, func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }),
		"no server": windowsLeaf(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }),
	} {
		reads.set("10.20.0.8:3389", cert)
		f.advance(time.Minute)
		scan("10.20.0.8", 422)
		f.alice.expect("POST", "/api/servers", rdpFields("Desk", "10.20.0.8", "3389", certificatePrint(cert)), 422)
		if list, _ := f.store.listServers(); len(list) != 1 {
			t.Fatalf("a certificate that is %s was stored", name)
		}
	}
	// An installation without RDP adds none, and says so.
	g, greads := serversFixture(t)
	view := listServersView(t, g.alice)
	if view.RDP || !view.SSH || !view.Adding {
		t.Fatalf("an SSH-only view %+v", view)
	}
	g.alice.expect("POST", "/api/servers/scan", rdpFields("", "10.20.0.8", "3389", ""), 409)
	if greads.calls != 0 {
		t.Fatal("an SSH-only installation read a server")
	}
	// Only a fresh administrator reads or adds.
	bob, _ := f.person("bob", roleUser)
	dave, _ := f.person("dave", roleAuditor)
	for _, c := range []*custodyClient{bob, dave} {
		c.expect("POST", "/api/servers/scan", rdpFields("", "10.20.0.8", "3389", ""), 403)
	}
	f.advance(freshProof + time.Minute)
	before := reads.count()
	f.alice.expect("POST", "/api/servers/scan", rdpFields("", "10.20.0.8", "3389", ""), 428)
	if reads.count() != before {
		t.Fatal("a read without fresh proof went out")
	}
}

// The six-month renewal: nobody's connection is silently moved to the new
// certificate, and an administrator accepts it only with the fingerprint from
// the console. Each person then accepts it on their own connection.
func TestRDPRenewalNeedsTheConsoleFingerprintAndEachPerson(t *testing.T) {
	f, reads, worker := desktopFixture(t)
	id, old := addDesktop(t, f, reads, "Desk", "10.20.0.8:3389")
	bob, b := f.person("bob", roleUser)
	record := desktopConnection(t, f, bob, b, id)
	if connectionTrust(t, bob) != "verified" {
		t.Fatal("a new connection is not ready")
	}
	// The server still shows what is pinned: nothing to do.
	var same struct {
		Same    bool
		Expires int64
	}
	if json.Unmarshal(f.alice.expect("POST", "/api/servers/"+id+"/scan", "{}", 200).Body.Bytes(), &same) != nil || !same.Same || same.Expires != old.NotAfter.Unix() {
		t.Fatal("the same certificate was not reported as the same")
	}
	// Windows renews: a read says it differs and does not say what it is.
	next := windowsLeaf(t, nil)
	reads.set("10.20.0.8:3389", next)
	shown := f.alice.expect("POST", "/api/servers/"+id+"/scan", "{}", 200).Body.String()
	if strings.Contains(shown, strings.TrimPrefix(certificatePrint(next), "SHA256:")) || strings.Contains(shown, "fingerprint") {
		t.Fatalf("a read handed out the new fingerprint: %s", shown)
	}
	if json.Unmarshal([]byte(shown), &same) != nil || same.Same {
		t.Fatal("a different certificate was reported as the same")
	}
	row, _ := serverRow(listServersView(t, f.alice), id)
	if row.Certificate != "changed" || row.Fingerprint != certificatePrint(old) {
		t.Fatalf("a renewed server row %+v", row)
	}
	if connectionTrust(t, bob) != "stopped" {
		t.Fatal("a person's connection does not say the server changed")
	}
	// Anything but the console's fingerprint leaves the pin as it was.
	key := func(fingerprint string, status int) {
		t.Helper()
		f.alice.expect("POST", "/api/servers/"+id+"/key", inputJSON(map[string]string{"fingerprint": fingerprint}), status)
	}
	key(certificatePrint(old), 409)
	key(certificatePrint(windowsLeaf(t, nil)), 409)
	key("not a fingerprint", 400)
	if row, _ = serverRow(listServersView(t, f.alice), id); row.Fingerprint != certificatePrint(old) {
		t.Fatal("a wrong fingerprint changed the pin")
	}
	// Someone else is refused whatever they bring.
	bob.expect("POST", "/api/servers/"+id+"/key", inputJSON(map[string]string{"fingerprint": certificatePrint(next)}), 403)
	// A certificate that cannot be used is never pinned, even when it matches.
	unfit := windowsLeaf(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil })
	reads.set("10.20.0.8:3389", unfit)
	key(certificatePrint(unfit), 422)
	reads.set("10.20.0.8:3389", next)
	key(certificatePrint(next), 204)
	row, _ = serverRow(listServersView(t, f.alice), id)
	if row.Fingerprint != certificatePrint(next) || row.Certificate != "current" || row.Expires != next.NotAfter.Unix() {
		t.Fatalf("a re-pinned server row %+v", row)
	}
	// The person decides for their own connection; it does not move by itself.
	if connectionTrust(t, bob) != "changed" {
		t.Fatal("a re-pinned server did not ask its users")
	}
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 401)
	var target struct{ Approval string }
	if json.Unmarshal(bob.expect("GET", "/api/targets/"+id, "", 200).Body.Bytes(), &target) != nil {
		t.Fatal("target unreadable")
	}
	var rows []struct{ Revision string }
	if json.Unmarshal(bob.expect("GET", "/api/connections", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 {
		t.Fatal("connections unreadable")
	}
	bob.expect("POST", "/api/connections/"+record+"/trust", inputJSON(map[string]string{"approval": target.Approval, "revision": rows[0].Revision}), 204)
	if connectionTrust(t, bob) != "verified" {
		t.Fatal("the person could not accept the new identity")
	}
	if worker.calls.Load() != 0 {
		t.Fatal("something opened a desktop while checking identities")
	}
	// A server with no RDP certificate takes no certificate as its identity.
	alice := mustLookup(t, f.store, "alice")
	ssh, e := f.store.addServer(alice.ID, "Terminal", "10.20.0.30", 22, hostKeyFixture(t).Marshal(), f.now)
	if e != nil {
		t.Fatal("fixture server failed")
	}
	if f.store.repinCertificate(alice.ID, ssh, next.Raw) == nil || f.store.repinCertificate(alice.ID, id, []byte("not a certificate")) == nil || f.store.repinServer(alice.ID, id, hostKeyFixture(t).Marshal()) == nil {
		t.Fatal("a server took another kind's identity")
	}
}

// What the gateway reads tells people and administrators; it writes nothing and
// grants nothing, and it follows the server back as well as away.
func TestCertificateWatchTellsPeopleAndWritesNothing(t *testing.T) {
	f, reads, _ := desktopFixture(t)
	id, old := addDesktop(t, f, reads, "Desk", "10.20.0.8:3389")
	bob, b := f.person("bob", roleUser)
	_ = desktopConnection(t, f, bob, b, id)
	state := func() string {
		t.Helper()
		row, ok := serverRow(listServersView(t, f.alice), id)
		if !ok {
			t.Fatal("server not listed")
		}
		return row.Certificate
	}
	stored := func() []byte {
		t.Helper()
		list, e := f.store.listServers()
		if e != nil {
			t.Fatal("servers unreadable")
		}
		for _, w := range list {
			if w.ID == id {
				return w.Certificate
			}
		}
		t.Fatal("server not stored")
		return nil
	}
	read := func() { t.Helper(); f.l.readCertificates(context.Background()) }
	read()
	if state() != "current" || connectionTrust(t, bob) != "verified" {
		t.Fatal("an unchanged server does not read as current")
	}
	// Windows renewed: the administrator is told, and so is the person.
	reads.set("10.20.0.8:3389", windowsLeaf(t, nil))
	read()
	if state() != "changed" || connectionTrust(t, bob) != "stopped" {
		t.Fatal("a changed certificate was not noticed")
	}
	if string(stored()) != string(old.Raw) {
		t.Fatal("a read changed the pin")
	}
	// Not answering says nothing new: only a certificate changes what is known.
	reads.fail("10.20.0.8:3389", errors.New("synthetic: unreachable"))
	read()
	if state() != "changed" {
		t.Fatal("a server that did not answer lost what was last seen")
	}
	// A bad actor who stops, or a router that comes back, clears it by itself.
	reads.set("10.20.0.8:3389", old)
	read()
	if state() != "current" || connectionTrust(t, bob) != "verified" {
		t.Fatal("the pinned certificate did not read as current again")
	}
	// The date: two weeks before the end it says so; after it nobody connects.
	ending := windowsLeaf(t, func(c *x509.Certificate) { c.NotAfter = f.now.Add(certificateSoon - time.Hour) })
	reads.set("10.20.0.8:3389", ending)
	f.alice.expect("POST", "/api/servers/"+id+"/key", inputJSON(map[string]string{"fingerprint": certificatePrint(ending)}), 204)
	if state() != "soon" {
		t.Fatalf("a certificate ending soon reads %q", state())
	}
	short := windowsLeaf(t, func(c *x509.Certificate) { c.NotAfter = f.now.Add(time.Minute) })
	reads.set("10.20.0.8:3389", short)
	f.alice.expect("POST", "/api/servers/"+id+"/key", inputJSON(map[string]string{"fingerprint": certificatePrint(short)}), 204)
	f.advance(2 * time.Minute)
	if row, _ := serverRow(listServersView(t, f.alice), id); row.Certificate != "expired" || row.Available {
		t.Fatalf("an expired pin reads %+v", row)
	}
	// Past its end, a certificate the server still shows is still not pinned.
	f.alice.expect("POST", "/api/servers/"+id+"/key", inputJSON(map[string]string{"fingerprint": certificatePrint(short)}), 422)
	// Removing the server forgets it.
	reads.set("10.20.0.8:3389", windowsLeaf(t, nil))
	read()
	f.alice.expect("DELETE", "/api/servers/"+id, "{}", 204)
	f.l.mu.Lock()
	_, kept := f.l.remote.seen[id]
	f.l.mu.Unlock()
	if kept {
		t.Fatal("a removed server was remembered")
	}
	// A read never says "changed" about a server nobody has read yet, and an
	// SSH server has no certificate to speak of.
	f.l.mu.Lock()
	state1, _ := f.l.certificateStateLocked(webServer{ID: id, Protocol: "rdp", Certificate: old.Raw})
	state2, ends := f.l.certificateStateLocked(webServer{ID: id, Protocol: "ssh"})
	f.l.mu.Unlock()
	if state1 == "changed" || state2 != "" || ends != 0 {
		t.Fatalf("certificate states %q %q %d", state1, state2, ends)
	}
}

func TestWatchCertificatesStartsWithRDPAndStopsWithTheLab(t *testing.T) {
	store, _, _ := bootstrapped(t)
	for _, options := range [][]Option{
		{WatchCertificates(0)},
		{WatchCertificates(-time.Second)},
		{WatchCertificates(time.Hour), WatchCertificates(time.Hour)},
	} {
		if l, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", store, nil, echoSSHWorker{}, &desktopWorker{}, sessionlimits.Default(), options...); e == nil {
			_ = l.Close()
			t.Fatal("a bad watch option was accepted")
		}
	}
	// Without an RDP worker there is nothing to watch.
	l, e := NewRemoteLabWithLimits("https://127.0.0.1:8443", store, nil, echoSSHWorker{}, nil, sessionlimits.Default(), WatchCertificates(time.Millisecond))
	if e != nil {
		t.Fatal("watching without RDP refused the lab")
	}
	l.mu.Lock()
	watching := l.remote.watching
	l.mu.Unlock()
	_ = l.Close()
	if watching {
		t.Fatal("an installation without RDP watches certificates")
	}
	// With one it reads at its interval, and Close waits for it to end.
	f, reads, _ := desktopFixture(t)
	addDesktop(t, f, reads, "Desk", "10.20.0.8:3389")
	done := make(chan struct{})
	f.l.background.Add(1)
	go func() { f.l.certificateWatch(time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	base := reads.count()
	for reads.count() < base+3 {
		if time.Now().After(deadline) {
			t.Fatal("the watch did not read at its interval")
		}
		time.Sleep(time.Millisecond)
	}
	if f.l.Close() != nil {
		t.Fatal("close failed")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch outlived the lab")
	}
	after := reads.count()
	time.Sleep(20 * time.Millisecond)
	if reads.count() != after {
		t.Fatal("the watch read after the lab closed")
	}
}

// Just before a session opens the gateway reads once more. A different
// certificate stops it there, before any worker exists, and the person is told.
// Everything else is left to the worker, which checks its own handshake.
func TestSocketStopsBeforeAnyWorkerWhenTheServerChanged(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	f, reads, worker := desktopFixtureAt(t, origin)
	server.Config.Handler = f.l
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	id, old := addDesktop(t, f, reads, "Desk", "10.20.0.8:3389")
	bob, b := f.person("bob", roleUser)
	record := desktopConnection(t, f, bob, b, id)
	connect := func() string {
		t.Helper()
		raw := grantFixture(t, bob, record)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		header := http.Header{"Origin": []string{origin}, "Cookie": []string{bob.cookie.String()}}
		socket, _, e := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/socket", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: header})
		if e != nil {
			t.Fatal("valid socket refused")
		}
		defer socket.CloseNow()
		if socket.Write(ctx, websocket.MessageText, []byte(inputJSON(map[string]string{"csrf": bob.csrf, "lease": raw}))) != nil {
			t.Fatal("proof write failed")
		}
		_, data, e := socket.Read(ctx)
		if e != nil {
			t.Fatal("the socket closed without saying why")
		}
		return string(data)
	}
	if connect() != `{"type":"ready"}` || worker.calls.Load() != 1 {
		t.Fatal("the pinned server did not open")
	}
	worker.mu.Lock()
	literal, pinned := worker.literal, worker.pinned
	worker.mu.Unlock()
	if !literal || string(pinned) != string(old.Raw) {
		t.Fatal("the worker was not given the literal target and its pin")
	}
	// Renewed since the last read: nothing below this point ever runs.
	reads.set("10.20.0.8:3389", windowsLeaf(t, nil))
	if got := connect(); got != `{"type":"identity-changed"}` {
		t.Fatalf("the socket said %s", got)
	}
	if worker.calls.Load() != 1 {
		t.Fatal("a worker started for a server that changed")
	}
	// The read itself told the administrator.
	if row, _ := serverRow(listServersView(t, f.alice), id); row.Certificate != "changed" {
		t.Fatal("a stopped session did not tell the administrator")
	}
	// The read cannot grant anything: when it fails the worker decides, holding
	// the pin, and when it is lost the worker still gets only the pin.
	reads.set("10.20.0.8:3389", old)
	reads.fail("10.20.0.8:3389", errors.New("synthetic: no answer"))
	if connect() != `{"type":"ready"}` || worker.calls.Load() != 2 {
		t.Fatal("a failed read decided instead of the worker")
	}
	// Without the watch nothing is read before a session.
	f.l.mu.Lock()
	f.l.remote.watching = false
	f.l.mu.Unlock()
	before := reads.count()
	reads.set("10.20.0.8:3389", windowsLeaf(t, nil))
	if connect() != `{"type":"ready"}` || reads.count() != before {
		t.Fatal("a session read the server without the watch")
	}
}

// A read through the guard stops at the guard, and an endless server is cut off.
func TestScanCertificateIsGuardedAndBounded(t *testing.T) {
	endpoint := netip.MustParseAddrPort("10.20.0.8:3389")
	policy, e := targetguard.New([]netip.AddrPort{netip.MustParseAddrPort("10.20.0.9:3389")}, serverProtected)
	if e != nil {
		t.Fatal("fixture policy failed")
	}
	if _, ok := guardedTarget(endpoint, serverNetworks, serverProtected); !ok {
		t.Fatal("fixture target refused")
	}
	if _, e := targetguard.NewAddressTarget(policy, endpoint.Addr(), endpoint.Port()); e == nil {
		t.Fatal("a target outside the policy was made")
	}
	var empty targetguard.NamedTarget
	if cert, e := scanCertificate(context.Background(), &empty); cert != nil || e == nil {
		t.Fatal("a read went through an empty target")
	}
	client, server := net.Pipe()
	written := make(chan int, 1)
	go func() {
		defer server.Close()
		var request [19]byte
		_, _ = io.ReadFull(server, request[:])
		confirmation := []byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 1, 0, 2, 0, 8, 0, 2, 0, 0, 0}
		_, _ = server.Write(confirmation)
		go func() { _, _ = io.Copy(io.Discard, server) }()
		chunk := make([]byte, 4096)
		total := 0
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
	if cert, e := rdpcert.Read(context.Background(), &cappedConn{Conn: client, left: 64 << 10}); cert != nil || e == nil {
		t.Fatal("an endless server was accepted")
	}
	_ = client.Close()
	if total := <-written; total > 64<<10 {
		t.Fatalf("read %d bytes from a server, over the bound", total)
	}
}

func TestBackupCarriesRDPServers(t *testing.T) {
	s, key, _ := bootstrapped(t)
	now := time.Now()
	alice := mustLookup(t, s, "alice")
	cert := windowsLeaf(t, nil)
	id, e := s.addRDPServer(alice.ID, "Backup canary desk", "10.20.0.8", 3389, cert.Raw, now)
	if e != nil {
		t.Fatal("fixture server failed")
	}
	if _, e = s.addRDPServer(alice.ID, "Same place", "10.20.0.8", 3389, windowsLeaf(t, nil).Raw, now); e != errDuplicate {
		t.Fatal("a second server at the same address and port was stored")
	}
	bob, e := s.CreateAccount("bob", bobPassword)
	if e != nil {
		t.Fatal("fixture account failed")
	}
	_ = bob
	if _, e = s.addRDPServer(mustLookup(t, s, "bob").ID, "Bob's", "10.20.0.9", 3389, cert.Raw, now); e == nil {
		t.Fatal("a user added a server")
	}
	for _, bad := range [][]byte{nil, []byte("not a certificate"), windowsLeaf(t, func(c *x509.Certificate) { c.KeyUsage = 0 }).Raw} {
		if _, e = s.addRDPServer(alice.ID, "Bad", "10.20.0.9", 3389, bad, now); e == nil {
			t.Fatal("an unfit certificate was stored")
		}
	}
	restored, _, summary, e := restoreStore(emptyDataDir(t), key, backupOf(t, s, now), now)
	if e != nil || summary.Servers != 1 {
		t.Fatalf("backup with an RDP server not restored: %+v", summary)
	}
	defer restored.Close()
	list, e := restored.listServers()
	if e != nil || len(list) != 1 || list[0].ID != id || string(list[0].Certificate) != string(cert.Raw) || list[0].Protocol != "rdp" {
		t.Fatal("restored RDP server differs")
	}
}
