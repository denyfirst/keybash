package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// Shared credentials (docs/adr/0009-shared-server-credentials.md).

func sharedSet(kind, username, secret string) string {
	return inputJSON(map[string]string{"kind": kind, "username": username, "secret": secret})
}
func sharedPrint(fingerprint string) string {
	return inputJSON(map[string]string{"fingerprint": fingerprint})
}

// pemLines are the lines of a private key's PEM body, each of which must
// never appear in anything Keybash answers.
func pemLines(t *testing.T, secret string) []string {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(secret), "\n") {
		if !strings.HasPrefix(line, "-----") && len(line) >= 16 {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		t.Fatal("fixture key has no body")
	}
	return lines
}

func TestSharedCredentialIsAnAdministratorsAndNeverShown(t *testing.T) {
	f, scans := serversFixture(t)
	keyServer, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	passwordServer, _ := addServerFixture(t, f.alice, scans, "Db", "10.20.0.8:22")
	var seen []string
	say := func(c *custodyClient, method, path, body string, status int) string {
		t.Helper()
		answer := c.expect(method, path, body, status).Body.String()
		seen = append(seen, answer)
		return answer
	}
	shared := func(c *custodyClient, server string) *sharedView {
		t.Helper()
		var view serversView
		if json.Unmarshal([]byte(say(c, "GET", "/api/servers", "", 200)), &view) != nil {
			t.Fatal("servers unreadable")
		}
		row, ok := serverRow(view, server)
		if !ok {
			t.Fatal("server missing")
		}
		return row.Shared
	}
	at := func(server, action string) string { return "/api/servers/" + server + "/" + action }

	// Every change needs fresh proof, like adding a server.
	f.advance(freshProof + time.Minute)
	say(f.alice, "POST", at(keyServer, "shared"), sharedSet("ssh-key", "deploy", ""), 428)
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": f.codes[0]}), 204)
	f.advance(61 * time.Second) // a fresh minute of server changes

	// Only an administrator sets one; malformed requests make nothing.
	bob, _ := f.person("bob", roleUser)
	dave, _ := f.person("dave", roleAuditor)
	say(bob, "POST", at(keyServer, "shared"), sharedSet("ssh-key", "deploy", ""), 403)
	say(dave, "POST", at(keyServer, "shared"), sharedSet("ssh-key", "deploy", ""), 403)
	for _, who := range []string{"bob", "dave"} {
		if f.store.setShared(mustLookup(t, f.store, who).ID, keyServer, "ssh-key", "deploy", "", f.now) == nil {
			t.Fatal("the store let a user or an auditor set a shared credential")
		}
	}
	for _, bad := range []string{
		sharedSet("rsa", "deploy", ""), sharedSet("ssh-key", "", ""), sharedSet("ssh-key", " deploy", ""), sharedSet("ssh-key", "de\x00ploy", ""),
		sharedSet("ssh-key", strings.Repeat("u", 129), ""), sharedSet("ssh-key", "deploy", "-----BEGIN OPENSSH PRIVATE KEY-----"),
		sharedSet("password", "deploy", ""), sharedSet("password", "deploy", "pass\x00word"), sharedSet("password", "deploy", strings.Repeat("p", 4097)),
		`{"kind":"ssh-key","username":"deploy"}`, `{"kind":"ssh-key","username":"deploy","secret":"","generated":"true"}`,
	} {
		say(f.alice, "POST", at(keyServer, "shared"), bad, 400)
	}
	if shared(f.alice, keyServer) != nil {
		t.Fatal("a refused request made a shared credential")
	}
	say(f.alice, "POST", at(strings.Repeat("e", 32), "shared"), sharedSet("ssh-key", "deploy", ""), 404)

	// A key is made here, once per server.
	say(f.alice, "POST", at(keyServer, "shared"), sharedSet("ssh-key", "deploy", ""), 204)
	say(f.alice, "POST", at(keyServer, "shared"), sharedSet("ssh-key", "deploy", ""), 409)
	say(f.alice, "POST", at(keyServer, "shared"), sharedSet("password", "deploy", "Synthetic password"), 409)
	alice := mustLookup(t, f.store, "alice")
	first, e := f.store.readShared(keyServer)
	if e != nil || first.Current.Kind != "ssh-key" || !first.Current.Generated || first.Current.Username != "deploy" || first.Generation != 1 || first.SetBy != alice.ID || first.Next != nil {
		t.Fatalf("stored shared key: %v", e)
	}
	view := shared(f.alice, keyServer)
	if view == nil || view.Kind != "ssh-key" || view.Username != "deploy" || view.Line != "restrict,pty "+first.Current.Public+" keybash-shared" ||
		view.Fingerprint != first.Current.Fingerprint || view.Used || view.Next != "" || view.SetBy != alice.ID || view.Set != f.now.Unix() {
		t.Fatalf("the administrator's view: %+v", view)
	}
	// An auditor reads the same summary; a user does not read the page.
	if audited := shared(dave, keyServer); audited == nil || *audited != *view {
		t.Fatal("the auditor's view differs")
	}
	say(bob, "GET", "/api/servers", "", 403)

	// A password is typed once, shown never, and replaced at once.
	const marker = "Synthetic-shared-password-7f3a"
	say(f.alice, "POST", at(passwordServer, "shared"), sharedSet("password", "ops", marker), 204)
	if pw := shared(f.alice, passwordServer); pw == nil || pw.Kind != "password" || pw.Username != "ops" || pw.Line != "" || pw.Fingerprint != "" || pw.Next != "" {
		t.Fatalf("a password's view: %+v", pw)
	}
	say(bob, "POST", at(passwordServer, "shared-password"), inputJSON(map[string]string{"username": "ops", "secret": marker + "-bob"}), 403)
	say(f.alice, "POST", at(passwordServer, "shared-password"), inputJSON(map[string]string{"username": "ops", "secret": ""}), 400)
	say(f.alice, "POST", at(passwordServer, "shared-password"), inputJSON(map[string]string{"username": "ops", "secret": marker + "-2"}), 204)
	if c, e := f.store.readShared(passwordServer); e != nil || c.Current.Secret != marker+"-2" || c.Generation != 2 {
		t.Fatal("the password was not replaced at once")
	}
	// Keys and passwords do not change into each other.
	say(f.alice, "POST", at(keyServer, "shared-password"), inputJSON(map[string]string{"username": "deploy", "secret": marker}), 403)
	say(f.alice, "POST", at(passwordServer, "shared-next"), "{}", 403)
	f.advance(61 * time.Second)

	// A key is replaced in two steps: the current one works until the switch.
	say(bob, "POST", at(keyServer, "shared-next"), "{}", 403)
	say(f.alice, "POST", at(keyServer, "shared-next"), "{}", 204)
	waiting, e := f.store.readShared(keyServer)
	if e != nil || waiting.Next == nil || waiting.Current.Fingerprint != first.Current.Fingerprint || waiting.Current.Secret != first.Current.Secret || waiting.Generation != 1 || waiting.Next.Username != "deploy" {
		t.Fatal("the next key replaced the current one early")
	}
	if view = shared(f.alice, keyServer); view.Fingerprint != first.Current.Fingerprint || view.Next != "restrict,pty "+waiting.Next.Public+" keybash-shared" || view.NextFingerprint != waiting.Next.Fingerprint {
		t.Fatalf("the view of a waiting key: %+v", view)
	}
	// The switch takes only the key the administrator saw.
	say(f.alice, "POST", at(keyServer, "shared-switch"), sharedPrint(first.Current.Fingerprint), 409)
	say(f.alice, "POST", at(keyServer, "shared-switch"), sharedPrint("SHA256:nope"), 400)
	say(bob, "POST", at(keyServer, "shared-switch"), sharedPrint(waiting.Next.Fingerprint), 403)
	say(f.alice, "POST", at(keyServer, "shared-switch"), sharedPrint(waiting.Next.Fingerprint), 204)
	switched, e := f.store.readShared(keyServer)
	if e != nil || switched.Current.Fingerprint != waiting.Next.Fingerprint || switched.Current.Secret != waiting.Next.Secret || switched.Next != nil || switched.Generation != 2 {
		t.Fatal("the switch did not make the waiting key the one used, and destroy the old one")
	}
	say(f.alice, "POST", at(keyServer, "shared-switch"), sharedPrint(waiting.Next.Fingerprint), 404)
	// A waiting key can be dropped; the current one stays.
	say(f.alice, "POST", at(keyServer, "shared-next"), "{}", 204)
	dropped, _ := f.store.readShared(keyServer)
	say(f.alice, "DELETE", at(keyServer, "shared-next"), "{}", 204)
	say(f.alice, "DELETE", at(keyServer, "shared-next"), "{}", 404)
	if c, e := f.store.readShared(keyServer); e != nil || c.Next != nil || c.Current.Fingerprint != switched.Current.Fingerprint || c.Generation != 2 {
		t.Fatal("dropping the waiting key changed the current one")
	}
	f.advance(61 * time.Second)

	// Removing it destroys it; removing a server takes its credential along.
	say(bob, "DELETE", at(keyServer, "shared"), "{}", 403)
	say(f.alice, "DELETE", at(keyServer, "shared"), "{}", 204)
	say(f.alice, "DELETE", at(keyServer, "shared"), "{}", 404)
	if _, e := f.store.readShared(keyServer); e != errMissing {
		t.Fatalf("a removed shared credential remains in the store: %v", e)
	}
	if shared(f.alice, keyServer) != nil {
		t.Fatal("a removed shared credential remains in the view")
	}
	say(f.alice, "DELETE", "/api/servers/"+passwordServer, "{}", 204)
	if f.store.view(func(tx *bolt.Tx) error {
		if b := tx.Bucket(sharedBucket); b == nil || b.Get([]byte(passwordServer)) != nil || b.Get([]byte(keyServer)) != nil {
			return errRefused
		}
		return nil
	}) != nil {
		t.Fatal("a removed server's shared credential remains")
	}

	// Nothing Keybash answered carried a secret.
	secrets := []string{marker, "PRIVATE KEY"}
	for _, key := range []Credential{first.Current, *waiting.Next, *dropped.Next} {
		secrets = append(secrets, pemLines(t, key.Secret)...)
	}
	for _, answer := range seen {
		for _, secret := range secrets {
			if strings.Contains(answer, secret) {
				t.Fatal("an answer carried a shared secret")
			}
		}
	}
}

func TestSharedRecordsAreCheckedOnRead(t *testing.T) {
	f, scans := serversFixture(t)
	one, _ := addServerFixture(t, f.alice, scans, "One", "10.20.0.7:22")
	two, _ := addServerFixture(t, f.alice, scans, "Two", "10.20.0.8:22")
	alice := mustLookup(t, f.store, "alice")
	if f.store.setShared(alice.ID, one, "ssh-key", "deploy", "", f.now) != nil {
		t.Fatal("fixture shared key refused")
	}
	verify := func() error {
		return f.store.view(func(tx *bolt.Tx) error { _, e := f.store.verifyAll(tx); return e })
	}
	if verify() != nil {
		t.Fatal("a store with a shared key did not verify")
	}
	good, _ := f.store.readShared(one)
	other, _ := newGeneratedKey(sharedName, "deploy")
	write := func(key string, c sharedCredential) {
		t.Helper()
		if e := f.store.update(func(tx *bolt.Tx) error {
			plain, e := json.Marshal(c)
			if e != nil {
				return e
			}
			sealed, e := f.store.seal(tx, "shared", key, key, 1, plain)
			if e != nil {
				return e
			}
			b, e := tx.CreateBucketIfNotExists(sharedBucket)
			if e != nil {
				return e
			}
			return b.Put([]byte(key), sealed)
		}); e != nil {
			t.Fatal(e)
		}
	}
	base := good
	base.Server = two
	if write(two, base); verify() != nil {
		t.Fatal("a well-formed record did not verify")
	}
	brought, used, foreign, renamed, shown := base, base, base, base, base
	brought.Current.Generated = false
	used.Current = Credential{Name: sharedName, Kind: "password", Username: "ops", Secret: "Synthetic password", Used: true}
	foreign.Current.Public = other.Public
	renamed.Current.Name = "Bob's key"
	shown.Current.ID = strings.Repeat("a", 32)
	nameless, unnumbered, stranger, twin, early, elsewhere := base, base, base, base, base, base
	nameless.SetBy = ""
	unnumbered.Generation = 0
	stranger.Next = &Credential{Name: sharedName, Kind: "ssh-key", Username: "root", Secret: other.Secret, Fingerprint: other.Fingerprint, Public: other.Public, Generated: true}
	twin.Next = &good.Current
	usedNext := other
	usedNext.Used = true
	early.Next = &usedNext
	elsewhere.Server = one
	for name, bad := range map[string]sharedCredential{
		"a key brought from elsewhere": brought, "a used password": used, "a public half not the key's own": foreign, "another name": renamed,
		"a credential ID": shown, "no setter": nameless, "no generation": unnumbered, "a waiting key for another account": stranger,
		"a waiting key equal to the current one": twin, "a waiting key already used": early, "another server's record": elsewhere,
	} {
		write(two, bad)
		if _, e := f.store.readShared(two); e == nil {
			t.Fatalf("%s was read", name)
		}
		if verify() == nil {
			t.Fatalf("a store holding %s verified", name)
		}
	}
	// A key is for SSH alone.
	if sharedSecret("rdp", good.Current) || !sharedSecret("ssh", good.Current) {
		t.Fatal("a shared key's protocol was not checked")
	}
	// A record copied under another server's name does not open, and a record
	// for no server fails the backup check.
	move := func(from, to string) {
		t.Helper()
		if e := f.store.update(func(tx *bolt.Tx) error {
			b := tx.Bucket(sharedBucket)
			raw := append([]byte(nil), b.Get([]byte(from))...)
			if e := b.Delete([]byte(two)); e != nil {
				return e
			}
			return b.Put([]byte(to), raw)
		}); e != nil {
			t.Fatal(e)
		}
	}
	move(one, two)
	if _, e := f.store.readShared(two); e == nil || verify() == nil {
		t.Fatal("a record under another server's name was read")
	}
	move(one, strings.Repeat("e", 32))
	if verify() == nil {
		t.Fatal("a shared record for no server verified")
	}
}

func TestSharedCredentialOpensOnlyForPeopleOnTheList(t *testing.T) {
	f, scans := serversFixture(t)
	id, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	bob, b := f.person("bob", roleUser)
	dave, _ := f.person("dave", roleAuditor)
	open := func(c *custodyClient, status int) string {
		t.Helper()
		w := c.expect("POST", "/api/remote/open-shared", inputJSON(map[string]string{"server": id}), status)
		if status != 200 {
			return ""
		}
		var data struct{ Lease string }
		if json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data.Lease) != 43 {
			t.Fatal("lease missing")
		}
		return data.Lease
	}
	listed := func() []sharedConnection {
		t.Helper()
		answer := bob.expect("GET", "/api/shared", "", 200).Body.String()
		if strings.Contains(answer, "PRIVATE") || strings.Contains(answer, "secret") {
			t.Fatal("the list carried a secret")
		}
		var rows []sharedConnection
		if json.Unmarshal([]byte(answer), &rows) != nil {
			t.Fatal("shared list unreadable")
		}
		return rows
	}
	redeemAs := func(c *custodyClient, raw string) (Credential, context.Context, error) {
		t.Helper()
		sid, _ := tokenID(c.cookie.Value)
		f.l.mu.Lock()
		defer f.l.mu.Unlock()
		_, _, credential, ctx, e := f.l.redeemRemoteLocked(sid, raw)
		return credential, ctx, e
	}
	redeem := func(raw string) (Credential, context.Context, error) { return redeemAs(bob, raw) }
	ended := func(ctx context.Context, what string) {
		t.Helper()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatalf("%s did not end the open session", what)
		}
		if context.Cause(ctx) != terminalweb.ReasonAccessChanged {
			t.Fatalf("%s ended the session without saying the access changed: %v", what, context.Cause(ctx))
		}
	}
	// The socket closing, as a page leaving would.
	closeAll := func() {
		f.l.mu.Lock()
		defer f.l.mu.Unlock()
		for key, lease := range f.l.remote.leases {
			if lease.owner == b.ID {
				if lease.cancel != nil {
					lease.cancel(nil)
				}
				delete(f.l.remote.leases, key)
			}
		}
	}
	grant := func(allowed bool) {
		t.Helper()
		action := "revoke"
		if allowed {
			action = "grant"
		}
		f.alice.expect("POST", "/api/servers/"+id+"/"+action, inputJSON(map[string]string{"account": b.ID}), 204)
	}

	// On the list, but nothing shared yet: nothing to open.
	grant(true)
	if len(listed()) != 0 {
		t.Fatal("a server with no shared credential was listed")
	}
	open(bob, 401)
	f.alice.expect("POST", "/api/servers/"+id+"/shared", sharedSet("ssh-key", "deploy", ""), 204)
	first, _ := f.store.readShared(id)
	if rows := listed(); len(rows) != 1 || rows[0] != (sharedConnection{Server: id, Name: "Web", Protocol: "ssh", Username: "deploy", Trust: "verified"}) {
		t.Fatalf("shared list: %+v", rows)
	}
	// An auditor holds no credential; malformed requests open nothing.
	dave.expect("GET", "/api/shared", "", 403)
	open(dave, 403)
	bob.expect("POST", "/api/remote/open-shared", `{"server":"`+id+`","connection":"`+id+`"}`, 400)
	bob.expect("POST", "/api/remote/open-shared", `{"server":"`+id+`","server":"`+id+`"}`, 400)
	bob.expect("POST", "/api/remote/open-shared", inputJSON(map[string]string{"server": "web"}), 401)
	bob.expect("POST", "/api/remote/open-shared", inputJSON(map[string]string{"server": strings.Repeat("e", 32)}), 401)

	// A listed person's lease opens with the shared key, once, and only for them.
	raw := open(bob, 200)
	if _, _, e := redeemAs(f.alice, raw); e == nil {
		t.Fatal("another account redeemed the lease")
	}
	credential, ctx, e := redeem(raw)
	if e != nil || credential.Fingerprint != first.Current.Fingerprint || credential.Username != "deploy" || !credential.Generated {
		t.Fatal("a listed person's lease did not open with the shared key")
	}
	if _, _, e := redeem(raw); e == nil {
		t.Fatal("a lease was redeemed twice")
	}
	// A new key does not end the open session, but a lease from before the
	// switch is not redeemed; one after it opens with the new key.
	pending := open(bob, 200)
	f.alice.expect("POST", "/api/servers/"+id+"/shared-next", "{}", 204)
	waiting, _ := f.store.readShared(id)
	f.alice.expect("POST", "/api/servers/"+id+"/shared-switch", sharedPrint(waiting.Next.Fingerprint), 204)
	if _, _, e := redeem(pending); e == nil {
		t.Fatal("a lease from before the switch was redeemed")
	}
	select {
	case <-ctx.Done():
		t.Fatal("a new key ended the open session")
	default:
	}
	closeAll()
	if credential, _, e = redeem(open(bob, 200)); e != nil || credential.Fingerprint != waiting.Next.Fingerprint {
		t.Fatal("a lease after the switch did not open with the new key")
	}
	closeAll()

	// Taking the person off ends their session and pending lease.
	_, ctx, e = redeem(open(bob, 200))
	if e != nil {
		t.Fatal("lease refused")
	}
	pending = open(bob, 200)
	grant(false)
	ended(ctx, "taking the person off")
	if _, _, e := redeem(pending); e == nil || len(listed()) != 0 {
		t.Fatal("a person taken off still reaches the shared credential")
	}
	open(bob, 401)

	// Removing the shared credential ends sessions on it at once.
	grant(true)
	_, ctx, e = redeem(open(bob, 200))
	if e != nil {
		t.Fatal("lease refused")
	}
	pending = open(bob, 200)
	f.alice.expect("DELETE", "/api/servers/"+id+"/shared", "{}", 204)
	ended(ctx, "removing the shared credential")
	if _, _, e := redeem(pending); e == nil || len(listed()) != 0 {
		t.Fatal("a removed shared credential was still used")
	}
	open(bob, 401)

	// Removing the server ends them too.
	f.alice.expect("POST", "/api/servers/"+id+"/shared", sharedSet("ssh-key", "deploy", ""), 204)
	_, ctx, e = redeem(open(bob, 200))
	if e != nil {
		t.Fatal("lease refused")
	}
	f.alice.expect("DELETE", "/api/servers/"+id, "{}", 204)
	ended(ctx, "removing the server")
	open(bob, 401)
}

// The page that opens a shared credential is served only to someone who could
// open it: on the list, of a server that has one, for the protocol in its path.
// It is marked so that it opens with open-shared.
func TestSharedSessionPageOpensOnlyForPeopleOnTheList(t *testing.T) {
	f, scans := serversFixture(t)
	id, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	bob, b := f.person("bob", roleUser)
	dave, _ := f.person("dave", roleAuditor)
	page := "/remote/shared/ssh/" + id
	access := func(action string) {
		t.Helper()
		f.alice.expect("POST", "/api/servers/"+id+"/"+action, inputJSON(map[string]string{"account": b.ID}), 204)
	}
	access("grant")
	bob.expect("GET", page, "", 404)
	f.alice.expect("POST", "/api/servers/"+id+"/shared", sharedSet("ssh-key", "deploy", ""), 204)
	w := bob.expect("GET", page, "", 200)
	body := w.Body.String()
	start := strings.Index(body, "<body ")
	if start < 0 || !strings.HasPrefix(body[start:], `<body data-owned-remote="ssh" data-connection="`+id+`" data-shared="1" `) || strings.Count(body, "data-shared") != 1 {
		t.Fatal("the shared page is not marked to open the server's shared credential")
	}
	if policy := w.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "; script-src 'self'; ") {
		t.Fatalf("a shared terminal page may compile WebAssembly: %s", policy)
	}
	// Another protocol, a server's ID as a connection's, other shapes, and
	// people not on the list: nothing.
	for _, path := range []string{"/remote/shared/rdp/" + id, "/remote/ssh/" + id, "/remote/shared/ssh/" + strings.Repeat("e", 32), "/remote/shared/ssh/" + strings.ToUpper(id), "/remote/shared/" + id, "/remote/shared/ssh/" + id + "/", "/remote/shared/shared/ssh/" + id} {
		if w := bob.expect("GET", path, "", 404); strings.Contains(w.Body.String(), "data-owned-remote") {
			t.Fatalf("%s served a session page", path)
		}
	}
	f.alice.expect("GET", page, "", 404)
	dave.expect("GET", page, "", 404)
	// Taken off the list, or the credential removed: gone again.
	access("revoke")
	bob.expect("GET", page, "", 404)
	access("grant")
	bob.expect("GET", page, "", 200)
	f.alice.expect("DELETE", "/api/servers/"+id+"/shared", "{}", 204)
	bob.expect("GET", page, "", 404)
}

// A shared desktop's card follows its server: ready; stopped while Windows
// shows another certificate than the pin; unavailable once the pin ends, and
// then nothing opens.
func TestSharedDesktopFollowsItsCertificate(t *testing.T) {
	f, reads, _ := desktopFixture(t)
	endpoint := "10.20.0.8:3389"
	pin := windowsLeaf(t, func(c *x509.Certificate) { c.NotAfter = f.now.Add(10 * time.Minute) })
	reads.set(endpoint, pin)
	f.alice.expect("POST", "/api/servers/scan", rdpFields("", "10.20.0.8", "3389", ""), 200)
	var made struct{ ID string }
	if json.Unmarshal(f.alice.expect("POST", "/api/servers", rdpFields("Desk", "10.20.0.8", "3389", certificatePrint(pin)), 200).Body.Bytes(), &made) != nil || !validID(made.ID) {
		t.Fatal("desktop was not added")
	}
	id := made.ID
	bob, b := f.person("bob", roleUser)
	f.alice.expect("POST", "/api/servers/"+id+"/grant", inputJSON(map[string]string{"account": b.ID}), 204)
	f.alice.expect("POST", "/api/servers/"+id+"/shared", sharedSet("password", "kbtest", "Synthetic-desk-password-7d2e"), 204)
	trust := func() string {
		t.Helper()
		var rows []sharedConnection
		if json.Unmarshal(bob.expect("GET", "/api/shared", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 || rows[0].Server != id || rows[0].Protocol != "rdp" || rows[0].Username != "kbtest" {
			t.Fatal("shared desktop not listed")
		}
		return rows[0].Trust
	}
	read := func() { t.Helper(); f.l.readCertificates(context.Background()) }
	read()
	if trust() != "verified" {
		t.Fatal("a shared desktop showing its pin is not ready")
	}
	bob.expect("GET", "/remote/shared/rdp/"+id, "", 200)
	reads.set(endpoint, windowsLeaf(t, nil))
	read()
	if trust() != "stopped" {
		t.Fatal("a shared desktop showing another certificate is not stopped")
	}
	reads.set(endpoint, pin)
	read()
	if trust() != "verified" {
		t.Fatal("a shared desktop showing its pin again is not ready")
	}
	f.now = f.now.Add(11 * time.Minute)
	if trust() != "unavailable" {
		t.Fatal("a shared desktop past its pin is not unavailable")
	}
	bob.expect("GET", "/remote/shared/rdp/"+id, "", 404)
	bob.expect("POST", "/api/remote/open-shared", inputJSON(map[string]string{"server": id}), 401)
}

// sharedSSHWorker opens an echo terminal and remembers what it was given.
type sharedSSHWorker struct {
	mu       sync.Mutex
	username string
	key      string
}

func (w *sharedSSHWorker) OpenSSH(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, username string, c sshkey.Credential) (terminalweb.Stream, error) {
	w.mu.Lock()
	w.username = username
	if key, ok := c.(*sshkey.Key); ok {
		w.key = ssh.FingerprintSHA256(key.PublicKey())
	}
	w.mu.Unlock()
	left, right := net.Pipe()
	go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
	context.AfterFunc(ctx, func() { _ = left.Close() })
	return fixtureRemoteStream{left}, nil
}

func TestSharedKeyReachesTheWorkerAndIsMarkedUsed(t *testing.T) {
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
	worker := &sharedSSHWorker{}
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
	c.expect("POST", "/api/servers/"+target.ID+"/shared", sharedSet("ssh-key", "deploy", ""), 204)
	made, e := store.readShared(target.ID)
	if e != nil {
		t.Fatal("shared key missing")
	}
	used := func() bool {
		t.Helper()
		var view serversView
		if json.Unmarshal(c.expect("GET", "/api/servers", "", 200).Body.Bytes(), &view) != nil {
			t.Fatal("servers unreadable")
		}
		row, ok := serverRow(view, target.ID)
		if !ok || row.Shared == nil {
			t.Fatal("shared key missing from the view")
		}
		return row.Shared.Used
	}
	if used() {
		t.Fatal("a new shared key was marked used")
	}
	var lease struct{ Lease string }
	if json.Unmarshal(c.expect("POST", "/api/remote/open-shared", inputJSON(map[string]string{"server": target.ID}), 200).Body.Bytes(), &lease) != nil {
		t.Fatal("lease missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	header := http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}
	socket, _, e := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/socket", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: header})
	if e != nil {
		t.Fatal("valid socket refused")
	}
	defer socket.CloseNow()
	if socket.Write(ctx, websocket.MessageText, []byte(inputJSON(map[string]string{"csrf": c.csrf, "lease": lease.Lease}))) != nil {
		t.Fatal("proof write failed")
	}
	if _, data, e := socket.Read(ctx); e != nil || string(data) != `{"type":"ready"}` {
		t.Fatal("the shared terminal did not open")
	}
	worker.mu.Lock()
	username, key := worker.username, worker.key
	worker.mu.Unlock()
	if username != "deploy" || key != made.Current.Fingerprint {
		t.Fatal("the worker did not get the shared key")
	}
	if !used() {
		t.Fatal("an opened terminal did not mark the shared key used")
	}
	after, _ := store.readShared(target.ID)
	if after.Generation != made.Generation || after.Current.Secret != made.Current.Secret {
		t.Fatal("the used mark changed the key")
	}
}
