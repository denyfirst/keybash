package identity

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/sessionlimits"
	bolt "go.etcd.io/bbolt"
)

// adminFixture is a remote lab whose bootstrap account, alice, administers it
// with a ready, freshly proved session. Its clock moves with advance.
type adminLab struct {
	t      *testing.T
	l      *Lab
	store  *Store
	alice  *custodyClient
	now    time.Time
	target RemoteTarget
	codes  recoveryCodes // alice's unused recovery codes, from the third on
}

func adminFixture(t *testing.T) *adminLab { return adminFixtureAt(t, "https://127.0.0.1:8443") }
func adminFixtureAt(t *testing.T, origin string) *adminLab {
	t.Helper()
	store, _, _ := bootstrapped(t)
	f := &adminLab{t: t, store: store, now: time.Now(), target: remoteTargetFixture(t)}
	_, _, codes := enrollFixture(t, store, "alice", f.now)
	worker := &fixtureRDPWorker{expected: "Synthetic remote password", closed: make(chan struct{})}
	l, e := NewRemoteLabWithLimits(origin, store, []RemoteTarget{f.target}, nil, worker, sessionlimits.Default())
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	t.Cleanup(func() { _ = l.Close() })
	f.l = l
	l.mu.Lock()
	l.now = func() time.Time { return f.now }
	l.mu.Unlock()
	f.alice = &custodyClient{t: t, l: l}
	f.alice.login()
	f.alice.session("challenge")
	f.alice.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	f.alice.session("ready")
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	f.codes = codes[2:]
	return f
}
func (f *adminLab) advance(d time.Duration) { advance(f.l, &f.now, d) }
func mustLookup(t *testing.T, s *Store, name string) durableAccount {
	t.Helper()
	a, e := s.lookup(name)
	if e != nil {
		t.Fatal("fixture account absent")
	}
	return a
}

// signIn gives an existing account a new phone and signs it in again, as its
// holder would after an administrator's change ended their sessions.
func (f *adminLab) signIn(name string) (*custodyClient, recoveryCodes) {
	f.t.Helper()
	a := mustLookup(f.t, f.store, name)
	if f.store.update(func(tx *bolt.Tx) error {
		a.Seed, a.Recovery, a.Revision = "", nil, a.Revision+1
		return f.store.saveAccount(tx, a)
	}) != nil {
		f.t.Fatal("fixture factor reset failed")
	}
	_, _, codes := enrollFixture(f.t, f.store, name, f.now)
	c := &custodyClient{t: f.t, l: f.l}
	c.expect("POST", "/api/session", inputJSON(map[string]string{"username": name, "password": bobPassword}), 204)
	c.session("challenge")
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	c.session("ready")
	return c, codes[1:]
}

// person makes an enrolled account with this role and signs it in.
func (f *adminLab) person(name, role string) (*custodyClient, durableAccount) {
	f.t.Helper()
	if _, e := f.store.CreateAccount(name, bobPassword); e != nil {
		f.t.Fatal("fixture account failed")
	}
	setRole(f.t, f.store, name, role)
	a, _, codes := enrollFixture(f.t, f.store, name, f.now)
	c := &custodyClient{t: f.t, l: f.l}
	c.expect("POST", "/api/session", inputJSON(map[string]string{"username": name, "password": bobPassword}), 204)
	c.session("challenge")
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	c.session("ready")
	return c, a
}
func setRole(t *testing.T, s *Store, name, role string) {
	t.Helper()
	a, e := s.lookup(name)
	if e != nil || s.update(func(tx *bolt.Tx) error { a.Role = role; a.Revision++; return s.saveAccount(tx, a) }) != nil {
		t.Fatal("fixture role failed")
	}
}
func roleOf(t *testing.T, c *custodyClient) string {
	t.Helper()
	var data struct{ Role string }
	if json.Unmarshal(c.expect("GET", "/api/session", "", 200).Body.Bytes(), &data) != nil {
		t.Fatal("session unreadable")
	}
	return data.Role
}
func listUsers(t *testing.T, c *custodyClient) (string, map[string]accountSummary) {
	t.Helper()
	var data struct {
		Self     string
		Accounts []accountSummary
	}
	if json.Unmarshal(c.expect("GET", "/api/users", "", 200).Body.Bytes(), &data) != nil {
		t.Fatal("users unreadable")
	}
	byName := map[string]accountSummary{}
	for _, a := range data.Accounts {
		byName[a.Username] = a
	}
	return data.Self, byName
}
func invite(t *testing.T, c *custodyClient, name, role string, status int) (string, string) {
	t.Helper()
	w := c.expect("POST", "/api/users", inputJSON(map[string]string{"username": name, "role": role}), status)
	var made struct{ ID, Code string }
	if status == 200 && (json.Unmarshal(w.Body.Bytes(), &made) != nil || !validID(made.ID) || len(made.Code) != 43) {
		t.Fatal("invite reply invalid")
	}
	return made.ID, made.Code
}

// Only a ready administrator sees and changes accounts, and every change asks
// for the phone again once the fresh window has passed.
func TestUsersAreForAFreshAdministrator(t *testing.T) {
	f := adminFixture(t)
	if roleOf(t, f.alice) != "admin" {
		t.Fatal("the bootstrap account is not the administrator")
	}
	self, users := listUsers(t, f.alice)
	if a := users["alice"]; a.ID != self || a.Role != "admin" || a.State != "active" || len(users) != 1 {
		t.Fatalf("the list misdescribes alice: %+v", users)
	}
	for _, leak := range []string{"Seed", "Hash", "Recovery", "Enrollment", "password"} {
		if strings.Contains(f.alice.expect("GET", "/api/users", "", 200).Body.String(), leak) {
			t.Fatalf("the list carries %q", leak)
		}
	}
	bob, _ := f.person("bob", roleUser)
	carol, _ := f.person("carol", roleAuditor)
	for _, c := range []*custodyClient{bob, carol} {
		c.expect("GET", "/api/users", "", 403)
		c.expect("POST", "/api/users", inputJSON(map[string]string{"username": "mallory", "role": "admin"}), 403)
	}
	(&custodyClient{t: t, l: f.l}).expect("GET", "/api/users", "", 401)
	// Malformed requests change nothing.
	invite(t, f.alice, "Mallory", "user", 400)
	invite(t, f.alice, "mallory", "root", 400)
	invite(t, f.alice, "mallory", "", 400)
	invite(t, f.alice, "bob", "user", 409)
	f.alice.expect("POST", "/api/users/"+strings.Repeat("0", 32)+"/role", inputJSON(map[string]string{"role": "admin"}), 404)
	f.alice.expect("POST", "/api/users/xyz/role", inputJSON(map[string]string{"role": "admin"}), 404)
	f.alice.expect("PUT", "/api/users", "{}", 404)
	// Past the fresh window, a change needs the phone again; the list does not.
	f.advance(freshProof)
	listUsers(t, f.alice)
	invite(t, f.alice, "dave", "user", 428)
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": f.codes[0]}), 204)
	invite(t, f.alice, "dave", "user", 200)
	if _, users = listUsers(t, f.alice); users["dave"].State != "invited" || users["dave"].Role != "user" || users["mallory"].ID != "" {
		t.Fatalf("the list after one invite: %+v", users)
	}
}

// An invite lets its holder choose the password, once, and continue at phone
// setup without another code. A wrong name, a wrong code and an expired code
// look the same, and attempts are limited.
func TestInviteLetsItsHolderChooseThePasswordOnce(t *testing.T) {
	f := adminFixture(t)
	_, code := invite(t, f.alice, "dave", "auditor", 200)
	claim := func(name, code, password string, status int) *custodyClient {
		c := &custodyClient{t: t, l: f.l}
		c.expect("POST", "/api/invite", inputJSON(map[string]string{"username": name, "code": code, "password": password}), status)
		return c
	}
	// No password opens an invited account, not even its own random one.
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "dave", "password": bobPassword}), 401)
	known, e := HashPassword(bobPassword)
	if e != nil {
		t.Fatal("fixture hash failed")
	}
	if _, _, e = f.store.inviteAccount(mustLookup(t, f.store, "alice").ID, "ghost", roleUser, known, f.now); e != nil {
		t.Fatal("fixture invite failed")
	}
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "ghost", "password": bobPassword}), 401)
	claim("dave", strings.Repeat("A", 43), bobPassword, 401)
	claim("nobody", code, bobPassword, 401)
	claim("alice", code, bobPassword, 401) // an enrolled account is no invite
	claim("dave", code, "short", 400)
	dave := &custodyClient{t: t, l: f.l}
	dave.call("POST", "/api/invite", `{"username":"dave","code":"`+code+`","password":"`+bobPassword+`","extra":"1"}`)
	if dave.cookie != nil {
		t.Fatal("a claim with an unknown field signed in")
	}
	dave = claim("dave", code, bobPassword, 204)
	// Until the phone is set up the code is still the setup code, but it no
	// longer replaces the chosen password.
	claim("dave", code, nextPassword, 401)
	dave.session("enroll")
	var state struct{ Setup bool }
	if json.Unmarshal(dave.expect("GET", "/api/session", "", 200).Body.Bytes(), &state) != nil || state.Setup {
		t.Fatal("the claim session still asks for the setup code")
	}
	w := dave.expect("POST", "/api/mfa/enrollment", "{}", 200)
	var seed struct{ Secret string }
	if json.Unmarshal(w.Body.Bytes(), &seed) != nil || !validSeed(seed.Secret) {
		t.Fatal("no seed after the claim")
	}
	dave.expect("POST", "/api/mfa/confirm", inputJSON(map[string]string{"code": otpCode(t, seed.Secret, f.now.Unix()/30)}), 200)
	dave.session("ready")
	if roleOf(t, dave) != "auditor" {
		t.Fatal("the invite's role was not kept")
	}
	// The code is spent: it neither claims again nor replaces the password.
	claim("dave", code, nextPassword, 401)
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "dave", "password": bobPassword}), 204)
	// An unclaimed invite expires with its code.
	_, late := invite(t, f.alice, "erin", "user", 200)
	hash, e := HashPassword(bobPassword)
	if e != nil || f.store.claimInvite("erin", late, hash, f.now.Add(enrollmentLife)) == nil {
		t.Fatal("an expired invite was claimed")
	}
	if _, users := listUsers(t, f.alice); users["erin"].State != "invited" {
		t.Fatal("a live invite is not listed as invited")
	}
	if summarize(mustLookup(t, f.store, "erin"), f.now.Add(enrollmentLife)).State != "expired" {
		t.Fatal("an expired invite is not listed as expired")
	}
	// Five tries per name a minute, then a wait, even with the right code.
	f2 := adminFixture(t)
	_, code = invite(t, f2.alice, "frank", "user", 200)
	for range inviteAttempts {
		(&custodyClient{t: t, l: f2.l}).expect("POST", "/api/invite", inputJSON(map[string]string{"username": "frank", "code": strings.Repeat("B", 43), "password": bobPassword}), 401)
	}
	(&custodyClient{t: t, l: f2.l}).expect("POST", "/api/invite", inputJSON(map[string]string{"username": "frank", "code": code, "password": bobPassword}), 429)
	f2.advance(time.Minute)
	(&custodyClient{t: t, l: f2.l}).expect("POST", "/api/invite", inputJSON(map[string]string{"username": "frank", "code": code, "password": bobPassword}), 204)
}

// A role change, a block, a reset and a delete each end the account's
// sessions at once; an administrator cannot change their own account here,
// so an administrator always remains.
func TestAdministratorChangesTakeEffectAtOnce(t *testing.T) {
	f := adminFixture(t)
	bob, b := f.person("bob", roleUser)
	path := "/api/users/" + b.ID
	f.alice.expect("POST", path+"/role", inputJSON(map[string]string{"role": "auditor"}), 204)
	bob.expect("GET", "/api/session", "", 401)
	bob, _ = f.signIn("bob")
	if roleOf(t, bob) != "auditor" {
		t.Fatal("the new role did not apply")
	}
	f.alice.expect("POST", path+"/block", "{}", 204)
	bob.expect("GET", "/api/session", "", 401)
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": bobPassword}), 401)
	if _, users := listUsers(t, f.alice); users["bob"].State != "blocked" {
		t.Fatal("a blocked account is not listed as blocked")
	}
	f.alice.expect("POST", path+"/unblock", "{}", 204)
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": bobPassword}), 204)
	// A reset sends the account back to an invite: the old password stops
	// working, and the new code lets its holder choose another.
	w := f.alice.expect("POST", path+"/reset", "{}", 200)
	var reset struct{ Code string }
	if json.Unmarshal(w.Body.Bytes(), &reset) != nil || len(reset.Code) != 43 {
		t.Fatal("reset gave no code")
	}
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": bobPassword}), 401)
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/invite", inputJSON(map[string]string{"username": "bob", "code": reset.Code, "password": nextPassword}), 204)
	// Deleting takes the account's keys, passwords and connections with it.
	if _, e := f.store.putCredential(b.ID, Credential{Name: "Bob's", Kind: "password", Username: "u", Secret: "s"}); e != nil {
		t.Fatal("fixture credential failed")
	}
	f.alice.expect("DELETE", path, "{}", 204)
	if f.store.view(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{credentialBucket, connectionBucket} {
			if bucket := tx.Bucket(name); bucket != nil {
				if k, _ := bucket.Cursor().Seek([]byte(b.ID + "/")); k != nil && strings.HasPrefix(string(k), b.ID+"/") {
					return errRefused
				}
			}
		}
		return nil
	}) != nil {
		t.Fatal("a deleted account's credentials or connections remain")
	}
	if _, e := f.store.Backup(io.Discard, f.now); e != nil {
		t.Fatal("the store does not verify after a delete")
	}
	if _, e := f.store.lookup("bob"); e == nil {
		t.Fatal("a deleted account remains")
	}
	f.alice.expect("DELETE", path, "{}", 404)
	// Not on oneself, by any route.
	self, _ := listUsers(t, f.alice)
	for _, change := range [][3]string{{"POST", "/role", `{"role":"user"}`}, {"POST", "/block", "{}"}, {"POST", "/reset", "{}"}, {"DELETE", "", "{}"}} {
		f.alice.expect(change[0], "/api/users/"+self+change[1], change[2], 403)
	}
	if roleOf(t, f.alice) != "admin" {
		t.Fatal("alice changed herself")
	}
	// A second administrator can change the first, and is then the one left.
	_, c := f.person("carol", roleAdmin)
	if e := f.store.changeAccount(c.ID, self, func(a *durableAccount) error { a.Role = roleUser; return nil }); e != nil {
		t.Fatal("one administrator could not demote another")
	}
	if e := f.store.changeAccount(self, c.ID, func(a *durableAccount) error { a.Role = roleUser; return nil }); e == nil {
		t.Fatal("a demoted administrator still changed accounts")
	}
	if _, _, e := f.store.inviteAccount(self, "late", roleAdmin, mustLookup(t, f.store, "alice").password(), f.now); e == nil {
		t.Fatal("a demoted administrator still invited someone")
	}
	if _, _, e := f.store.inviteAccount(c.ID, "late", roleUser, mustLookup(t, f.store, "alice").password(), f.now); e != nil {
		t.Fatal("an administrator could not invite")
	}
}

// An auditor reaches no server and holds no key or password, whatever the
// route; an installation's details are for administrators.
func TestAuditorReachesNoServer(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	f := adminFixtureAt(t, origin)
	server.Config.Handler = f.l
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	socket := func(c *custodyClient) int {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, response, err := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/socket", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}})
		if conn != nil {
			conn.CloseNow()
		}
		if response == nil {
			t.Fatal("no socket response")
		}
		if response.Body != nil {
			_ = response.Body.Close()
		}
		if err == nil {
			return 101
		}
		return response.StatusCode
	}
	bob, b := f.person("bob", roleUser)
	if socket(bob) != 101 {
		t.Fatal("a user's terminal socket was refused")
	}
	credential, e := f.store.putCredential(b.ID, Credential{Name: "Synthetic remote", Kind: "password", Username: "synthetic-user", Secret: "Synthetic remote password"})
	if e != nil {
		t.Fatal("fixture credential failed")
	}
	w := bob.expect("POST", "/api/connections", inputJSON(map[string]string{"name": "Bob's desktop", "target": f.target.ID, "credential": credential, "approval": approvalFingerprint(f.target)}), 200)
	var record struct{ ID string }
	if json.Unmarshal(w.Body.Bytes(), &record) != nil || !validID(record.ID) {
		t.Fatal("connection creation failed")
	}
	bob.expect("GET", "/remote/rdp/"+record.ID, "", 200)
	bob.expect("GET", "/api/installation", "", 403)
	grantFixture(t, bob, record.ID)
	// The same person as an auditor: every server route refuses.
	setRole(t, f.store, "bob", roleAuditor)
	bob.expect("GET", "/api/session", "", 401)
	bob, codes := f.signIn("bob")
	for _, route := range [][3]string{
		{"GET", "/api/credentials", ""},
		{"POST", "/api/credentials", `{"name":"x","kind":"password","username":"u","secret":"s","passphrase":""}`},
		{"POST", "/api/credentials/generate", `{"name":"x","username":"u"}`},
		{"POST", "/api/credentials/" + credential + "/reveal", "{}"},
		{"DELETE", "/api/credentials/" + credential, "{}"},
		{"GET", "/api/targets", ""},
		{"GET", "/api/targets/" + f.target.ID, ""},
		{"GET", "/api/connections", ""},
		{"POST", "/api/remote/open", inputJSON(map[string]string{"connection": record.ID})},
		{"GET", "/api/remote/capacity", ""},
		{"GET", "/api/installation", ""},
		{"GET", "/api/users", ""},
	} {
		bob.expect(route[0], route[1], route[2], 403)
	}
	bob.expect("GET", "/remote/rdp/"+record.ID, "", 404)
	if socket(bob) != 403 {
		t.Fatal("an auditor opened a terminal socket")
	}
	f.l.mu.Lock()
	id, _ := tokenID(bob.cookie.Value)
	_, e = f.l.grantRemoteLocked(id, record.ID)
	f.l.mu.Unlock()
	if e == nil {
		t.Fatal("an auditor's session was granted a server")
	}
	// Their own account stays theirs to look after.
	bob.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[0]}), 204)
	bob.expect("POST", "/api/mfa/recovery", "{}", 200)
}

// A copy from before roles names its one account administrator when it
// starts; with several accounts it names none, and the operator's offline
// recovery does.
func TestCopiesFromBeforeRolesGetAnAdministrator(t *testing.T) {
	store, _, _ := bootstrapped(t)
	if mustLookup(t, store, "alice").Role != roleAdmin {
		t.Fatal("the bootstrap account is not an administrator")
	}
	setRole(t, store, "alice", roleUser)
	l, e := NewPersistent("https://127.0.0.1:8443", store)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	_ = l.Close()
	if a, _ := store.lookup("alice"); a.Role != roleAdmin {
		t.Fatal("the sole account was not named administrator")
	}
	setRole(t, store, "alice", roleUser)
	if _, e = store.CreateAccount("bob", bobPassword); e != nil {
		t.Fatal("second account failed")
	}
	if l, e = NewPersistent("https://127.0.0.1:8443", store); e != nil {
		t.Fatal("persistent lab refused")
	}
	_ = l.Close()
	for _, name := range []string{"alice", "bob"} {
		if a, _ := store.lookup(name); a.Role != roleUser {
			t.Fatalf("%s was named administrator among several accounts", name)
		}
	}
	if _, e = store.RecoverAccount("bob", nextPassword, false, true); e != nil {
		t.Fatal("offline recovery refused")
	}
	if a, _ := store.lookup("bob"); a.Role != roleAdmin || a.Disabled {
		t.Fatal("offline recovery did not name an administrator")
	}
}

// Account records hold only known roles, and an invited account has no factor
// and keeps its code.
func TestAccountRecordsRefuseUnknownRoles(t *testing.T) {
	store, _, _ := bootstrapped(t)
	a, _ := store.lookup("alice")
	for _, bad := range []func(*durableAccount){
		func(a *durableAccount) { a.Role = "root" },
		func(a *durableAccount) { a.Role = "Admin" },
		func(a *durableAccount) { a.Invited = true }, // no code
	} {
		changed := a
		bad(&changed)
		changed.Revision++
		if store.update(func(tx *bolt.Tx) error { return store.saveAccount(tx, changed) }) != nil {
			t.Fatal("fixture save failed")
		}
		if _, e := store.lookup("alice"); e == nil {
			t.Fatal("an account record with a bad role or invite was read")
		}
		if store.update(func(tx *bolt.Tx) error { a.Revision = changed.Revision + 1; return store.saveAccount(tx, a) }) != nil {
			t.Fatal("fixture restore failed")
		}
	}
	for _, word := range []string{"user", "admin", "auditor"} {
		if role, ok := wordRole(word); !ok || roleWord(role) != word {
			t.Fatalf("role word %q does not round-trip", word)
		}
	}
	for _, word := range []string{"", "root", "Admin", "users"} {
		if _, ok := wordRole(word); ok {
			t.Fatalf("role word %q accepted", word)
		}
	}
}
