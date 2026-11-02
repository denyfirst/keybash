package identity

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func resetCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var reply struct{ Code string }
	if json.Unmarshal(w.Body.Bytes(), &reply) != nil || len(reply.Code) != 43 {
		t.Fatal("no one-time code in the reply")
	}
	return reply.Code
}

// A forgotten password: an administrator's code and the holder's own factor
// set a new one together, once. The code alone, a wrong code, a spent or an
// expired one open nothing, so the administrator who holds the code cannot
// become the account, and a wrong code never spends the holder's factor.
func TestPasswordResetNeedsTheCodeAndTheHoldersFactor(t *testing.T) {
	f := adminFixture(t)
	if _, e := f.store.CreateAccount("carol", bobPassword); e != nil {
		t.Fatal("fixture account failed")
	}
	carol, seed, codes := enrollFixture(t, f.store, "carol", f.now)
	held := &custodyClient{t: t, l: f.l}
	held.expect("POST", "/api/session", inputJSON(map[string]string{"username": "carol", "password": bobPassword}), 204)
	held.session("challenge")
	held.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	held.session("ready")
	ready := mustLookup(t, f.store, "carol")
	path := "/api/users/" + carol.ID + "/password"
	code := resetCode(t, f.alice.expect("POST", path, "{}", 200))
	held.expect("GET", "/api/session", "", 401) // a change ends the person's sessions
	if a := mustLookup(t, f.store, "carol"); a.Seed != seed || a.password() != carol.password() || len(a.Recovery) != len(ready.Recovery) || a.LastCounter != ready.LastCounter {
		t.Fatal("issuing a reset code changed the password or the factor")
	}
	other := &custodyClient{t: t, l: f.l} // a session opened after the code, which the reset ends
	other.expect("POST", "/api/session", inputJSON(map[string]string{"username": "carol", "password": bobPassword}), 204)
	other.session("challenge")
	other.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[2]}), 204)
	other.session("ready")
	reset := func(name, code, factor, password string, status int) *custodyClient {
		c := &custodyClient{t: t, l: f.l}
		c.expect("POST", "/api/password-reset", inputJSON(map[string]string{"username": name, "code": code, "factor": factor, "password": password}), status)
		return c
	}
	spent := func() int { return mustLookup(t, f.store, "carol").FactorCount }
	before := spent()
	reset("carol", strings.Repeat("A", 43), otpCode(t, seed, f.now.Unix()/30), nextPassword, 401)
	reset("nobody", code, otpCode(t, seed, f.now.Unix()/30), nextPassword, 401)
	if spent() != before {
		t.Fatal("a wrong name or code spent the holder's factor budget")
	}
	// The administrator holds the code, not the phone.
	reset("carol", code, "not-a-factor", nextPassword, 401)
	if spent() != before+1 {
		t.Fatal("a wrong factor after the right code did not spend the budget")
	}
	reset("carol", code, otpCode(t, seed, f.now.Unix()/30), "short", 400)
	extra := &custodyClient{t: t, l: f.l}
	extra.call("POST", "/api/password-reset", `{"username":"carol","code":"`+code+`","factor":"123456","password":"`+nextPassword+`","role":"admin"}`)
	if extra.cookie != nil {
		t.Fatal("a reset with an unknown field signed in")
	}
	// The holder: the code, the current phone code and a new password, which
	// signs them in.
	signed := reset("carol", code, otpCode(t, seed, f.now.Unix()/30), nextPassword, 204)
	other.expect("GET", "/api/session", "", 401)
	signed.session("ready")
	if roleOf(t, signed) != "user" {
		t.Fatal("a reset changed the role")
	}
	f.advance(time.Minute)
	reset("carol", code, codes[1], bobPassword, 401) // spent
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "carol", "password": bobPassword}), 401)
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "carol", "password": nextPassword}), 204)
	// A recovery code proves the factor too; a reset ends the earlier session.
	code = resetCode(t, f.alice.expect("POST", path, "{}", 200))
	late := resetCode(t, f.alice.expect("POST", path, "{}", 200)) // replaces code
	reset("carol", code, codes[1], bobPassword, 401)
	reset("carol", late, codes[1], bobPassword, 204)
	if len(mustLookup(t, f.store, "carol").Recovery) != len(codes)-3 {
		t.Fatal("the recovery code was not spent")
	}
	// An expired code opens nothing.
	f.advance(time.Minute)
	code = resetCode(t, f.alice.expect("POST", path, "{}", 200))
	f.advance(enrollmentLife)
	reset("carol", code, otpCode(t, seed, f.now.Unix()/30), nextPassword, 401)
	// Five attempts a minute per name, then none.
	for range resetAttempts {
		reset("ghost", strings.Repeat("A", 43), "123456", nextPassword, 401)
	}
	reset("ghost", strings.Repeat("A", 43), "123456", nextPassword, 429)
}

// Only an administrator issues a reset code, freshly confirmed, for someone
// else who has a phone and is neither invited nor blocked.
func TestPasswordResetCodesAreForEnrolledPeople(t *testing.T) {
	f := adminFixture(t)
	user, carol := f.person("carol", roleUser)
	user.expect("POST", "/api/users/"+carol.ID+"/password", "{}", 403)
	self := mustLookup(t, f.store, "alice")
	f.alice.expect("POST", "/api/users/"+self.ID+"/password", "{}", 403)
	f.alice.expect("POST", "/api/users/"+strings.Repeat("e", 32)+"/password", "{}", 404)
	f.alice.expect("POST", "/api/users/"+carol.ID+"/password", `{"extra":"1"}`, 400)
	if _, e := f.store.CreateAccount("dave", bobPassword); e != nil {
		t.Fatal("fixture account failed")
	}
	f.alice.expect("POST", "/api/users/"+mustLookup(t, f.store, "dave").ID+"/password", "{}", 409) // no phone yet
	invited, _ := invite(t, f.alice, "erin", "user", 200)
	f.alice.expect("POST", "/api/users/"+invited+"/password", "{}", 409)
	f.alice.expect("POST", "/api/users/"+carol.ID+"/block", "{}", 204)
	f.alice.expect("POST", "/api/users/"+carol.ID+"/password", "{}", 409)
	f.alice.expect("POST", "/api/users/"+carol.ID+"/unblock", "{}", 204)
	f.advance(freshProof)
	f.alice.expect("POST", "/api/users/"+carol.ID+"/password", "{}", 428)
}

// Starting over, for someone who lost both password and phone, deletes what
// the account held in the same step, so the administrator who receives the
// new invite code never reaches it. The ID, name and role stay.
func TestStartOverDeletesWhatTheAccountHeld(t *testing.T) {
	f := adminFixture(t)
	frankSession, frank := f.person("frank", roleAuditor)
	record := Credential{Name: "Frank key", Kind: "password", Username: "frank", Secret: "Synthetic start-over secret 91"}
	if validateCredential(&record) != nil {
		t.Fatal("fixture credential refused")
	}
	credential, e := f.store.putCredential(frank.ID, record)
	if e != nil {
		t.Fatal("fixture credential failed")
	}
	if _, e = f.store.putConnection(frank.ID, connection{Name: "Frank server", Target: f.target.ID, Credential: credential, Approval: approvalFingerprint(f.target), Fingerprint: identityFingerprint(f.target)}); e != nil {
		t.Fatal("fixture connection failed")
	}
	self := mustLookup(t, f.store, "alice")
	f.alice.expect("POST", "/api/users/"+self.ID+"/restart", "{}", 403)
	f.alice.expect("POST", "/api/users/"+frank.ID+"/restart", `{"extra":"1"}`, 400)
	code := resetCode(t, f.alice.expect("POST", "/api/users/"+frank.ID+"/restart", "{}", 200))
	frankSession.expect("GET", "/api/session", "", 401)
	a := mustLookup(t, f.store, "frank")
	if a.ID != frank.ID || a.Role != roleAuditor || !a.Invited || a.Seed != "" || len(a.Recovery) != 0 || a.password() == frank.password() {
		t.Fatal("starting over did not make the account a fresh invite")
	}
	prefix := []byte(frank.ID + "/")
	if f.store.view(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{credentialBucket, connectionBucket} {
			if b := tx.Bucket(name); b != nil {
				if k, _ := b.Cursor().Seek(prefix); k != nil && bytes.HasPrefix(k, prefix) {
					return errRefused
				}
			}
		}
		return nil
	}) != nil {
		t.Fatal("a key, password or connection outlived starting over")
	}
	if _, e = f.store.Backup(io.Discard, f.now); e != nil {
		t.Fatal("the store no longer verifies after starting over")
	}
	(&custodyClient{t: t, l: f.l}).expect("POST", "/api/session", inputJSON(map[string]string{"username": "frank", "password": bobPassword}), 401)
	claimed := &custodyClient{t: t, l: f.l}
	claimed.expect("POST", "/api/invite", inputJSON(map[string]string{"username": "frank", "code": code, "password": nextPassword}), 204)
	claimed.session("enroll")
}

// A record's reset code is whole or absent, with its expiry, and never on an
// invite.
func TestAccountRecordsRefuseMalformedPasswordResets(t *testing.T) {
	store, _, _ := bootstrapped(t)
	a, _ := store.lookup("alice")
	for _, bad := range []func(*durableAccount){
		func(a *durableAccount) { a.PasswordReset, a.PasswordResetEnd = make([]byte, 31), 1 },
		func(a *durableAccount) { a.PasswordReset = make([]byte, 32) },
		func(a *durableAccount) { a.PasswordResetEnd = 1 },
		func(a *durableAccount) { a.PasswordReset, a.PasswordResetEnd = make([]byte, 32), -1 },
		func(a *durableAccount) {
			a.PasswordReset, a.PasswordResetEnd, a.Invited, a.Enrollment, a.EnrollmentEnd = make([]byte, 32), 1, true, make([]byte, 32), 1
		},
	} {
		changed := a
		bad(&changed)
		changed.Revision++
		if store.update(func(tx *bolt.Tx) error { return store.saveAccount(tx, changed) }) != nil {
			t.Fatal("fixture save failed")
		}
		if _, e := store.lookup("alice"); e == nil {
			t.Fatal("an account record with a malformed reset code was read")
		}
		if store.update(func(tx *bolt.Tx) error { a.Revision = changed.Revision + 1; return store.saveAccount(tx, a) }) != nil {
			t.Fatal("fixture restore failed")
		}
	}
}
