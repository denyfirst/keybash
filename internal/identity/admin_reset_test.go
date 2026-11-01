package identity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// An administrator's "reset access" must not let that administrator become
// the account and read what it keeps. Reset itself must still work; the
// attack may stop at any later step, but it must never end with the secret.
func TestAdministratorResetCannotReadTheAccountsSecrets(t *testing.T) {
	f := adminFixture(t)
	bob, bobAccount := f.person("bob", "")
	const secret = "Synthetic secret only bob should ever see"
	w := bob.expect("POST", "/api/credentials", inputJSON(map[string]string{
		"name": "Bob's server", "kind": "password", "username": "root", "secret": secret, "passphrase": ""}), 200)
	var made struct{ ID string }
	if json.Unmarshal(w.Body.Bytes(), &made) != nil || !validID(made.ID) {
		t.Fatal("fixture credential not stored")
	}
	// The administrator resets bob and receives a code.
	w = f.alice.expect("POST", "/api/users/"+bobAccount.ID+"/reset", "{}", 200)
	var reset struct{ Code string }
	if json.Unmarshal(w.Body.Bytes(), &reset) != nil || len(reset.Code) != 43 {
		t.Fatal("reset gave no code")
	}
	// In another browser the administrator tries to become bob with that code
	// and a password of their own, then to enroll their own phone.
	mallory := &custodyClient{t: t, l: f.l}
	if mallory.call("POST", "/api/invite", inputJSON(map[string]string{"username": "bob", "code": reset.Code, "password": nextPassword})).Code != 204 {
		return // the code alone does not open bob's account
	}
	var state struct{ CSRF, Stage string }
	if json.Unmarshal(mallory.call("GET", "/api/session", "").Body.Bytes(), &state) != nil || state.Stage != "enroll" {
		return
	}
	mallory.csrf = state.CSRF
	w = mallory.call("POST", "/api/mfa/enrollment", "{}")
	var seed struct{ Secret string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &seed) != nil {
		return
	}
	if mallory.call("POST", "/api/mfa/confirm", inputJSON(map[string]string{"code": otpCode(t, seed.Secret, f.now.Unix()/30)})).Code != 200 {
		return
	}
	if json.Unmarshal(mallory.call("GET", "/api/session", "").Body.Bytes(), &state) != nil || state.Stage != "ready" {
		return
	}
	mallory.csrf = state.CSRF
	f.advance(30 * time.Second)
	mallory.call("POST", "/api/reauth", inputJSON(map[string]string{"code": otpCode(t, seed.Secret, f.now.Unix()/30)}))
	if w = mallory.call("POST", "/api/credentials/"+made.ID+"/reveal", "{}"); strings.Contains(w.Body.String(), secret) {
		t.Fatalf("an administrator read another account's secret through reset and invite (status %d)", w.Code)
	}
}
