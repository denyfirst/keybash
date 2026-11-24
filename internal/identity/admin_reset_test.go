package identity

import (
	"encoding/json"
	"testing"
	"time"
)

// An administrator's "reset access" must not let that administrator become
// the person and connect as them. Reset itself must still work; the attack
// may stop at any later step, but it must never end in the person's session.
func TestAdministratorResetCannotBecomeThePerson(t *testing.T) {
	f := adminFixture(t)
	_, bobAccount := f.person("bob", "")
	account := accountFixture(t, f.l, f.target.ID, "bob", "Synthetic password only bob may use", bobAccount.ID)
	// The administrator resets bob and receives a code.
	w := f.alice.expect("POST", "/api/users/"+bobAccount.ID+"/reset", "{}", 200)
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
	if w = mallory.call("POST", "/api/remote/open", inputJSON(map[string]string{"account": account})); w.Code == 200 {
		t.Fatal("an administrator connected as another person through reset and invite")
	}
}
