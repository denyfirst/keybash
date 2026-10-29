package identity

import (
	"strings"
	"testing"
	"time"
)

// wrongCode is a six-digit code that none of the three accepted counters
// produce at now.
func wrongCode(t *testing.T, seed string, now time.Time) string {
	t.Helper()
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		valid := false
		for d := int64(-1); d <= 1; d++ {
			valid = valid || otpCode(t, seed, now.Unix()/30+d) == candidate
		}
		if !valid {
			return candidate
		}
	}
	t.Fatal("no wrong code")
	return ""
}

func TestStepUpTakesTheCodeAloneAndEndsTheSessionAfterFailures(t *testing.T) {
	s, _, _, code := custodyFixture(t)
	now := time.Now()
	hash, e := HashPassword(alicePassword)
	if e != nil || s.bootstrap(code, "alice", hash, now) != nil {
		t.Fatal("fixture account failed")
	}
	_, seed, recovery := enrollFixture(t, s, "alice", now)
	l, e := NewPersistent("https://127.0.0.1:8443", s)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	defer l.Close()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	signIn := func(c *custodyClient, factor string) {
		t.Helper()
		c.login()
		c.session("challenge")
		c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": factor}), 204)
		c.session("ready")
	}
	c, other := &custodyClient{t: t, l: l}, &custodyClient{t: t, l: l}
	signIn(c, recovery[0])
	signIn(other, recovery[1])
	step := func(c *custodyClient, code string, status int) {
		t.Helper()
		c.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": code}), status)
	}
	// Sign-in is fresh proof for freshProof; after that a fresh-only action
	// answers 428 before it looks at the record, and the page asks for a code.
	missing := "/api/credentials/" + strings.Repeat("a", 32) + "/reveal"
	advance(l, &now, 10*time.Minute-time.Second) // ten minutes, as the page tells people
	c.expect("POST", missing, "{}", 404)
	advance(l, &now, time.Second)
	c.expect("POST", missing, "{}", 428)
	// Account security asks too, and a stale request changes nothing.
	c.expect("POST", "/api/mfa/recovery", "{}", 428)
	c.expect("POST", "/api/mfa/reset", "{}", 428)
	c.expect("POST", "/api/password", inputJSON(map[string]string{"password": alicePassword, "next": nextPassword}), 428)
	c.session("ready")

	// The code alone: a password field, a missing code or a malformed body
	// is refused as input and spends no failure.
	for _, body := range []string{`{"password":"` + alicePassword + `"}`, inputJSON(map[string]string{"password": alicePassword, "code": "123456"}), `{"code":1}`, `not json`, `{"code":"1","code":"2"}`} {
		c.expect("POST", "/api/reauth", body, 400)
	}
	step(other, recovery[4], 204) // a right code is activity: other stays inside idleLife
	// Four wrong codes leave the session; a right one renews the window
	// and resets the count.
	advance(l, &now, 61*time.Second) // a new minute for the per-account limit
	c.expect("POST", missing, "{}", 428)
	for range 4 {
		step(c, wrongCode(t, seed, now), 401)
	}
	c.expect("GET", "/api/session", "", 200)
	c.expect("POST", missing, "{}", 428) // a wrong code renews nothing
	step(c, otpCode(t, seed, now.Unix()/30), 204)
	c.expect("POST", missing, "{}", 404)
	// The renewed window is ten minutes from the code, not from sign-in.
	advance(l, &now, 10*time.Minute-time.Second)
	c.expect("POST", missing, "{}", 404)
	step(other, otpCode(t, seed, now.Unix()/30), 204)

	// Five wrong codes in a row end this session, and only this one; the
	// count started again at the right code above.
	advance(l, &now, 61*time.Second)
	for range stepUpFailures - 1 {
		step(c, wrongCode(t, seed, now), 401)
	}
	c.expect("GET", "/api/session", "", 200)
	step(c, wrongCode(t, seed, now), 401)
	c.expect("GET", "/api/session", "", 401)
	other.expect("GET", "/api/session", "", 200)

	// A spent code is not accepted again, whether a TOTP counter or a
	// recovery code; the one used at sign-in is spent too.
	advance(l, &now, 61*time.Second)
	used := otpCode(t, seed, now.Unix()/30)
	step(other, used, 204)
	step(other, used, 401)
	step(other, recovery[2], 204)
	step(other, recovery[2], 401)
	advance(l, &now, 61*time.Second)
	step(other, recovery[1], 401)
	other.expect("GET", "/api/session", "", 200)

	// The per-account limit answers 429 without trying the code, so it does
	// not count toward ending a session.
	third := &custodyClient{t: t, l: l}
	advance(l, &now, 61*time.Second)
	signIn(third, recovery[3])
	advance(l, &now, 61*time.Second)
	for range stepUpFailures - 1 {
		step(third, wrongCode(t, seed, now), 401)
	}
	step(other, wrongCode(t, seed, now), 401) // the account's fifth attempt this minute
	step(third, wrongCode(t, seed, now), 429)
	third.expect("GET", "/api/session", "", 200)
	advance(l, &now, 61*time.Second)
	step(third, otpCode(t, seed, now.Unix()/30), 204)
}
