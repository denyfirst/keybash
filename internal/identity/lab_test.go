package identity

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const alicePassword = "Synthetic-Alice şifrəsi 1!"
const bobPassword = "Synthetic-Bob password 2!"
const nextPassword = "Changed-Alice şifrəsi 3!"

var fixtureHashes struct {
	sync.Once
	alice, bob PasswordHash
	err        error
}

func accounts(t *testing.T) []Account {
	t.Helper()
	fixtureHashes.Do(func() {
		fixtureHashes.alice, fixtureHashes.err = HashPassword(alicePassword)
		if fixtureHashes.err == nil {
			fixtureHashes.bob, fixtureHashes.err = HashPassword(bobPassword)
		}
	})
	if fixtureHashes.err != nil {
		t.Fatal("synthetic account hashing failed")
	}
	return []Account{{"alice", fixtureHashes.alice}, {"bob", fixtureHashes.bob}}
}
func fixture(t *testing.T) *Lab {
	t.Helper()
	l, err := NewLab("https://127.0.0.1:9443", accounts(t))
	if err != nil {
		t.Fatal("valid identity configuration refused")
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}
func request(l *Lab, method, path, body, raw string) *http.Request {
	r := httptest.NewRequest(method, l.origin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:54000"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", l.origin)
	r.Header.Set("X-Keybash-Request", "1")
	if raw != "" {
		r.AddCookie(sessionCookie(raw, 1))
		id, _ := tokenID(raw)
		r.Header.Set("X-Keybash-CSRF", l.csrf(id))
	}
	return r
}
func respond(l *Lab, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	l.ServeHTTP(w, r)
	return w
}
func jsonBody(fields map[string]string) string {
	data, _ := json.Marshal(fields)
	return string(data)
}
func signIn(t *testing.T, l *Lab, username, password, previous string) string {
	t.Helper()
	w := respond(l, request(l, "POST", "/api/session", jsonBody(map[string]string{"username": username, "password": password}), previous))
	if w.Code != 204 || len(w.Result().Cookies()) != 1 {
		t.Fatal("valid password login refused")
	}
	c := w.Result().Cookies()[0]
	if c.Name != cookieName || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatal("session cookie boundary weakened")
	}
	return c.Value
}
func sessionContext(t *testing.T, l *Lab, raw string) context.Context {
	t.Helper()
	id, _ := tokenID(raw)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sessions[id] == nil {
		t.Fatal("fixture session absent")
	}
	return l.sessions[id].ctx
}
func requireCanceled(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("revoked session context stayed live")
	}
}

func TestPasswordSaltUnicodeAndWrongPassword(t *testing.T) {
	a := accounts(t)[0].Password
	b, err := HashPassword(alicePassword)
	if err != nil || a.salt == b.salt || a.sum == b.sum || !b.verify(alicePassword) {
		t.Fatal("salted Unicode password hashing failed")
	}
	for _, value := range []string{bobPassword, " " + alicePassword, alicePassword + " ", "", string([]byte{0xff})} {
		if a.verify(value) {
			t.Fatal("wrong or repaired password accepted")
		}
	}
	for _, value := range []string{"fourteen chars", strings.Repeat("ş", 14), strings.Repeat("a", 1025), string([]byte{0xff})} {
		if _, err := HashPassword(value); err == nil {
			t.Fatal("invalid new password accepted")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", a), fmt.Sprintf("%x", a.sum)) {
		t.Fatal("password hash leaked through formatting")
	}
}

func TestIdentityLoginRejectsUntrustedTransportBeforeHash(t *testing.T) {
	l := fixture(t)
	l.derive <- struct{}{}
	l.derive <- struct{}{}
	defer func() { <-l.derive; <-l.derive }()
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.TLS = nil },
		func(r *http.Request) { r.Header.Del("Origin") },
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") },
		func(r *http.Request) { r.Header.Del("X-Keybash-Request") },
	} {
		r := request(l, "POST", "/api/session", jsonBody(map[string]string{"username": "alice", "password": alicePassword}), "")
		mutate(r)
		if respond(l, r).Code != 403 {
			t.Fatal("untrusted login reached derivation")
		}
	}
}

func TestIdentityLoginGateRotationLogoutAndAccountIsolation(t *testing.T) {
	l := fixture(t)
	if w := respond(l, request(l, "GET", "/", "", "")); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatal("anonymous protected page opened")
	}
	if w := respond(l, request(l, "GET", "/api/session", "", "")); w.Code != 401 {
		t.Fatal("anonymous account metadata opened")
	}
	a := signIn(t, l, "alice", alicePassword, "")
	old := sessionContext(t, l, a)
	b := signIn(t, l, "bob", bobPassword, "")
	bob := sessionContext(t, l, b)
	a2 := signIn(t, l, "alice", alicePassword, a)
	if a == a2 {
		t.Fatal("session token was reused")
	}
	requireCanceled(t, old)
	for raw, username := range map[string]string{a2: "alice", b: "bob"} {
		w := respond(l, request(l, "GET", "/api/session", "", raw))
		var data struct{ Username, CSRF string }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || data.Username != username || len(data.CSRF) != 43 {
			t.Fatal("session owner changed or disappeared")
		}
	}
	aCtx := sessionContext(t, l, a2)
	w := respond(l, request(l, "DELETE", "/api/session", "", a2))
	if w.Code != 204 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("valid logout refused")
	}
	requireCanceled(t, aCtx)
	if bob.Err() != nil || respond(l, request(l, "GET", "/api/session", "", b)).Code != 200 {
		t.Fatal("logout revoked another account")
	}
	if respond(l, request(l, "GET", "/api/session", "", a2)).Code != 401 {
		t.Fatal("revoked cookie was reusable")
	}
}

func TestIdentityPasswordChangeRevokesOnlyItsOwner(t *testing.T) {
	l := fixture(t)
	a1 := signIn(t, l, "alice", alicePassword, "")
	a2 := signIn(t, l, "alice", alicePassword, "")
	b := signIn(t, l, "bob", bobPassword, "")
	c1, c2, cb := sessionContext(t, l, a1), sessionContext(t, l, a2), sessionContext(t, l, b)
	w := respond(l, request(l, "POST", "/api/password", jsonBody(map[string]string{"password": alicePassword, "next": nextPassword}), a1))
	if w.Code != 204 {
		t.Fatal("valid password change refused")
	}
	requireCanceled(t, c1)
	requireCanceled(t, c2)
	if cb.Err() != nil {
		t.Fatal("password change revoked another account")
	}
	w = respond(l, request(l, "POST", "/api/session", jsonBody(map[string]string{"username": "alice", "password": alicePassword}), ""))
	if w.Code != 401 {
		t.Fatal("old password remained usable")
	}
	_ = signIn(t, l, "alice", nextPassword, "")
}

func TestIdentityRefusesWrongUnknownAndCrossAccountPassword(t *testing.T) {
	l := fixture(t)
	for _, fields := range []map[string]string{{"username": "alice", "password": bobPassword}, {"username": "unknown", "password": alicePassword}} {
		w := respond(l, request(l, "POST", "/api/session", jsonBody(fields), ""))
		if w.Code != 401 || w.Body.String() != "request refused\n" || len(w.Result().Cookies()) != 0 {
			t.Fatal("wrong or unknown account password accepted/disclosed")
		}
	}
	a := signIn(t, l, "alice", alicePassword, "")
	w := respond(l, request(l, "POST", "/api/password", jsonBody(map[string]string{"password": bobPassword, "next": nextPassword}), a))
	if w.Code != 401 || sessionContext(t, l, a).Err() != nil {
		t.Fatal("another account password changed owner credentials")
	}
}

func TestIdentityTLSOriginCSRFAndCookieBoundary(t *testing.T) {
	l := fixture(t)
	a := signIn(t, l, "alice", alicePassword, "")
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.TLS = nil },
		func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 },
		func(r *http.Request) { r.Host = "foreign.invalid" },
		func(r *http.Request) { r.RemoteAddr = "192.0.2.5:9000" },
		func(r *http.Request) { r.Header.Del("Origin") },
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") },
		func(r *http.Request) { r.Header.Del("X-Keybash-Request") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		func(r *http.Request) { r.Header.Del("X-Keybash-CSRF") },
		func(r *http.Request) { r.Header.Set("X-Keybash-CSRF", strings.Repeat("a", 43)) },
		func(r *http.Request) { r.URL.RawQuery = "token=not-accepted" },
	} {
		r := request(l, "DELETE", "/api/session", "", a)
		mutate(r)
		if respond(l, r).Code != 403 {
			t.Fatal("unsafe origin/transport/CSRF accepted")
		}
	}
	for _, raw := range []string{strings.Repeat("x", 43), strings.Repeat("x", 4096), a + "="} {
		if respond(l, request(l, "GET", "/api/session", "", raw)).Code != 401 {
			t.Fatal("forged cookie accepted")
		}
	}
	r := request(l, "GET", "/api/session", "", a)
	r.AddCookie(sessionCookie(a, 1))
	if respond(l, r).Code != 401 {
		t.Fatal("duplicate session cookies accepted")
	}
	w := respond(l, request(l, "GET", "/login", "", ""))
	if w.Code != 200 || strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("login asset security policy weakened")
	}
}

func TestIdentityStrictJSONAndBodyBounds(t *testing.T) {
	l := fixture(t)
	for _, body := range []string{`null`, `[]`, `{}`, `{"username":"alice","password":null}`, `{"username":"alice","Password":"x"}`,
		`{"username":"alice","password":"one","password":"two"}`, `{"username":"alice","password":"one","target":"host"}`,
		`{"username":"alice","password":"one"}{}`, `{"username":"alice","password":"\ud800xxxxxxxxxxxxxxx"}`, `{"username":"alice","password":"\udc00xxxxxxxxxxxxxxx"}`,
		`{"username":"alice","password":"` + strings.Repeat("a", 1025) + `"}`, strings.Repeat(" ", 16*1024+1), string([]byte{0xff})} {
		if respond(l, request(l, "POST", "/api/session", body, "")).Code != 400 {
			t.Fatal("malformed login payload accepted")
		}
	}
	for _, body := range []string{`{"username":"alice","password":"\ud83d\ude00"}`, `{"username":"alice","password":"literal\\ud800"}`} {
		if _, ok := parseInput([]byte(body), "username", "password"); !ok {
			t.Fatal("valid Unicode/escaped password refused")
		}
	}
	r := request(l, "POST", "/api/session", `{"username":"alice","password":"x"}`, "")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if respond(l, r).Code != 400 {
		t.Fatal("native form payload accepted")
	}
}

func TestIdentityRateKDFAndSessionQuotas(t *testing.T) {
	l := fixture(t)
	for i := range 6 {
		_, err := l.login(context.Background(), "alice", bobPassword, "")
		if i < 5 && err != errRefused || i == 5 && err != errLimited {
			t.Fatal("account attempt budget not enforced")
		}
	}
	l2 := fixture(t)
	l2.derive <- struct{}{}
	l2.derive <- struct{}{}
	if _, err := l2.login(context.Background(), "bob", bobPassword, ""); err != errLimited {
		t.Fatal("excess parallel KDF accepted")
	}
	<-l2.derive
	<-l2.derive
	l2.mu.Lock()
	for i := range 128 {
		id := sha256.Sum256([]byte(fmt.Sprint(i)))
		ctx, cancel := context.WithCancel(context.Background())
		l2.sessions[id] = &session{username: "alice", created: l2.now(), last: l2.now(), ctx: ctx, cancel: cancel}
	}
	l2.mu.Unlock()
	if _, err := l2.login(context.Background(), "bob", bobPassword, ""); err != errLimited {
		t.Fatal("aggregate session quota escaped")
	}
}

func TestIdentityAttemptBucketsAreUniformAndBounded(t *testing.T) {
	l := fixture(t)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = func() time.Time { return now }
	for i := range 6 {
		known, unknown := l.attemptLocked("alice"), l.attemptLocked("not-registered")
		if known != unknown || known != (i < 5) {
			t.Fatal("known/unknown attempt limits differ or are bypassed")
		}
	}
	now = now.Add(time.Minute)
	for i := range 21 {
		if l.attemptLocked(fmt.Sprint("untrusted-", i)) != (i < 20) {
			t.Fatal("global attempt budget escaped")
		}
	}
	if len(l.attempts) != 20 {
		t.Fatal("attacker-selected attempt state is not bounded")
	}
	now = now.Add(time.Minute)
	if !l.attemptLocked("alice") || len(l.attempts) != 1 {
		t.Fatal("expired attempt window did not recover")
	}
}

func TestIdentityActivityRenewalAndOwnerSessionQuota(t *testing.T) {
	l := fixture(t)
	now := time.Now()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	a := signIn(t, l, "alice", alicePassword, "")
	l.mu.Lock()
	now = now.Add(idleLife - time.Second)
	l.mu.Unlock()
	if respond(l, request(l, "GET", "/", "", a)).Code != 200 {
		t.Fatal("active account page refused")
	}
	l.mu.Lock()
	now = now.Add(time.Second)
	for i := range 7 {
		id := sha256.Sum256([]byte(fmt.Sprint("owner-", i)))
		ctx, cancel := context.WithCancel(context.Background())
		l.sessions[id] = &session{username: "alice", created: now, last: now, ctx: ctx, cancel: cancel}
	}
	l.mu.Unlock()
	if respond(l, request(l, "GET", "/api/session", "", a)).Code != 200 {
		t.Fatal("user activity did not renew idle lifetime")
	}
	if _, err := l.login(context.Background(), "alice", alicePassword, ""); err != errLimited {
		t.Fatal("owner session quota escaped")
	}
	old := sessionContext(t, l, a)
	_ = signIn(t, l, "alice", alicePassword, a)
	requireCanceled(t, old)
	l.mu.Lock()
	count := len(l.sessions)
	l.mu.Unlock()
	if count != 8 {
		t.Fatal("rotation at capacity changed the session count")
	}
}

func TestIdentityPasswordChangeCannotFinishAfterLogout(t *testing.T) {
	l := fixture(t)
	a := signIn(t, l, "alice", alicePassword, "")
	id, _ := tokenID(a)
	done := make(chan error, 1)
	go func() { done <- l.change(context.Background(), id, alicePassword, nextPassword) }()
	deadline := time.Now().Add(3 * time.Second)
	for len(l.derive) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(l.derive) == 0 {
		t.Fatal("in-flight password change was not observed")
	}
	if respond(l, request(l, "DELETE", "/api/session", "", a)).Code != 204 {
		t.Fatal("logout during password change refused")
	}
	if err := <-done; err != errRefused {
		t.Fatal("password changed after its session was revoked")
	}
	_ = signIn(t, l, "alice", alicePassword, "")
}

func TestIdentityBackgroundExpiryCancelsWithoutRequest(t *testing.T) {
	l := fixture(t)
	a := signIn(t, l, "alice", alicePassword, "")
	c := sessionContext(t, l, a)
	id, _ := tokenID(a)
	l.mu.Lock()
	l.sessions[id].last = time.Now().Add(-idleLife)
	l.mu.Unlock()
	select {
	case <-c.Done():
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("background expiry did not revoke idle session")
	}
}

func TestIdentityIdleAbsoluteExpiryAndStatusDoesNotExtend(t *testing.T) {
	l := fixture(t)
	now := time.Now()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	a := signIn(t, l, "alice", alicePassword, "")
	c := sessionContext(t, l, a)
	l.mu.Lock()
	now = now.Add(idleLife - time.Second)
	l.mu.Unlock()
	if respond(l, request(l, "GET", "/api/session", "", a)).Code != 200 {
		t.Fatal("live status refused")
	}
	l.mu.Lock()
	now = now.Add(time.Second)
	l.sweepLocked()
	l.mu.Unlock()
	requireCanceled(t, c)
	a = signIn(t, l, "alice", alicePassword, "")
	c = sessionContext(t, l, a)
	id, _ := tokenID(a)
	l.mu.Lock()
	now = now.Add(absoluteLife)
	l.sessions[id].last = now // recent activity cannot extend absolute lifetime
	l.sweepLocked()
	l.mu.Unlock()
	requireCanceled(t, c)
}

func TestIdentityRevocationDuringDerivationAndClose(t *testing.T) {
	l := fixture(t)
	done := make(chan error, 1)
	go func() { _, err := l.login(context.Background(), "alice", alicePassword, ""); done <- err }()
	deadline := time.Now().Add(3 * time.Second)
	for len(l.derive) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(l.derive) == 0 {
		t.Fatal("in-flight derivation was not observed")
	}
	l.mu.Lock()
	l.accounts["alice"].revision++
	l.mu.Unlock()
	if err := <-done; err != errRefused {
		t.Fatal("stale password derivation created a session")
	}
	a := signIn(t, l, "bob", bobPassword, "")
	c := sessionContext(t, l, a)
	_ = l.Close()
	requireCanceled(t, c)
	if _, err := l.login(context.Background(), "bob", bobPassword, ""); err == nil {
		t.Fatal("closed identity lab accepted a login")
	}
}

func TestIdentityConfigurationRefusesMissingDuplicateOrUntrusted(t *testing.T) {
	a := accounts(t)
	for _, origin := range []string{"http://127.0.0.1:443", "https://localhost:443", "https://192.0.2.1:443", "https://127.0.0.1:0", "https://127.0.0.1:https", "https://127.0.0.1:443/", "https://127.0.0.1:0443"} {
		if l, err := NewLab(origin, a); err == nil {
			_ = l.Close()
			t.Fatal("invalid identity origin accepted")
		}
	}
	for _, entries := range [][]Account{nil, {a[0], a[0]}, {{"Alice", a[0].Password}}, {{"alice", PasswordHash{}}}} {
		if l, err := NewLab("https://127.0.0.1:443", entries); err == nil {
			_ = l.Close()
			t.Fatal("invalid account configuration accepted")
		}
	}
}

func FuzzIdentityJSON(f *testing.F) {
	for _, seed := range []string{`{"username":"alice","password":"test"}`, `{"password":"\ud83d\ude00","next":"literal\\ud800"}`, `null`, `{"password":"\ud800"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fields, ok := parseInput(data, "username", "password")
		if ok && (len(fields) != 2 || len(fields["username"]) > 1024 || len(fields["password"]) > 1024) {
			t.Fatal("JSON field bounds escaped")
		}
	})
}
