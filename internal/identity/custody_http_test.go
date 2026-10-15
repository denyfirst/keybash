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

	bolt "go.etcd.io/bbolt"
)

type custodyClient struct {
	t      *testing.T
	l      *Lab
	cookie *http.Cookie
	csrf   string
}

func (c *custodyClient) call(method, path, body string) *httptest.ResponseRecorder {
	c.t.Helper()
	r := httptest.NewRequest(method, "https://127.0.0.1:8443"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:9876"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("Origin", "https://127.0.0.1:8443")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Keybash-Request", "1")
	r.Header.Set("X-Keybash-CSRF", c.csrf)
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	c.l.ServeHTTP(w, r)
	for _, cookie := range w.Result().Cookies() {
		c.cookie = cookie
	}
	return w
}
func (c *custodyClient) expect(method, path, body string, status int) *httptest.ResponseRecorder {
	c.t.Helper()
	w := c.call(method, path, body)
	if w.Code != status {
		c.t.Fatalf("%s %s: got %d want %d", method, path, w.Code, status)
	}
	return w
}
func (c *custodyClient) session(stage string) {
	c.t.Helper()
	w := c.expect("GET", "/api/session", "", 200)
	var data struct{ CSRF, Stage string }
	if json.Unmarshal(w.Body.Bytes(), &data) != nil || data.Stage != stage || data.CSRF == "" {
		c.t.Fatal("session stage/CSRF invalid")
	}
	c.csrf = data.CSRF
}
func inputJSON(value any) string { b, _ := json.Marshal(value); return string(b) }
func (c *custodyClient) login() {
	c.t.Helper()
	c.expect("POST", "/api/session", inputJSON(map[string]string{"username": "alice", "password": alicePassword}), 204)
}
func advance(l *Lab, now *time.Time, d time.Duration) { l.mu.Lock(); *now = now.Add(d); l.mu.Unlock() }
func TestCustodyHTTPBootstrapMFAAndVault(t *testing.T) {
	s, _, _, code := custodyFixture(t)
	l, e := NewPersistent("https://127.0.0.1:8443", s)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	defer l.Close()
	now := time.Now()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	c := custodyClient{t: t, l: l}
	c.expect("GET", "/api/credentials", "", 401)
	c.expect("POST", "/api/bootstrap", inputJSON(map[string]string{"code": "wrong", "username": "alice", "password": alicePassword}), 401)
	c.expect("POST", "/api/bootstrap", inputJSON(map[string]string{"code": code, "username": "alice", "password": alicePassword}), 204)
	c.session("enroll")
	c.expect("POST", "/api/bootstrap", inputJSON(map[string]string{"code": code, "username": "other", "password": alicePassword}), 401)
	c.expect("GET", "/api/credentials", "", 403)
	c.expect("POST", "/api/credentials", `{"name":"x","kind":"password","username":"u","secret":"s","passphrase":""}`, 403)
	setupCookie := c.cookie
	w := c.expect("POST", "/api/mfa/enrollment", "{}", 200)
	var seed struct{ Secret string }
	if json.Unmarshal(w.Body.Bytes(), &seed) != nil || !validSeed(seed.Secret) {
		t.Fatal("enrollment seed missing")
	}
	c.expect("POST", "/api/mfa/confirm", `{"code":"x"}`, 401)
	w = c.expect("POST", "/api/mfa/confirm", inputJSON(map[string]string{"code": otpCode(t, seed.Secret, now.Unix()/30-1)}), 200)
	var recovery struct{ Codes []string }
	if json.Unmarshal(w.Body.Bytes(), &recovery) != nil || len(recovery.Codes) != 10 {
		t.Fatal("recovery codes missing")
	}
	c.session("ready")
	if c.cookie.Value == setupCookie.Value {
		t.Fatal("MFA did not rotate cookie")
	}
	stale := custodyClient{t: t, l: l, cookie: setupCookie}
	stale.expect("GET", "/api/session", "", 401)
	c.expect("GET", "/api/credentials", "", 200)
	c.expect("POST", "/api/credentials", `{"name":"x","kind":"password","username":"u","secret":"s","passphrase":""}`, 403)
	c.expect("POST", "/api/reauth", inputJSON(map[string]string{"password": alicePassword, "code": otpCode(t, seed.Secret, now.Unix()/30)}), 204)
	oldCSRF := c.csrf
	c.csrf = "wrong"
	c.expect("POST", "/api/credentials", `{}`, 403)
	c.csrf = oldCSRF
	c.expect("POST", "/api/credentials", `{"name":"x","name":"y","kind":"password","username":"u","secret":"s","passphrase":""}`, 400)
	c.expect("POST", "/api/credentials", `{"name":"x","kind":"password","username":"u","secret":"s","passphrase":"","owner":"other"}`, 400)
	w = c.expect("POST", "/api/credentials", `{"name":"<img src=x>","kind":"password","username":"u","secret":"synthetic-custody-secret","passphrase":""}`, 200)
	var record struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &record)
	if !validID(record.ID) {
		t.Fatal("credential not created")
	}
	listed := c.expect("GET", "/api/credentials", "", 200)
	if strings.Contains(listed.Body.String(), "synthetic-custody-secret") {
		t.Fatal("metadata leaked secret")
	}
	revealed := c.expect("POST", "/api/credentials/"+record.ID+"/reveal", "{}", 200)
	if !strings.Contains(revealed.Body.String(), "synthetic-custody-secret") {
		t.Fatal("owner reveal failed")
	}
	c.expect("POST", "/api/credentials/"+strings.Repeat("a", 32)+"/reveal", "{}", 404)
	advance(l, &now, 121*time.Second)
	c.expect("POST", "/api/credentials/"+record.ID+"/reveal", "{}", 403)
	c.expect("POST", "/api/reauth", inputJSON(map[string]string{"password": alicePassword, "code": recovery.Codes[0]}), 204)
	// Reset enters enrollment but leaves old MFA active until confirmation.
	c.expect("POST", "/api/mfa/reset", "{}", 204)
	c.session("enroll")
	a, e := s.lookup("alice")
	if e != nil || a.Seed != seed.Secret {
		t.Fatal("replacement discarded active MFA")
	}
	other := custodyClient{t: t, l: l}
	other.login()
	other.session("challenge")
	other.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": recovery.Codes[1]}), 204)
	other.session("ready")
	c.expect("POST", "/api/mfa/enrollment", "{}", 200)
	c.expect("POST", "/api/mfa/confirm", `{"code":"bad"}`, 401)
	// Cancelling replacement must not disable the active factor or expose vault.
	c.expect("DELETE", "/api/session", "{}", 204)
	c.expect("GET", "/api/session", "", 401)
	advance(l, &now, 61*time.Second)
	other.expect("POST", "/api/reauth", inputJSON(map[string]string{"password": alicePassword, "code": recovery.Codes[2]}), 204)
	other.expect("DELETE", "/api/credentials/"+record.ID, "{}", 204)
	other.expect("POST", "/api/credentials/"+record.ID+"/reveal", "{}", 404)
	other.expect("POST", "/api/password", inputJSON(map[string]string{"password": alicePassword, "next": nextPassword}), 204)
	other.expect("GET", "/api/session", "", 401)
	c.expect("POST", "/api/session", inputJSON(map[string]string{"username": "alice", "password": alicePassword}), 401)
	c.expect("POST", "/api/session", inputJSON(map[string]string{"username": "alice", "password": nextPassword}), 204)
	c.session("challenge")
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": recovery.Codes[0]}), 401)
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": recovery.Codes[3]}), 204)
	c.session("ready")
	oldCookie := c.cookie
	_ = l.Close()
	fresh, e := NewPersistent("https://127.0.0.1:8443", s)
	if e != nil {
		t.Fatal("restart refused")
	}
	defer fresh.Close()
	c.l = fresh
	c.cookie = oldCookie
	c.expect("GET", "/api/session", "", 401)
}

func TestCustodyOfflineRecoveryBootstrapRenewalAndSealLimit(t *testing.T) {
	s, _, _, code := custodyFixture(t)
	next, e := s.RenewBootstrap()
	if e != nil || s.bootstrapValid(code, time.Now()) || !s.bootstrapValid(next, time.Now()) {
		t.Fatal("bootstrap renewal failed")
	}
	if s.bootstrap(next, "alice", accounts(t)[0].Password, time.Now()) != nil {
		t.Fatal("renewed bootstrap refused")
	}
	if _, e = s.RenewBootstrap(); e == nil {
		t.Fatal("initialized registration reopened")
	}
	a, _, _ := enrollFixture(t, s, "alice", time.Now())
	if s.RecoverAccount("alice", nextPassword, false) != nil {
		t.Fatal("operator recovery refused")
	}
	b, e := s.lookup("alice")
	if e != nil || b.ID != a.ID || b.Revision != a.Revision+1 || b.Seed != a.Seed || !b.password().verify(nextPassword) {
		t.Fatal("operator recovery lost account or factor")
	}
	if s.RecoverAccount("alice", alicePassword, true) != nil {
		t.Fatal("lost-factor recovery refused")
	}
	b, _ = s.lookup("alice")
	if b.Seed != "" || len(b.Recovery) != 0 || b.Revision != a.Revision+2 {
		t.Fatal("offline lost-factor recovery incomplete")
	}
	if s.update(func(tx *bolt.Tx) error {
		m, e := s.meta(tx)
		if e != nil {
			return e
		}
		m.Seals = 1 << 31
		return s.putMeta(tx, m)
	}) != nil {
		t.Fatal("seal-limit fixture failed")
	}
	if s.replacePassword(b.ID, b.Revision, accounts(t)[0].Password) == nil {
		t.Fatal("wrap message limit bypassed")
	}
	if s.update(func(tx *bolt.Tx) error {
		raw := append([]byte(nil), tx.Bucket(metaBucket).Get(metaKey)...)
		var m storeMeta
		if json.Unmarshal(raw, &m) != nil {
			return errRefused
		}
		m.Seals = 0
		raw, _ = json.Marshal(m)
		return tx.Bucket(metaBucket).Put(metaKey, raw)
	}) != nil {
		t.Fatal("metadata tamper fixture failed")
	}
	if _, e = s.lookup("alice"); e == nil {
		t.Fatal("unauthenticated seal-counter reset accepted")
	}
}

func TestCustodyStrictFieldsAndSlowBodyIsolation(t *testing.T) {
	for _, raw := range []string{`{"code":"a","code":"b"}`, `{"code":null}`, `{"code":"\ud800"}`, `{"code":"a"} {}`, `{"code":"a","extra":"b"}`, `[]`} {
		if _, ok := parseFields([]byte(raw), 1024, "code"); ok {
			t.Fatal("ambiguous or malformed fields accepted")
		}
	}
	if fields, ok := parseFields([]byte(`{"code":"123456"}`), 1024, "code"); !ok || fields["code"] != "123456" {
		t.Fatal("valid fields refused")
	}
	s, _, _ := bootstrapped(t)
	l, e := NewPersistent("https://127.0.0.1:8443", s)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	defer l.Close()
	c := custodyClient{t: t, l: l}
	c.login()
	c.session("enroll")
	reader, writer := io.Pipe()
	defer writer.Close()
	started := make(chan struct{})
	done := make(chan struct{})
	r := httptest.NewRequest("POST", "https://127.0.0.1:8443/api/mfa/enrollment", reader)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Origin", l.origin)
	r.Header.Set("X-Keybash-Request", "1")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Keybash-CSRF", c.csrf)
	r.AddCookie(c.cookie)
	r.Body = &startedBody{ReadCloser: r.Body, started: started}
	go func() { defer close(done); l.ServeHTTP(httptest.NewRecorder(), r) }()
	<-started
	logout := make(chan int, 1)
	go func() { logout <- c.call("DELETE", "/api/session", "{}").Code }()
	select {
	case status := <-logout:
		if status != 204 {
			t.Fatal("logout refused")
		}
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("slow body blocked session revocation")
	}
	_ = writer.Close()
	<-done
}

type startedBody struct {
	io.ReadCloser
	started chan struct{}
	first   bool
}

func (b *startedBody) Read(p []byte) (int, error) {
	if !b.first {
		b.first = true
		close(b.started)
	}
	return b.ReadCloser.Read(p)
}

func FuzzCustodyFields(f *testing.F) {
	f.Add([]byte(`{"code":"123456"}`))
	f.Add([]byte(`{"code":"\ud800"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		fields, ok := parseFields(raw, 4096, "code")
		if ok {
			if len(fields) != 1 || len(fields["code"]) > 4096 {
				t.Fatal("parser accepted invalid bounds")
			}
			encoded, _ := json.Marshal(fields)
			if _, again := parseFields(encoded, 4096, "code"); !again {
				t.Fatal("accepted fields not round-trippable")
			}
		}
	})
}

// Cancellation never consumes a factor or grants fresh authority.
func TestCustodyCancelledReauthentication(t *testing.T) {
	s, _, _ := bootstrapped(t)
	_, _, codes := enrollFixture(t, s, "alice", time.Now())
	l, e := NewPersistent("https://127.0.0.1:8443", s)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	defer l.Close()
	raw, e := l.login(context.Background(), "alice", alicePassword, "")
	if e != nil {
		t.Fatal("login refused")
	}
	id, _ := tokenID(raw)
	l.mu.Lock()
	raw, e = l.finishFactorLocked(id, codes[0])
	l.mu.Unlock()
	if e != nil {
		t.Fatal("factor refused")
	}
	id, _ = tokenID(raw)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l.reauthenticate(ctx, id, alicePassword, codes[1]) == nil {
		t.Fatal("cancelled reauth accepted")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.readyLocked(id, true) != nil {
		t.Fatal("cancelled reauth granted authority")
	}
}
