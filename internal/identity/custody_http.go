package identity

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/denyfirst/keybash/web"
)

func readFields(w http.ResponseWriter, r *http.Request, limit int, names ...string) (map[string]string, bool) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, false
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(limit)))
	if e != nil {
		return nil, false
	}
	defer clear(data)
	return parseFields(data, limit, names...)
}
func parseFields(data []byte, limit int, names ...string) (map[string]string, bool) {
	if len(data) == 0 || len(data) > limit || !scalarJSON(data) {
		return nil, false
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]string, len(names))
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		if e != nil || !ok || !allowed[name] {
			return nil, false
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, false
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil || len(raw) == 0 || raw[0] != '"' {
			return nil, false
		}
		var value string
		if json.Unmarshal(raw, &value) != nil || len(value) > 64*1024 {
			return nil, false
		}
		fields[name] = value
	}
	last, e := d.Token()
	if e != nil || last != json.Delim('}') || len(fields) != len(names) || d.Decode(new(any)) != io.EOF {
		return nil, false
	}
	return fields, true
}
func jsonReply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

func (l *Lab) bootstrapHTTP(w http.ResponseWriter, r *http.Request) {
	fields, ok := readFields(w, r, 16*1024, "code", "username", "password")
	if !ok || !usernameInput(fields["username"]) || !passwordInput(fields["password"]) {
		refuse(w, 400)
		return
	}
	defer clear(fields)
	l.mu.Lock()
	allowed := !l.closed && l.attemptLocked("bootstrap:", setupAttempts)
	now := l.now()
	l.mu.Unlock()
	if !allowed {
		identityError(w, errLimited)
		return
	}
	if !l.store.bootstrapValid(fields["code"], now) || !l.slot(r.Context()) {
		refuse(w, 401)
		return
	}
	defer func() { <-l.derive }()
	hash, e := HashPassword(fields["password"])
	if e != nil {
		refuse(w, 400)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || r.Context().Err() != nil || l.store.bootstrap(fields["code"], fields["username"], hash, l.now()) != nil {
		refuse(w, 401)
		return
	}
	if !l.refreshLocked(fields["username"]) {
		refuse(w, 503)
		return
	}
	raw, e := l.issueLocked(fields["username"], "")
	if e != nil {
		identityError(w, e)
		return
	}
	// The bootstrap code already proved operator authority for this account.
	id, _ := tokenID(raw)
	l.sessions[id].setupProved = true
	http.SetCookie(w, sessionCookie(raw, int(absoluteLife.Seconds())))
	w.WriteHeader(204)
}
func (l *Lab) serveDurable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-read=(), clipboard-write=(self)")
	if r.URL.Path == "/api/remote/socket" {
		l.remoteSocket(w, r)
		return
	}
	// Read bounded bodies before taking the account/session mutex. A slow
	// client must not hold logout, expiry or another user's authentication.
	if r.Method != "GET" {
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
		original := r.Body
		body, e := io.ReadAll(http.MaxBytesReader(w, original, 96*1024))
		_ = original.Close()
		_ = controller.SetReadDeadline(time.Time{})
		if e != nil {
			refuse(w, 400)
			return
		}
		defer clear(body)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	if r.Method == "GET" {
		switch r.URL.Path {
		case "/login":
			serveAsset(w, "custody-login.html")
			return
		case "/custody.mjs":
			serveAsset(w, "custody.mjs")
			return
		case "/systems.mjs":
			serveAsset(w, "systems.mjs")
			return
		case "/auth.css":
			serveAsset(w, "auth.css")
			return
		case "/custody.css":
			serveAsset(w, "custody.css")
			return
		case "/keybash.css":
			serveAsset(w, "keybash.css")
			return
		case web.FontPath:
			serveAsset(w, "schibsted-grotesk.woff2")
			return
		case "/api/setup":
			ready, e := l.store.initialized()
			if e != nil {
				refuse(w, 503)
				return
			}
			jsonReply(w, struct {
				Initialized bool `json:"initialized"`
			}{ready})
			return
		}
	}
	if r.URL.Path == "/api/bootstrap" && r.Method == "POST" {
		l.bootstrapHTTP(w, r)
		return
	}
	if r.URL.Path == "/api/session" && r.Method == "POST" {
		fields, ok := readInput(w, r, "username", "password")
		if !ok || !usernameInput(fields["username"]) || !passwordInput(fields["password"]) {
			refuse(w, 400)
			return
		}
		raw, e := l.loginFrom(r.Context(), l.source(r), fields["username"], fields["password"], requestToken(r))
		clear(fields)
		if e != nil {
			identityError(w, e)
			return
		}
		http.SetCookie(w, sessionCookie(raw, int(absoluteLife.Seconds())))
		w.WriteHeader(204)
		return
	}
	// The workspace is one document with a page per path; the script shows
	// the part the path names. Loading a page counts as activity.
	page := r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/keys" || r.URL.Path == "/account")
	id, valid := tokenID(requestToken(r))
	l.mu.Lock()
	s := l.liveLocked(id, page)
	if !valid || s == nil {
		l.mu.Unlock()
		if page {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			refuse(w, 401)
		}
		return
	}
	if r.Method != "GET" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Keybash-CSRF")), []byte(l.csrf(id))) != 1 {
		l.mu.Unlock()
		refuse(w, 403)
		return
	}
	if r.URL.Path == "/api/session" && r.Method == "DELETE" {
		l.forgetLocked(id)
		l.mu.Unlock()
		http.SetCookie(w, sessionCookie("", -1))
		w.WriteHeader(204)
		return
	}
	if page {
		l.mu.Unlock()
		serveAsset(w, "custody-workspace.html")
		return
	}
	if r.URL.Path == "/api/session" && r.Method == "GET" {
		data := struct {
			Username string `json:"username"`
			CSRF     string `json:"csrf"`
			Stage    string `json:"stage"`
			Remote   bool   `json:"remote"`
			Setup    bool   `json:"setup"` // first enrollment still needs the operator's setup code
		}{s.username, l.csrf(id), s.stage, l.remote != nil, s.stage == "enroll" && !s.replacing && !s.setupProved}
		l.mu.Unlock()
		jsonReply(w, data)
		return
	}
	if r.URL.Path == "/api/mfa/enrollment" && r.Method == "POST" {
		// A first enrollment reveals a seed only after the operator's one-time
		// setup code (or the bootstrap code) is proved; the password alone is
		// not enough. A replacement relies on its fresh reauthentication.
		needSetup := s.stage == "enroll" && !s.replacing && !s.setupProved
		var fields map[string]string
		var ok bool
		if needSetup {
			fields, ok = readFields(w, r, 1024, "setup")
		} else {
			fields, ok = readFields(w, r, 1024)
		}
		if !ok || s.stage != "enroll" || s.replacing && !l.now().Before(s.reauthUntil) {
			l.mu.Unlock()
			refuse(w, 403)
			return
		}
		if needSetup {
			if !l.attemptLocked("mfa:"+s.username, factorAttempts) {
				l.mu.Unlock()
				identityError(w, errLimited)
				return
			}
			valid := l.store.enrollmentValid(s.owner, fields["setup"], l.now())
			clear(fields)
			if !valid {
				l.mu.Unlock()
				refuse(w, 403)
				return
			}
			s.setupProved = true
		}
		if s.pendingSeed == "" {
			var e error
			s.pendingSeed, e = newSeed()
			if e != nil {
				l.mu.Unlock()
				refuse(w, 503)
				return
			}
		}
		seed, username := s.pendingSeed, s.username
		l.mu.Unlock()
		modules, e := seedQR(username, seed)
		if e != nil {
			refuse(w, 503)
			return
		}
		jsonReply(w, struct {
			Secret string   `json:"secret"`
			QR     []string `json:"qr"` // the same seed, for a phone to scan
		}{seed, modules})
		return
	}
	if r.URL.Path == "/api/mfa/confirm" && r.Method == "POST" {
		fields, ok := readFields(w, r, 1024, "code")
		if !ok {
			l.mu.Unlock()
			refuse(w, 400)
			return
		}
		raw, codes, e := l.confirmEnrollmentLocked(id, fields["code"])
		clear(fields)
		l.mu.Unlock()
		if e != nil {
			identityError(w, e)
			return
		}
		http.SetCookie(w, sessionCookie(raw, int(absoluteLife.Seconds())))
		jsonReply(w, struct {
			Codes recoveryCodes `json:"codes"`
		}{codes})
		return
	}
	if r.URL.Path == "/api/mfa/verify" && r.Method == "POST" {
		fields, ok := readFields(w, r, 1024, "code")
		if !ok {
			l.mu.Unlock()
			refuse(w, 400)
			return
		}
		raw, e := l.finishFactorLocked(id, fields["code"])
		clear(fields)
		l.mu.Unlock()
		if e != nil {
			identityError(w, e)
			return
		}
		http.SetCookie(w, sessionCookie(raw, int(absoluteLife.Seconds())))
		w.WriteHeader(204)
		return
	}
	if l.readyLocked(id, false) != s {
		l.mu.Unlock()
		refuse(w, 403)
		return
	}
	if r.Method == "GET" {
		l.mu.Unlock()
		if l.remoteAsset(w, r, s) {
			return
		}
		l.mu.Lock()
		s = l.readyLocked(id, false)
		if s == nil {
			l.mu.Unlock()
			refuse(w, 401)
			return
		}
	}
	if r.URL.Path == "/api/targets" || strings.HasPrefix(r.URL.Path, "/api/targets/") || strings.HasPrefix(r.URL.Path, "/api/connections") || r.URL.Path == "/api/remote/open" || r.URL.Path == "/api/remote/capacity" {
		l.remoteHTTP(w, r, id, s)
		return
	}
	if r.URL.Path == "/api/reauth" && r.Method == "POST" {
		l.mu.Unlock()
		fields, ok := readFields(w, r, 1024, "code")
		if !ok {
			refuse(w, 400)
			return
		}
		e := l.stepUp(r.Context(), id, fields["code"])
		clear(fields)
		if e != nil {
			identityError(w, e)
			return
		}
		w.WriteHeader(204)
		return
	}
	if r.URL.Path == "/api/credentials" && r.Method == "GET" {
		items, e := l.store.listCredentials(s.owner)
		l.mu.Unlock()
		if e != nil {
			refuse(w, 503)
			return
		}
		jsonReply(w, items)
		return
	}
	// Adding a record only needs the ready session. Everything else here
	// reveals, removes or changes account security and asks for a factor
	// proved within freshProof; 428 tells the page to ask for a code.
	adding := (r.URL.Path == "/api/credentials" || r.URL.Path == "/api/credentials/generate") && r.Method == "POST"
	if !adding && l.readyLocked(id, true) != s {
		l.mu.Unlock()
		refuse(w, http.StatusPreconditionRequired)
		return
	}
	s.last = l.now()
	switch {
	case r.URL.Path == "/api/password" && r.Method == "POST":
		l.mu.Unlock()
		fields, ok := readInput(w, r, "password", "next")
		if !ok {
			refuse(w, 400)
			return
		}
		e := l.change(r.Context(), id, fields["password"], fields["next"])
		clear(fields)
		if e != nil {
			identityError(w, e)
			return
		}
		http.SetCookie(w, sessionCookie("", -1))
		w.WriteHeader(204)
	case r.URL.Path == "/api/mfa/reset" && r.Method == "POST":
		if _, ok := readFields(w, r, 1024); !ok {
			l.mu.Unlock()
			refuse(w, 400)
			return
		}
		s.stage = "enroll"
		s.replacing = true
		s.pendingSeed = ""
		s.challengeEnd = l.now().Add(5 * time.Minute)
		l.sweepRemotesLocked()
		l.mu.Unlock()
		w.WriteHeader(204)
	case r.URL.Path == "/api/mfa/recovery" && r.Method == "POST":
		if _, ok := readFields(w, r, 1024); !ok {
			l.mu.Unlock()
			refuse(w, 400)
			return
		}
		name := s.username
		codes, e := l.store.regenerateRecovery(s.owner, s.revision)
		if e != nil {
			l.mu.Unlock()
			refuse(w, 503)
			return
		}
		l.refreshLocked(name)
		raw, e := l.issueLocked(name, "")
		if e == nil {
			newID, _ := tokenID(raw)
			l.sessions[newID].stage = "ready"
		}
		l.mu.Unlock()
		if e != nil {
			identityError(w, e)
			return
		}
		http.SetCookie(w, sessionCookie(raw, int(absoluteLife.Seconds())))
		jsonReply(w, struct {
			Codes recoveryCodes `json:"codes"`
		}{codes})
	case r.URL.Path == "/api/credentials/generate" && r.Method == "POST":
		if !l.attemptLocked("import:"+s.username, importAttempts) {
			l.mu.Unlock()
			identityError(w, errLimited)
			return
		}
		l.mu.Unlock()
		fields, ok := readFields(w, r, 1024, "name", "username")
		if !ok {
			refuse(w, 400)
			return
		}
		c, e := newGeneratedKey(fields["name"], fields["username"])
		if e != nil {
			refuse(w, 400)
			return
		}
		l.mu.Lock()
		if l.readyLocked(id, false) != s || r.Context().Err() != nil {
			l.mu.Unlock()
			refuse(w, 401)
			return
		}
		record, e := l.store.putCredential(s.owner, c)
		l.mu.Unlock()
		if e != nil {
			refuse(w, 503)
			return
		}
		// Only the public line leaves; the private key stays sealed here.
		jsonReply(w, struct {
			ID     string `json:"id"`
			Public string `json:"public"`
		}{record, c.Public})
	case r.URL.Path == "/api/credentials" && r.Method == "POST":
		if !l.attemptLocked("import:"+s.username, importAttempts) {
			l.mu.Unlock()
			identityError(w, errLimited)
			return
		}
		l.mu.Unlock()
		fields, ok := readFields(w, r, 96*1024, "name", "kind", "username", "secret", "passphrase")
		if !ok {
			refuse(w, 400)
			return
		}
		c := Credential{Name: fields["name"], Kind: fields["kind"], Username: fields["username"], Secret: fields["secret"], Passphrase: fields["passphrase"]}
		clear(fields)
		if !l.slot(r.Context()) {
			identityError(w, errLimited)
			return
		}
		e := validateCredential(&c)
		<-l.derive
		if e != nil {
			refuse(w, 400)
			return
		}
		l.mu.Lock()
		if l.readyLocked(id, false) != s || r.Context().Err() != nil {
			l.mu.Unlock()
			refuse(w, 401)
			return
		}
		record, e := l.store.putCredential(s.owner, c)
		l.mu.Unlock()
		if e != nil {
			refuse(w, 503)
			return
		}
		jsonReply(w, struct {
			ID string `json:"id"`
		}{record})
	default:
		prefix := "/api/credentials/"
		path := strings.TrimPrefix(r.URL.Path, prefix)
		record, action, _ := strings.Cut(path, "/")
		if !strings.HasPrefix(r.URL.Path, prefix) || !validID(record) {
			l.mu.Unlock()
			refuse(w, 404)
			return
		}
		if r.Method == "DELETE" && action == "" {
			if _, ok := readFields(w, r, 1024); !ok {
				l.mu.Unlock()
				refuse(w, 400)
				return
			}
			e := l.store.deleteCredential(s.owner, record)
			if e == nil {
				l.revokeRemotesLocked(s.owner, "", record)
			}
			l.mu.Unlock()
			if e != nil {
				refuse(w, 404)
				return
			}
			w.WriteHeader(204)
			return
		}
		if r.Method == "POST" && action == "reveal" {
			if _, ok := readFields(w, r, 1024); !ok {
				l.mu.Unlock()
				refuse(w, 400)
				return
			}
			c, e := l.store.readCredential(s.owner, record)
			l.mu.Unlock()
			if e != nil {
				refuse(w, 404)
				return
			}
			if c.Generated {
				refuse(w, 403) // made here, never exported
				return
			}
			deadlineDone := make(chan struct{})
			stop := context.AfterFunc(s.ctx, func() { defer close(deadlineDone); _ = http.NewResponseController(w).SetWriteDeadline(time.Now()) })
			defer func() {
				if !stop() {
					<-deadlineDone
				}
			}()
			if s.ctx.Err() != nil || r.Context().Err() != nil {
				refuse(w, 401)
				return
			}
			jsonReply(w, c)
			return
		}
		l.mu.Unlock()
		refuse(w, 404)
	}
}
