package identity

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"unicode/utf8"

	"github.com/denyfirst/keybash/web"
)

func (l *Lab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-read=(), clipboard-write=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'")
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, ipErr := netip.ParseAddr(peer)
	if l == nil || err != nil || ipErr != nil || !ip.Unmap().IsLoopback() || r.Host != l.host || r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || r.URL.RawQuery != "" || r.URL.Path != r.URL.EscapedPath() {
		refuse(w, http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		if r.Header.Get("Origin") != l.origin || r.Header.Get("X-Keybash-Request") != "1" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			refuse(w, http.StatusForbidden)
			return
		}
	}
	if l.store != nil {
		l.serveDurable(w, r)
		return
	}
	if r.URL.Path == "/api/session" && r.Method == http.MethodPost {
		fields, ok := readInput(w, r, "username", "password")
		if !ok || !usernameInput(fields["username"]) || !passwordInput(fields["password"]) {
			refuse(w, http.StatusBadRequest)
			return
		}
		previous := requestToken(r)
		raw, err := l.login(r.Context(), fields["username"], fields["password"], previous)
		clear(fields)
		if err != nil {
			identityError(w, err)
			return
		}
		http.SetCookie(w, sessionCookie(raw, int(absoluteLife.Seconds())))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodGet {
		assets := map[string]string{"/login": "auth-login.html", "/auth.mjs": "auth.mjs", "/auth.css": "auth.css"}
		if name := assets[r.URL.Path]; name != "" {
			serveAsset(w, name)
			return
		}
	}
	id, valid := tokenID(requestToken(r))
	l.mu.Lock()
	s := l.liveLocked(id, r.URL.Path == "/" && r.Method == http.MethodGet)
	if !valid || s == nil {
		l.mu.Unlock()
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			refuse(w, http.StatusUnauthorized)
		}
		return
	}
	username, csrf := s.username, l.csrf(id)
	if r.Method != http.MethodGet && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Keybash-CSRF")), []byte(csrf)) != 1 {
		l.mu.Unlock()
		refuse(w, http.StatusForbidden)
		return
	}
	if r.URL.Path == "/api/session" && r.Method == http.MethodDelete {
		l.forgetLocked(id)
		l.mu.Unlock()
		http.SetCookie(w, sessionCookie("", -1))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	l.mu.Unlock()
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		serveAsset(w, "auth-workspace.html")
	case r.URL.Path == "/api/session" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(struct {
			Username string `json:"username"`
			CSRF     string `json:"csrf"`
		}{username, csrf})
	case r.URL.Path == "/api/password" && r.Method == http.MethodPost:
		fields, ok := readInput(w, r, "password", "next")
		if !ok || !passwordInput(fields["password"]) || !passwordInput(fields["next"]) || utf8.RuneCountInString(fields["next"]) < 15 {
			refuse(w, http.StatusBadRequest)
			return
		}
		err := l.change(r.Context(), id, fields["password"], fields["next"])
		clear(fields)
		if err != nil {
			identityError(w, err)
			return
		}
		http.SetCookie(w, sessionCookie("", -1))
		w.WriteHeader(http.StatusNoContent)
	default:
		refuse(w, http.StatusNotFound)
	}
}

func refuse(w http.ResponseWriter, status int) { http.Error(w, "request refused", status) }
func identityError(w http.ResponseWriter, err error) {
	if err == errLimited {
		w.Header().Set("Retry-After", "60")
		refuse(w, http.StatusTooManyRequests)
		return
	}
	refuse(w, http.StatusUnauthorized)
}
func sessionCookie(value string, age int) *http.Cookie {
	return &http.Cookie{Name: cookieName, Value: value, Path: "/", MaxAge: age,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}
func requestToken(r *http.Request) string {
	var raw string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == cookieName {
			raw = cookie.Value
			count++
		}
	}
	if count != 1 {
		return ""
	}
	return raw
}
func serveAsset(w http.ResponseWriter, name string) {
	data, err := web.Assets.ReadFile(name)
	if err != nil {
		refuse(w, http.StatusInternalServerError)
		return
	}
	typeName := "text/html; charset=utf-8"
	if name == "auth.mjs" || name == "custody.mjs" {
		typeName = "text/javascript; charset=utf-8"
	} else if name == "auth.css" || name == "custody.css" {
		typeName = "text/css; charset=utf-8"
	}
	w.Header().Set("Content-Type", typeName)
	_, _ = w.Write(data)
}

// Reject invalid UTF-8 and lone JSON surrogate escapes before encoding/json can
// replace them. This preserves password bytes instead of silently repairing them.
func scalarJSON(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		if i+1 >= len(data) {
			return false
		}
		if data[i+1] != 'u' {
			i++
			continue
		}
		if i+6 > len(data) {
			return false
		}
		n, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil || n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+12 > len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
		i += 5
	}
	return true
}

func readInput(w http.ResponseWriter, r *http.Request, first, second string) (map[string]string, bool) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
	if err != nil {
		return nil, false
	}
	defer clear(data)
	return parseInput(data, first, second)
}
func parseInput(data []byte, first, second string) (map[string]string, bool) {
	if len(data) == 0 || len(data) > 16*1024 || !scalarJSON(data) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]string, 2)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || name != first && name != second {
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
		if json.Unmarshal(raw, &value) != nil || len(value) > 1024 {
			return nil, false
		}
		fields[name] = value
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || len(fields) != 2 || d.Decode(new(any)) != io.EOF {
		return nil, false
	}
	return fields, true
}
