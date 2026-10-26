// Package terminalweb is a loopback HTTPS lab boundary, not application login.
package terminalweb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/web"
)

var ErrInvalidLab = errors.New("invalid terminal lab configuration")

const cookieName = "__Host-keybash-lab"

type Stream interface {
	Read([]byte) (int, error)
	ReadStderr([]byte) (int, error)
	Write([]byte) (int, error)
	Resize(uint32, uint32) error
	Close() error // Must unblock all reads/writes.
}

type Factory func(context.Context) (Stream, error)

// Lab has one owner and one active socket. Secrets stay in memory; no target,
// username, credential or host-key choice is accepted from an HTTP request.
type Lab struct {
	origin, host string
	factory      Factory
	outputLimit  int
	creditWait   time.Duration
	desktop      bool
	mu           sync.Mutex
	bootstrap    [32]byte
	bootstrapEnd time.Time
	used         bool
	session      [32]byte
	expires      time.Time
	active       bool
	cancel       context.CancelFunc
}

// New requires an exact HTTPS numeric loopback origin. The returned one-use
// code is sensitive: pass via an in-memory local channel, never URL/log/storage.
func New(origin string, factory Factory) (*Lab, string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != origin || factory == nil {
		return nil, "", ErrInvalidLab
	}
	host, port, err := net.SplitHostPort(u.Host)
	addr, parseErr := netip.ParseAddr(host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || parseErr != nil || !addr.IsLoopback() || addr.Zone() != "" || portErr != nil || portNumber == 0 {
		return nil, "", ErrInvalidLab
	}
	code, err := randomToken()
	if err != nil {
		return nil, "", ErrInvalidLab
	}
	return &Lab{origin: origin, host: u.Host, factory: factory, outputLimit: 8 * 1024 * 1024, creditWait: creditTimeout, bootstrap: sha256.Sum256([]byte(code)), bootstrapEnd: time.Now().Add(5 * time.Minute)}, code, nil
}

// NewDesktop uses the same loopback/TLS/owner/session boundary with a fixed
// desktop asset profile. The supplied Stream must validate both directions;
// this transport is not a Guacamole argument or credential endpoint.
func NewDesktop(origin string, factory Factory) (*Lab, string, error) {
	lab, code, err := New(origin, factory)
	if err == nil {
		lab.desktop = true
	}
	return lab, code, err
}

func randomToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}

func (l *Lab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if l == nil || l.factory == nil {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src "+l.origin+" "+strings.Replace(l.origin, "https:", "wss:", 1)+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
	if l.desktop {
		w.Header().Set("Content-Security-Policy", w.Header().Get("Content-Security-Policy")+"; img-src blob:")
	}
	peer, _, peerErr := net.SplitHostPort(r.RemoteAddr)
	peerAddr, addrErr := netip.ParseAddr(peer)
	if peerErr != nil || addrErr != nil || !peerAddr.Unmap().IsLoopback() || r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || r.Host != l.host || r.URL.RawQuery != "" || r.URL.Path != r.URL.EscapedPath() {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/lab/socket" {
		l.socket(w, r)
		return
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("Origin") != l.origin || r.Header.Get("X-Keybash-Lab") != "1" {
			http.Error(w, "request refused", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/lab/grant":
			l.grant(w, r)
		case "/lab/logout":
			l.logout(w, r)
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "request refused", http.StatusMethodNotAllowed)
		return
	}
	assets := map[string]string{"/": "index.html", "/app.mjs": "app.mjs", "/remote.mjs": "remote.mjs", "/paste.mjs": "paste.mjs", "/style.css": "style.css", "/vendor/xterm.js": "vendor/xterm.js", "/vendor/xterm.css": "vendor/xterm.css"}
	if l.desktop {
		assets = map[string]string{"/": "desktop.html", "/desktop-workspace.mjs": "desktop-workspace.mjs", "/paste.mjs": "paste.mjs", "/desktop.mjs": "desktop.mjs", "/remote.mjs": "remote.mjs", "/style.css": "style.css", "/desktop.css": "desktop.css", "/vendor/guacamole.mjs": "vendor/guacamole.mjs"}
	}
	path, ok := assets[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := web.Assets.ReadFile(path)
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}
	typeName := "text/javascript; charset=utf-8"
	if strings.HasSuffix(path, ".css") {
		typeName = "text/css; charset=utf-8"
	} else if strings.HasSuffix(path, ".html") {
		typeName = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", typeName)
	_, _ = w.Write(data)
}

func (l *Lab) grant(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "text/plain" {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64))
	if err != nil || len(body) != 43 {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	hash := sha256.Sum256(body)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used || !time.Now().Before(l.bootstrapEnd) || subtle.ConstantTimeCompare(hash[:], l.bootstrap[:]) != 1 {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	session, err := randomToken()
	if err != nil {
		http.Error(w, "request refused", http.StatusInternalServerError)
		return
	}
	l.used = true
	l.bootstrap = [32]byte{}
	l.session = sha256.Sum256([]byte(session))
	l.expires = time.Now().Add(15 * time.Minute)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: session, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 900})
	w.WriteHeader(http.StatusNoContent)
}

func (l *Lab) authorized(r *http.Request) bool { // l.mu must be held.
	cookie, err := r.Cookie(cookieName)
	if err != nil || len(cookie.Value) != 43 || !time.Now().Before(l.expires) {
		return false
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	return subtle.ConstantTimeCompare(hash[:], l.session[:]) == 1
}

func (l *Lab) logout(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	if !l.authorized(r) {
		l.mu.Unlock()
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	l.expires = time.Time{}
	l.session = [32]byte{}
	cancel := l.cancel
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (l *Lab) socket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.Header.Get("Origin") != l.origin {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	l.mu.Lock()
	if !l.authorized(r) || l.active {
		l.mu.Unlock()
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), l.expires)
	l.active, l.cancel = true, cancel
	l.mu.Unlock()
	defer func() { cancel(); l.mu.Lock(); l.active, l.cancel = false, nil; l.mu.Unlock() }()
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(32768)
	stream, err := l.factory(ctx)
	if err != nil || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		return
	}
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseNow(); _ = stream.Close() })
	defer stop()
	run(ctx, cancel, conn, stream, l.outputLimit, l.creditWait)
}
