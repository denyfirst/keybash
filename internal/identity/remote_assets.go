package identity

import (
	"bytes"
	"html"
	"net/http"
	"strings"

	"github.com/denyfirst/keybash/web"
)

func (l *Lab) remoteAsset(w http.ResponseWriter, r *http.Request, s *session) bool {
	assets := map[string]string{"/app.mjs": "app.mjs", "/desktop-workspace.mjs": "desktop-workspace.mjs", "/remote.mjs": "remote.mjs", "/paste.mjs": "paste.mjs", "/style.css": "style.css", "/desktop.css": "desktop.css", "/vendor/xterm.js": "vendor/xterm.js", "/vendor/xterm-addon-webgl.js": "vendor/xterm-addon-webgl.js", "/vendor/xterm.css": "vendor/xterm.css",
		// The desktop page on IronRDP (BROWSER-RDP-PAGE.md, 3d), and IronRDP's
		// browser client exactly as vendored and checked against CI's build
		// (scripts/vendor-ironrdp-web.py).
		"/remote-desktop.mjs": "remote-desktop.mjs", "/remote-desktop-input.mjs": "remote-desktop-input.mjs", "/remote-desktop-gfx.mjs": "remote-desktop-gfx.mjs",
		"/vendor/ironrdp/ironrdp_web.js": "vendor/ironrdp/ironrdp_web.js", "/vendor/ironrdp/ironrdp_web_bg.wasm": "vendor/ironrdp/ironrdp_web_bg.wasm"}
	file := assets[r.URL.Path]
	protocol := ""
	account := ""
	// A session opens on its own page, by the account's ID (ADR 0010):
	// /remote/{ssh|rdp}/{account}.
	if strings.HasPrefix(r.URL.Path, "/remote/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/remote/"), "/")
		if len(parts) != 2 || !validID(parts[1]) || (parts[0] != "ssh" && parts[0] != "rdp") {
			return false
		}
		protocol, account = parts[0], parts[1]
		l.mu.Lock()
		// The same checks as opening it: on the account, the server usable,
		// and of the protocol in the path.
		allowed := !l.closed && s.ctx.Err() == nil && l.remote != nil
		if allowed {
			target, _, ok := l.accountLocked(s, account)
			allowed = ok && target.Protocol == protocol
		}
		l.mu.Unlock()
		if !allowed {
			refuse(w, 404)
			return true
		}
		file = "index.html"
		if protocol == "rdp" {
			file = "remote-desktop.html"
		}
	}
	if file == "" {
		return false
	}
	data, e := web.Assets.ReadFile(file)
	if e != nil {
		refuse(w, 503)
		return true
	}
	scripts := "'self'"
	if protocol == "rdp" {
		// The desktop page runs IronRDP's WebAssembly, which needs this to
		// compile; it does not let the page evaluate JavaScript. No other page
		// has it.
		scripts = "'self' 'wasm-unsafe-eval'"
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src "+scripts+"; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src "+l.origin+" "+strings.Replace(l.origin, "https:", "wss:", 1)+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; img-src blob:")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-read=(self), clipboard-write=(self)")
	if protocol != "ssh" && protocol != "rdp" {
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-read=(), clipboard-write=(self)")
	}
	mime := "text/javascript; charset=utf-8"
	if strings.HasSuffix(file, ".css") {
		mime = "text/css; charset=utf-8"
	}
	if strings.HasSuffix(file, ".wasm") {
		// The type browsers compile WebAssembly from as it streams in.
		mime = "application/wasm"
	}
	if strings.HasSuffix(file, ".html") {
		mime = "text/html; charset=utf-8"
		// Mark the body tag whatever else it carries. A page that cannot be
		// marked would fall back to the lab login, so it is refused instead.
		mark := `<body data-owned-remote="` + html.EscapeString(protocol) + `" data-account="` + html.EscapeString(account) + `"`
		// A desktop opens with the account's chosen picture, one fixed word.
		if picture := l.store.preferencesOf(s.owner).Picture; protocol == "rdp" && (picture == "smooth" || picture == "sharp") {
			mark += ` data-picture="` + picture + `"`
		}
		marked := bytes.Replace(data, []byte("<body"), []byte(mark), 1)
		if bytes.Equal(marked, data) {
			refuse(w, 503)
			return true
		}
		data = marked
	}
	w.Header().Set("Content-Type", mime)
	_, _ = w.Write(data)
	return true
}
