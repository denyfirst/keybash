package identity

import (
	"bytes"
	"html"
	"net/http"
	"strings"

	"github.com/denyfirst/keybash/web"
)

func (l *Lab) remoteAsset(w http.ResponseWriter, r *http.Request, s *session) bool {
	assets := map[string]string{"/app.mjs": "app.mjs", "/desktop.mjs": "desktop.mjs", "/desktop-workspace.mjs": "desktop-workspace.mjs", "/remote.mjs": "remote.mjs", "/paste.mjs": "paste.mjs", "/style.css": "style.css", "/desktop.css": "desktop.css", "/vendor/xterm.js": "vendor/xterm.js", "/vendor/xterm.css": "vendor/xterm.css", "/vendor/guacamole.mjs": "vendor/guacamole.mjs"}
	file := assets[r.URL.Path]
	protocol := ""
	record := ""
	if strings.HasPrefix(r.URL.Path, "/remote/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/remote/"), "/")
		if len(parts) != 2 || !validID(parts[1]) || (parts[0] != "ssh" && parts[0] != "rdp") {
			return false
		}
		protocol, record = parts[0], parts[1]
		c, e := l.store.readConnection(s.owner, record)
		l.mu.Lock()
		allowed := e == nil && !l.closed && s.ctx.Err() == nil && l.remote != nil && l.remote.targets[c.Target].Protocol == protocol && connectionTrusted(c, l.remote.targets[c.Target], l.now())
		l.mu.Unlock()
		if !allowed {
			refuse(w, 404)
			return true
		}
		file = "index.html"
		if protocol == "rdp" {
			file = "desktop.html"
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src "+l.origin+" "+strings.Replace(l.origin, "https:", "wss:", 1)+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; img-src blob:")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-read=(self), clipboard-write=(self)")
	if protocol != "ssh" && protocol != "rdp" {
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-read=(), clipboard-write=(self)")
	}
	mime := "text/javascript; charset=utf-8"
	if strings.HasSuffix(file, ".css") {
		mime = "text/css; charset=utf-8"
	}
	if strings.HasSuffix(file, ".html") {
		mime = "text/html; charset=utf-8"
		// Mark the body tag whatever else it carries. A page that cannot be
		// marked would fall back to the lab login, so it is refused instead.
		marked := bytes.Replace(data, []byte("<body"), []byte(`<body data-owned-remote="`+html.EscapeString(protocol)+`" data-connection="`+html.EscapeString(record)+`"`), 1)
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
