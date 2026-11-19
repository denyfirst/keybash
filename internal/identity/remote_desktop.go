package identity

import (
	"context"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/rdcleanpath"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// BrowserRDPWorker opens a desktop whose RDP client runs in the browser
// (ADR 0008, docs/BROWSER-RDP-PAGE.md), through Keybash's RDP proxy, with the
// stored credential and the approved certificate.
type BrowserRDPWorker interface {
	OpenBrowserRDP(context.Context, RDPRequest) (terminalweb.MessageStream, error)
}

// desktopToken is the page's proof inside the RDCleanPath request: its CSRF
// value and its single-use lease, both 43 base64url characters, joined by a
// dot. The base64url alphabet has no dot.
func desktopToken(token string) (csrf, lease string, ok bool) {
	if len(token) != 87 || token[43] != '.' {
		return "", "", false
	}
	return token[:43], token[44:], true
}

// fastPathInput is a browser message that starts with a fast-path input PDU:
// the person's keys and mouse. Graphics acknowledgements and every other
// reply the page sends by itself are slow-path, and do not keep a desktop
// signed in.
func fastPathInput(message []byte) bool {
	return len(message) > 1 && message[0]&0x03 == 0
}

// remoteDesktop is the browser desktop's socket. It makes the checks the
// current socket makes (origin, session, access to servers, capacity), then
// reads the page's proof from IronRDP's first message, the RDCleanPath
// request, never from the address. The request goes on to the proxy without
// the proof.
func (l *Lab) remoteDesktop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.Header.Get("Origin") != l.origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		refuse(w, 403)
		return
	}
	id, ok := tokenID(requestToken(r))
	l.mu.Lock()
	s := l.readyLocked(id, false)
	var browser BrowserRDPWorker
	if l.remote != nil {
		browser, _ = l.remote.rdp.(BrowserRDPWorker)
	}
	allowed := ok && s != nil && browser != nil && l.serversLocked(s)
	capacityFull := allowed && !l.reserveRemoteSocketLocked(s.owner)
	l.mu.Unlock()
	if capacityFull {
		remoteCapacityError(w)
		return
	}
	if !allowed {
		refuse(w, 403)
		return
	}
	defer func() {
		l.mu.Lock()
		l.remote.sockets[s.owner]--
		if l.remote.sockets[s.owner] == 0 {
			delete(l.remote.sockets, s.owner)
		}
		l.mu.Unlock()
	}()
	socket, e := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return
	}
	defer socket.CloseNow()
	stopOwner := context.AfterFunc(s.ctx, func() { _ = socket.CloseNow() })
	defer stopOwner()
	socket.SetReadLimit(rdcleanpath.MaxRequest)
	first, stop := context.WithTimeout(r.Context(), 5*time.Second)
	kind, data, e := socket.Read(first)
	stop()
	if e != nil || kind != websocket.MessageBinary {
		return
	}
	request, e := rdcleanpath.Parse(data)
	clear(data)
	if e != nil {
		return
	}
	csrf, raw, ok := desktopToken(request.Token)
	if !ok {
		return
	}
	l.mu.Lock()
	if subtle.ConstantTimeCompare([]byte(csrf), []byte(l.csrf(id))) != 1 {
		l.mu.Unlock()
		return
	}
	lease, target, credential, ctx, e := l.redeemRemoteLocked(id, raw)
	l.mu.Unlock()
	if e != nil {
		return
	}
	key, _ := tokenID(raw)
	defer func() { lease.cancel(nil); l.mu.Lock(); delete(l.remote.leases, key); l.mu.Unlock() }()
	if target.Protocol != "rdp" {
		return // a desktop lease only
	}
	stopRequest := context.AfterFunc(r.Context(), func() { lease.cancel(nil) })
	defer stopRequest()
	stopSocket := context.AfterFunc(ctx, func() { _ = socket.CloseNow() })
	defer stopSocket()
	// Told before the proxy starts or a password goes anywhere; the proxy
	// would refuse this certificate on its own TLS anyway.
	if l.serverShowsAnother(ctx, target) {
		_ = socket.Close(terminalweb.CloseIdentityChanged, "identity-changed")
		return
	}
	forward, e := rdcleanpath.Forward(request.X224)
	if e != nil {
		return
	}
	// As openRemote: a bounded setup slot, and the stored credential's rules.
	if !l.slot(ctx) {
		return
	}
	e = validateCredential(&credential)
	<-l.derive
	if e != nil || ctx.Err() != nil {
		return
	}
	setupTimer := time.AfterFunc(10*time.Second, func() { lease.cancel(nil) })
	stream, e := browser.OpenBrowserRDP(ctx, RDPRequest{Target: target.Target, Certificate: append([]byte(nil), target.Identity...),
		Username: credential.Username, Password: credential.Secret})
	setupTimer.Stop()
	if e != nil || stream == nil || ctx.Err() != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return
	}
	if stream.WriteMessage(forward) != nil {
		_ = stream.Close()
		return
	}
	// From here RelayMessages closes the socket when ctx ends, after saying
	// why in the close; closing it at once here would leave the page with no
	// reason.
	stopOwner()
	stopSocket()
	terminalweb.RelayMessages(ctx, socket, stream, func(message []byte) bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		if ctx.Err() != nil || l.readyLocked(id, false) == nil {
			return false
		}
		if fastPathInput(message) {
			l.sessions[id].last = l.now()
		}
		return true
	})
}
