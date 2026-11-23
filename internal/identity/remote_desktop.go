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

// remoteDesktop is the desktop's socket, the only way a desktop opens. It
// makes the checks the terminal socket makes (origin, session, access to
// servers, capacity), then reads the page's proof from IronRDP's first
// message, the RDCleanPath request, never from the address. The request goes
// on to the proxy without the proof.
func (l *Lab) remoteDesktop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.Header.Get("Origin") != l.origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		refuse(w, 403)
		return
	}
	id, ok := tokenID(requestToken(r))
	l.mu.Lock()
	s := l.readyLocked(id, false)
	var browser RDPWorker
	if l.remote != nil {
		browser = l.remote.rdp
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
	// Windows needs a moment after a desktop to the same account ends before
	// it starts the next one's picture: one opened at once, after a reload, a
	// closed tab or Connect again, got "Connected" and a black screen. The
	// next one waits out the rest of desktopSettle, and this one's end is
	// noted when it returns.
	settleKey := desktopKey(target.ID, credential.Username)
	l.mu.Lock()
	settle := l.remote.settleDesktopLocked(settleKey, l.now())
	l.mu.Unlock()
	defer func() { l.mu.Lock(); l.remote.desktopEnds[settleKey] = l.now(); l.mu.Unlock() }()
	if settle > 0 {
		wait := time.NewTimer(settle)
		select {
		case <-wait.C:
		case <-ctx.Done():
			wait.Stop()
			return
		}
	}
	// The certificate read runs while the proxy's sandbox starts. The proxy
	// dials the server only once it has the RDCleanPath request, and that
	// waits for the read below: a person whose server shows another
	// certificate is told so before anything reaches the server and before a
	// password goes there. The proxy would refuse it on its own TLS anyway.
	changed := make(chan bool, 1)
	go func() { changed <- l.serverShowsAnother(ctx, target) }()
	forward, e := rdcleanpath.Forward(request.X224)
	if e != nil {
		return
	}
	// The stored credential's rules. A desktop's lease holds a password only
	// (compatible, at redeem), which derives nothing, so a desktop takes no
	// derivation slot and never waits behind someone's sign-in.
	e = validateCredential(&credential)
	if e != nil || ctx.Err() != nil {
		return
	}
	setupTimer := time.AfterFunc(10*time.Second, func() { lease.cancel(nil) })
	stream, e := browser.OpenBrowserRDP(ctx, RDPRequest{Target: target.Target, Certificate: append([]byte(nil), target.Identity...),
		Username: credential.Username, Password: credential.Secret})
	setupTimer.Stop()
	if e != nil && stream != nil {
		_ = stream.Close()
		stream = nil
	}
	// The read's answer is told first, whether or not the proxy started: a
	// server showing another certificate is the reason the person needs.
	other := false
	select {
	case other = <-changed:
	case <-ctx.Done():
	}
	if other || stream == nil || ctx.Err() != nil {
		if stream != nil {
			_ = stream.Close()
		}
		if other {
			_ = socket.Close(terminalweb.CloseIdentityChanged, "identity-changed")
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
