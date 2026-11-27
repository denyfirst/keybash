package identity

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	bolt "go.etcd.io/bbolt"
)

// FilesWorker opens a Files session (ADR 0011) with the same pin and
// credential a terminal uses. The SSH worker implements it; a launcher
// without it never offers Files.
type FilesWorker interface {
	OpenFiles(context.Context, *targetguard.NamedTarget, []byte, string, sshkey.Credential, terminalweb.FilesMode) (terminalweb.FilesStream, error)
}

// validFilesSetting is a server's file transfer switch: off ("") for any
// server, and download or both only for SSH.
func validFilesSetting(protocol, files string) bool {
	return files == "" || protocol == "ssh" && terminalweb.ValidFilesMode(terminalweb.FilesMode(files))
}

// setServerFiles turns file transfer off ("") or to download or both.
func (s *Store) setServerFiles(actor, id, files string) error {
	return s.editServer(actor, id, func(_ *bolt.Tx, w *webServer) error {
		if !validFilesSetting(w.Protocol, files) {
			return errRefused
		}
		w.Files = files
		return nil
	})
}

// filesModeLocked is what the account's server allows now, or "".
func (l *Lab) filesModeLocked(account string) terminalweb.FilesMode {
	info, ok := l.remote.accounts[account]
	if !ok || info.protocol != "ssh" || !terminalweb.ValidFilesMode(terminalweb.FilesMode(info.files)) {
		return ""
	}
	return terminalweb.FilesMode(info.files)
}

// grantFilesLocked is grantRemoteLocked for a Files session: the same ready
// sign-in, rate, account and capacity, and only while the server allows
// files. The lease keeps the mode it was granted with.
func (l *Lab) grantFilesLocked(id [32]byte, account string) (string, terminalweb.FilesMode, error) {
	s := l.readyLocked(id, false)
	if s == nil || l.remote == nil || !l.serversLocked(s) || !validID(account) {
		return "", "", errRefused
	}
	if _, ok := l.remote.ssh.(FilesWorker); !ok {
		return "", "", errRefused
	}
	if !l.attemptLocked("remote:"+s.username, remoteAttempts) {
		return "", "", errLimited
	}
	l.sweepRemotesLocked()
	t, a, ok := l.accountLocked(s, account)
	mode := l.filesModeLocked(account)
	if !ok || t.Protocol != "ssh" || mode == "" {
		return "", "", errRefused
	}
	raw, e := l.issueLeaseLocked(s, &remoteLease{session: id, owner: s.owner, account: account, target: t.ID, approval: approvalFingerprint(t), generation: a.Generation, files: mode})
	return raw, mode, e
}

// openFiles opens a Files session in a bounded setup slot, as openTerminal
// opens a terminal.
func (l *Lab) openFiles(ctx context.Context, t RemoteTarget, c Credential, mode terminalweb.FilesMode) (terminalweb.FilesStream, error) {
	worker, ok := l.remote.ssh.(FilesWorker)
	if !ok || t.Protocol != "ssh" || ctx.Err() != nil || !l.slot(ctx) {
		return nil, errRefused
	}
	key, e := checkCredential(&c)
	var auth sshkey.Credential
	if e == nil {
		if c.Kind == "password" {
			auth, e = sshkey.NewPassword(c.Secret)
		} else {
			auth = key
		}
		if e == nil {
			defer auth.Close()
		}
	}
	<-l.derive
	if e != nil || ctx.Err() != nil {
		return nil, errRefused
	}
	return worker.OpenFiles(ctx, t.Target, t.Identity, c.Username, auth, mode)
}

// remoteFilesSocket is a Files session's socket. It takes only a Files
// lease, checks the server still allows the mode the lease was granted
// with, and then relays (terminalweb.FilesRelay), which checks every
// operation again.
func (l *Lab) remoteFilesSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.Header.Get("Origin") != l.origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		refuse(w, 403)
		return
	}
	id, ok := tokenID(requestToken(r))
	l.mu.Lock()
	s := l.readyLocked(id, false)
	allowed := ok && s != nil && l.remote != nil && l.serversLocked(s)
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
	socket.SetReadLimit(1024)
	first, stop := context.WithTimeout(r.Context(), 5*time.Second)
	kind, data, e := socket.Read(first)
	stop()
	if e != nil || kind != websocket.MessageText {
		return
	}
	fields, ok := parseFields(data, 1024, "csrf", "lease")
	clear(data)
	if !ok {
		return
	}
	l.mu.Lock()
	if subtle.ConstantTimeCompare([]byte(fields["csrf"]), []byte(l.csrf(id))) != 1 {
		l.mu.Unlock()
		return
	}
	lease, target, credential, ctx, e := l.redeemRemoteLocked(id, fields["lease"])
	raw := fields["lease"]
	clear(fields)
	var mode terminalweb.FilesMode
	if e == nil {
		mode = l.filesModeLocked(lease.account)
	}
	l.mu.Unlock()
	if e != nil {
		return
	}
	key, _ := tokenID(raw)
	defer func() { lease.cancel(nil); l.mu.Lock(); delete(l.remote.leases, key); l.mu.Unlock() }()
	// A terminal's lease is used up here without starting anything, and a
	// Files lease opens only what the server still allows.
	if target.Protocol != "ssh" || lease.files == "" || mode != lease.files {
		return
	}
	stopRequest := context.AfterFunc(r.Context(), func() { lease.cancel(nil) })
	defer stopRequest()
	stopSocket := context.AfterFunc(ctx, func() { _ = socket.CloseNow() })
	defer stopSocket()
	setupTimer := time.AfterFunc(10*time.Second, func() { lease.cancel(nil) })
	stream, e := l.openFiles(ctx, target, credential, mode)
	setupTimer.Stop()
	if e != nil || stream == nil || ctx.Err() != nil {
		if stream != nil {
			_ = stream.Close()
		}
		var reason terminalweb.Reason
		if errors.As(e, &reason) && (reason == terminalweb.ReasonKey || reason == terminalweb.ReasonCredentials) && ctx.Err() == nil {
			say, done := context.WithTimeout(ctx, time.Second)
			_ = socket.Write(say, websocket.MessageText, []byte(`{"type":"ended","reason":"`+string(reason)+`"}`))
			done()
		}
		return
	}
	if credential.Generated && !credential.Used {
		_ = l.store.markAccountUsed(lease.target, lease.account, credential.Fingerprint)
	}
	l.mu.Lock()
	info := l.remote.accounts[lease.account]
	l.mu.Unlock()
	ready, _ := json.Marshal(map[string]string{"type": "ready", "mode": string(mode), "server": info.name, "account": info.username, "host": target.Target.Hostname()})
	if socket.Write(ctx, websocket.MessageText, ready) != nil {
		_ = stream.Close()
		return
	}
	stopOwner()
	stopSocket()
	// Each operation and each upload chunk keeps the sign-in alive, and ends
	// the session when the sign-in is no longer ready.
	activity := func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if ctx.Err() != nil || l.readyLocked(id, false) == nil {
			return errRefused
		}
		l.sessions[id].last = l.now()
		return nil
	}
	terminalweb.FilesRelay(ctx, socket, stream, mode, activity)
}
