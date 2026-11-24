package identity

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

// RemoteTarget is trusted operator approval, not browser/discovered input.
// The copied identity and guarded immutable target cannot be changed by a
// connection row. ID must be a stable random 128-bit lowercase hex identifier.
type RemoteTarget struct {
	ID, Name, Protocol string
	Target             *targetguard.NamedTarget
	Identity           []byte // SSH wire public key or RDP approved leaf DER
}

// RDPWorker is a TRUSTED launcher boundary, not an extension/plugin surface.
// It opens a desktop whose RDP client runs in the browser (ADR 0008,
// docs/BROWSER-RDP-PAGE.md) through Keybash's RDP proxy, with the stored
// credential and the approved certificate. Implementations must enforce the
// supplied pin on the proxy's own TLS before CredSSP and bind the proxy's
// revocation to ctx. No fallback or separate TLS probe authority is enabled.
type RDPWorker interface {
	OpenBrowserRDP(context.Context, RDPRequest) (terminalweb.MessageStream, error)
}

// SSHWorker receives exactly one session credential: a key or a password.
type SSHWorker interface {
	OpenSSH(context.Context, *targetguard.NamedTarget, []byte, string, sshkey.Credential) (terminalweb.Stream, error)
}
type RDPRequest struct {
	Target             *targetguard.NamedTarget
	Certificate        []byte
	Username, Password string
}

func (RDPRequest) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[authorized RDP request redacted]")
}

type remoteConfig struct {
	limits  sessionlimits.Limits
	sockets map[string]int
	ssh     SSHWorker
	// targets is every server a lease can reach, rebuilt from the store on
	// each change (reloadServersLocked); accounts says who may use each
	// server's accounts, by account ID.
	targets             map[string]RemoteTarget
	accounts            map[string]accountInfo
	unchecked           map[string]bool // RDP servers pinned without the console check
	networks, protected []netip.Prefix  // see TargetNetworks
	scan                func(context.Context, *targetguard.NamedTarget) (ssh.PublicKey, error)
	scanRDP             func(context.Context, *targetguard.NamedTarget) (*x509.Certificate, error)
	scans               int               // running now
	watching            bool              // see WatchCertificates
	seen                map[string]string // fingerprint each RDP server last showed
	rdp                 RDPWorker
	leases              map[[32]byte]*remoteLease
	// desktopEnds is when the last desktop to each server and Windows
	// account ended; desktopSettle how long the next one waits after it
	// (see settleDesktopLocked).
	desktopEnds   map[string]time.Time
	desktopSettle time.Duration
}

// desktopSettle is how long Windows needs after a desktop to one account
// ends before it starts the next one's picture. Measured on 2026-11-22
// against Windows Server 2025: a desktop opened 0.3 s after the last one
// ended got "Connected" and no picture; one opened 0.8 s after drew.
const desktopSettle = 1500 * time.Millisecond

// settleDesktopLocked says how long a desktop to key must wait for the last
// one to settle, and forgets ends that have settled.
func (c *remoteConfig) settleDesktopLocked(key string, now time.Time) time.Duration {
	for k, ended := range c.desktopEnds {
		if now.Sub(ended) >= c.desktopSettle {
			delete(c.desktopEnds, k)
		}
	}
	if ended, ok := c.desktopEnds[key]; ok {
		return c.desktopSettle - now.Sub(ended)
	}
	return 0
}

// desktopKey names a server and a Windows account; Windows' user names
// ignore case.
func desktopKey(target, username string) string {
	return target + "\x00" + strings.ToLower(username)
}

// remoteLease is one person's way through one account (ADR 0010), bound when
// granted to the account's generation and the server's approval.
type remoteLease struct {
	session                          [32]byte
	owner, account, target, approval string // target: the account's server; approval: its identity when granted
	generation                       uint64
	expires                          time.Time
	active                           bool
	cancel                           context.CancelCauseFunc // the cause is a terminalweb.Reason the page can show
}

// NewRemoteLab adds ownership authorization to the existing loopback TLS lab.
// Stock SSH uses the guarded/pinned connector. A nil RDP launcher refuses RDP.
// targets are the operator's server file: each moves into the store's server
// list once (importServers). From then on every server is managed on the
// Servers page and reached only through its accounts, by the people each
// lists. Restart kills every pending and active lease. Production isolation and audit
// remain gates.
func NewRemoteLab(origin string, store *Store, targets []RemoteTarget, worker SSHWorker, rdp RDPWorker, options ...Option) (*Lab, error) {
	return NewRemoteLabWithLimits(origin, store, targets, worker, rdp, sessionlimits.Default(), options...)
}

// NewRemoteLabWithLimits copies an administrator-selected immutable capacity.
// Browser requests cannot change it; restart revokes old sessions and leases.
func NewRemoteLabWithLimits(origin string, store *Store, targets []RemoteTarget, worker SSHWorker, rdp RDPWorker, limits sessionlimits.Limits, options ...Option) (*Lab, error) {
	if !limits.Valid() || len(targets) > 256 {
		return nil, errRefused
	}
	config := &remoteConfig{limits: limits, targets: make(map[string]RemoteTarget), sockets: make(map[string]int), ssh: worker, rdp: rdp, leases: make(map[[32]byte]*remoteLease), scan: scanHostKey, scanRDP: scanCertificate, seen: make(map[string]string),
		desktopEnds: make(map[string]time.Time), desktopSettle: desktopSettle}
	seen := make(map[string]bool, len(targets))
	var addresses []netip.Addr
	for _, t := range targets {
		if !validID(t.ID) || !label(t.Name, 160, false) || t.Target == nil || t.Target.Hostname() == "" || seen[t.ID] {
			return nil, errRefused
		}
		switch t.Protocol {
		case "ssh":
			if len(t.Identity) == 0 || len(t.Identity) > 256 {
				return nil, errRefused
			}
			key, e := ssh.ParsePublicKey(t.Identity)
			if worker == nil || e != nil || key.Type() != ssh.KeyAlgoED25519 || len(t.Identity) > 256 {
				return nil, errRefused
			}
		case "rdp":
			if rdp == nil || len(t.Identity) == 0 || len(t.Identity) > 32*1024 {
				return nil, errRefused
			}
			cert, e := x509.ParseCertificate(t.Identity)
			// An expired or not yet valid certificate still loads; usableTarget
			// keeps only this server unavailable until the operator replaces it.
			if e != nil || cert.VerifyHostname(t.Target.Hostname()) != nil {
				return nil, errRefused
			}
		default:
			return nil, errRefused
		}
		seen[t.ID] = true
		for _, value := range t.Target.Snapshot().Addresses {
			if addr, e := netip.ParseAddr(value); e == nil {
				addresses = append(addresses, addr)
			}
		}
	}
	l, e := NewPersistent(origin, store, options...)
	if e != nil {
		return nil, e
	}
	// The file's servers move into the list before anything is served; a
	// start that cannot move them does not start.
	if store.importServers(targets, time.Now()) != nil {
		_ = l.Close()
		return nil, errRefused
	}
	l.mu.Lock()
	// Without target networks the gateway reaches exactly the file's servers,
	// as an install that names none does.
	config.networks, config.protected = l.networks, l.protected
	if config.networks == nil {
		config.networks = targetguard.HostNetworks(addresses)
	}
	l.remote = config
	// A store whose servers cannot be read starts with none.
	_ = l.reloadServersLocked()
	config.watching = l.watchEvery > 0 && rdp != nil
	if config.watching {
		l.background.Add(1)
		go l.certificateWatch(l.watchEvery)
	}
	l.mu.Unlock()
	return l, nil
}
func (l *Lab) sweepRemotesLocked() {
	if l.remote == nil {
		return
	}
	for key, lease := range l.remote.leases {
		s := l.sessions[lease.session]
		if l.closed || s == nil || s.stage != "ready" || !lease.active && !l.now().Before(lease.expires) {
			if lease.cancel != nil {
				// An ended sign-in already gave its own cause, which this keeps.
				var cause error = terminalweb.ReasonSignedOut
				if l.closed {
					cause = nil
				}
				lease.cancel(cause)
			}
			delete(l.remote.leases, key)
		}
	}
}

// issueLeaseLocked stores a one-use lease for s within the capacity limits
// and returns its token. It expires in 30 seconds.
func (l *Lab) issueLeaseLocked(s *session, lease *remoteLease) (string, error) {
	count := 0
	for _, other := range l.remote.leases {
		if other.owner == s.owner {
			count++
		}
	}
	if count >= l.remote.limits.PerOwner || len(l.remote.leases) >= l.remote.limits.Total {
		return "", errRemoteCapacity
	}
	raw, e := token()
	if e != nil {
		return "", e
	}
	key, _ := tokenID(raw)
	if l.remote.leases[key] != nil {
		return "", errRefused
	}
	lease.expires = l.now().Add(30 * time.Second)
	l.remote.leases[key] = lease
	s.last = l.now()
	return raw, nil
}

// Caller holds l.mu. Consume before starting any parser/dial/worker, including
// failed setup. Another browser/account cannot consume or use this capability.
func (l *Lab) redeemRemoteLocked(id [32]byte, raw string) (*remoteLease, RemoteTarget, Credential, context.Context, error) {
	key, ok := tokenID(raw)
	s := l.readyLocked(id, false)
	if !ok || s == nil || l.remote == nil || !l.serversLocked(s) {
		return nil, RemoteTarget{}, Credential{}, nil, errRefused
	}
	lease := l.remote.leases[key]
	if lease == nil || lease.active || lease.session != id || lease.owner != s.owner || !l.now().Before(lease.expires) {
		return nil, RemoteTarget{}, Credential{}, nil, errRefused
	}
	target, account, ok := l.accountLocked(s, lease.account)
	if !ok || target.ID != lease.target || approvalFingerprint(target) != lease.approval || account.Generation != lease.generation {
		return nil, RemoteTarget{}, Credential{}, nil, errRefused
	}
	ctx, cancel := context.WithCancelCause(s.ctx)
	lease.active, lease.cancel = true, cancel
	return lease, target, account.Current, ctx, nil
}

// openTerminal opens an SSH terminal in a bounded setup slot, with the stored
// credential under its own rules. Desktops open on their own socket
// (remoteDesktop), never here.
func (l *Lab) openTerminal(ctx context.Context, t RemoteTarget, c Credential) (terminalweb.Stream, error) {
	if t.Protocol != "ssh" || l.remote.ssh == nil || ctx.Err() != nil || !l.slot(ctx) {
		return nil, errRefused
	}
	// The key is opened once: checkCredential's own check hands it over.
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
	return l.remote.ssh.OpenSSH(ctx, t.Target, t.Identity, c.Username, auth)
}
func (l *Lab) remoteSocket(w http.ResponseWriter, r *http.Request) {
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
	l.mu.Unlock()
	if e != nil {
		return
	}
	key, _ := tokenID(raw)
	// This socket is for terminals. A desktop's lease is used up here without
	// starting anything; a desktop opens only on its own socket.
	defer func() { lease.cancel(nil); l.mu.Lock(); delete(l.remote.leases, key); l.mu.Unlock() }()
	if target.Protocol != "ssh" {
		return
	}
	stopRequest := context.AfterFunc(r.Context(), func() { lease.cancel(nil) })
	defer stopRequest()
	stopSocket := context.AfterFunc(ctx, func() { _ = socket.CloseNow() })
	defer stopSocket()
	setupTimer := time.AfterFunc(10*time.Second, func() { lease.cancel(nil) })
	stream, e := l.openTerminal(ctx, target, credential)
	setupTimer.Stop()
	if e != nil || stream == nil || ctx.Err() != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return
	}
	// An SSH stream exists only after the server took the key and opened a
	// terminal, so a key made here is now known to be on a server.
	if credential.Generated && !credential.Used {
		_ = l.store.markAccountUsed(lease.target, lease.account, credential.Fingerprint)
	}
	if socket.Write(ctx, websocket.MessageText, []byte(`{"type":"ready"}`)) != nil {
		_ = stream.Close()
		return
	}
	// From here Relay closes the socket when ctx ends, after saying why;
	// closing it at once here would leave the page with no reason.
	stopOwner()
	stopSocket()
	terminalweb.Relay(ctx, socket, &remoteActivity{Stream: stream, l: l, id: id, ctx: ctx})
}

// Reason passes on why the stream ended by itself, when it can say.
func (s *remoteActivity) Reason() terminalweb.Reason {
	if r, ok := s.Stream.(terminalweb.Reasoned); ok {
		return r.Reason()
	}
	return ""
}

// remoteActivity is a terminal's stream: what the person types keeps the
// sign-in alive, once the terminal took it.
type remoteActivity struct {
	ctx context.Context
	terminalweb.Stream
	l  *Lab
	id [32]byte
}

func (s *remoteActivity) Write(p []byte) (int, error) {
	s.l.mu.Lock()
	live := s.ctx.Err() == nil && s.l.readyLocked(s.id, false) != nil
	s.l.mu.Unlock()
	if !live {
		return 0, errRefused
	}
	n, e := s.Stream.Write(p)
	// A terminal's input is the person's own, an opaque stream; only what the
	// terminal took counts. A desktop's activity is its fast-path input alone
	// (fastPathInput).
	if e == nil && n == len(p) && len(p) > 0 {
		s.l.mu.Lock()
		if s.ctx.Err() == nil && s.l.readyLocked(s.id, false) != nil {
			s.l.sessions[s.id].last = s.l.now()
		}
		s.l.mu.Unlock()
	}
	return n, e
}
func (s *remoteActivity) Resize(c, r uint32) error {
	s.l.mu.Lock()
	live := s.ctx.Err() == nil && s.l.readyLocked(s.id, false) != nil
	s.l.mu.Unlock()
	if !live {
		return errRefused
	}
	return s.Stream.Resize(c, r)
}

// Returns with the session mutex RELEASED on every path.
func (l *Lab) remoteHTTP(w http.ResponseWriter, r *http.Request, id [32]byte, s *session) {
	status := 204
	var result any
	defer func() {
		l.mu.Unlock()
		if result != nil {
			jsonReply(w, result)
		} else if status == 204 {
			w.WriteHeader(204)
		} else if status == 429 {
			identityError(w, errLimited)
		} else {
			refuse(w, status)
		}
	}()
	if l.remote == nil {
		status = 503
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/remote/capacity" {
		result = l.remote.limits // configured values only; no other owners' usage
		return
	}
	// The servers this person reaches, one card per account (ADR 0010).
	if r.Method == "GET" && r.URL.Path == "/api/access" {
		result = l.accessLocked(s)
		return
	}
	// Opening one needs only the ready session (see grantRemoteLocked): the
	// administrator confirmed the server's identity when adding it.
	if r.Method == "POST" && r.URL.Path == "/api/remote/open" {
		fields, ok := readFields(w, r, 1024, "account")
		if !ok {
			status = 400
			return
		}
		raw, e := l.grantRemoteLocked(id, fields["account"])
		clear(fields)
		if e != nil {
			status = 401
			if e == errRemoteCapacity {
				markRemoteCapacity(w)
				status = 503
			}
			if e == errLimited {
				status = 429
			}
			return
		}
		result = struct {
			Lease string `json:"lease"`
		}{raw}
		return
	}
	status = 404
}
