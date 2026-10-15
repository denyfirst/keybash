package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
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

func approvalFingerprint(t RemoteTarget) string {
	digest := sha256.Sum256(append([]byte("keybash/approval/v1/"+t.ID+"/"+t.Protocol+"/"+t.Target.Hostname()+"/"), t.Identity...))
	return hex.EncodeToString(digest[:])
}

// RDPWorker is a TRUSTED launcher boundary, not an extension/plugin surface.
// Implementations must enforce the supplied pin on the worker's own TLS before
// CredSSP and bind guarded broker/process revocation to ctx. The shipped CLI
// does not supply a launcher: the native isolated implementation remains a CI
// lab. No fallback, separate TLS probe authority or bare guacd dial is enabled.
type RDPWorker interface {
	OpenRDP(context.Context, RDPRequest) (terminalweb.Stream, error)
}
type SSHWorker interface {
	OpenSSH(context.Context, *targetguard.NamedTarget, []byte, string, ssh.Signer) (terminalweb.Stream, error)
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
	sockets map[string]int
	ssh     SSHWorker
	targets map[string]RemoteTarget
	rdp     RDPWorker
	leases  map[[32]byte]*remoteLease
}
type remoteLease struct {
	session                               [32]byte
	owner, connection, credential, target string
	expires                               time.Time
	active                                bool
	cancel                                context.CancelFunc
}

// NewRemoteLab adds ownership authorization to the existing loopback TLS lab.
// Stock SSH uses the guarded/pinned connector. A nil RDP launcher refuses RDP.
// Targets are immutable for this process; restart kills every pending/active
// lease. Production isolation, operator configuration and audit remain gates.
func NewRemoteLab(origin string, store *Store, targets []RemoteTarget, worker SSHWorker, rdp RDPWorker) (*Lab, error) {
	if len(targets) == 0 || len(targets) > 256 {
		return nil, errRefused
	}
	config := &remoteConfig{targets: make(map[string]RemoteTarget), sockets: make(map[string]int), ssh: worker, rdp: rdp, leases: make(map[[32]byte]*remoteLease)}
	for _, t := range targets {
		if !validID(t.ID) || !label(t.Name, 160, false) || t.Target == nil || t.Target.Hostname() == "" || config.targets[t.ID].ID != "" {
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
			if e != nil || cert.VerifyHostname(t.Target.Hostname()) != nil || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
				return nil, errRefused
			}
		default:
			return nil, errRefused
		}
		t.Identity = append([]byte(nil), t.Identity...)
		config.targets[t.ID] = t
	}
	l, e := NewPersistent(origin, store)
	if e != nil {
		return nil, e
	}
	l.mu.Lock()
	l.remote = config
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
				lease.cancel()
			}
			delete(l.remote.leases, key)
		}
	}
}
func (l *Lab) revokeRemotesLocked(owner, connection, credential string) {
	if l.remote == nil {
		return
	}
	for key, lease := range l.remote.leases {
		if lease.owner == owner && (connection != "" && lease.connection == connection || credential != "" && lease.credential == credential) {
			if lease.cancel != nil {
				lease.cancel()
			}
			delete(l.remote.leases, key)
		}
	}
}
func compatible(t RemoteTarget, c Credential) bool {
	return c.Username != "" && (t.Protocol == "ssh" && c.Kind == "ssh-key" || t.Protocol == "rdp" && c.Kind == "password")
}
func (l *Lab) grantRemoteLocked(id [32]byte, record string) (string, error) {
	s := l.readyLocked(id, true)
	if s == nil || l.remote == nil || !l.attemptLocked("remote:"+s.username) {
		return "", errRefused
	}
	l.sweepRemotesLocked()
	c, e := l.store.readConnection(s.owner, record)
	if e != nil {
		return "", errRefused
	}
	t, ok := l.remote.targets[c.Target]
	if !ok || c.Approval != approvalFingerprint(t) {
		return "", errRefused
	}
	credential, e := l.store.readCredential(s.owner, c.Credential)
	if e != nil || !compatible(t, credential) {
		return "", errRefused
	}
	count := 0
	for _, lease := range l.remote.leases {
		if lease.owner == s.owner {
			count++
		}
	}
	if count >= 2 || len(l.remote.leases) >= 8 {
		return "", errLimited
	}
	raw, e := token()
	if e != nil {
		return "", e
	}
	key, _ := tokenID(raw)
	if l.remote.leases[key] != nil {
		return "", errRefused
	}
	l.remote.leases[key] = &remoteLease{session: id, owner: s.owner, connection: record, credential: c.Credential, target: c.Target, expires: l.now().Add(30 * time.Second)}
	s.last = l.now()
	return raw, nil
}

// Caller holds l.mu. Consume before starting any parser/dial/worker, including
// failed setup. Another browser/account cannot consume or use this capability.
func (l *Lab) redeemRemoteLocked(id [32]byte, raw string) (*remoteLease, RemoteTarget, Credential, context.Context, error) {
	key, ok := tokenID(raw)
	s := l.readyLocked(id, true)
	if !ok || s == nil || l.remote == nil {
		return nil, RemoteTarget{}, Credential{}, nil, errRefused
	}
	lease := l.remote.leases[key]
	if lease == nil || lease.active || lease.session != id || lease.owner != s.owner || !l.now().Before(lease.expires) {
		return nil, RemoteTarget{}, Credential{}, nil, errRefused
	}
	c, e := l.store.readConnection(s.owner, lease.connection)
	if e != nil || c.Credential != lease.credential || c.Target != lease.target {
		return nil, RemoteTarget{}, Credential{}, nil, errRefused
	}
	target, ok := l.remote.targets[c.Target]
	if !ok || c.Approval != approvalFingerprint(target) {
		return nil, RemoteTarget{}, Credential{}, nil, errRefused
	}
	credential, e := l.store.readCredential(s.owner, c.Credential)
	if e != nil || !compatible(target, credential) {
		return nil, RemoteTarget{}, Credential{}, nil, errRefused
	}
	ctx, cancel := context.WithCancel(s.ctx)
	lease.active, lease.cancel = true, cancel
	return lease, target, credential, ctx, nil
}
func (l *Lab) openRemote(ctx context.Context, t RemoteTarget, c Credential) (terminalweb.Stream, error) {
	if ctx.Err() != nil || !l.slot(ctx) {
		return nil, errRefused
	}
	e := validateCredential(&c)
	var signer ssh.Signer
	if e == nil && t.Protocol == "ssh" {
		if c.Passphrase == "" {
			signer, e = ssh.ParsePrivateKey([]byte(c.Secret))
		} else {
			signer, e = ssh.ParsePrivateKeyWithPassphrase([]byte(c.Secret), []byte(c.Passphrase))
		}
	}
	<-l.derive
	if e != nil || ctx.Err() != nil {
		return nil, errRefused
	}
	if t.Protocol == "ssh" {
		return l.remote.ssh.OpenSSH(ctx, t.Target, t.Identity, c.Username, signer)
	}
	return l.remote.rdp.OpenRDP(ctx, RDPRequest{t.Target, append([]byte(nil), t.Identity...), c.Username, c.Secret})
}
func (l *Lab) remoteSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.Header.Get("Origin") != l.origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		refuse(w, 403)
		return
	}
	id, ok := tokenID(requestToken(r))
	l.mu.Lock()
	s := l.readyLocked(id, true)
	allowed := ok && s != nil && l.remote != nil
	if allowed {
		total := 0
		for _, count := range l.remote.sockets {
			total += count
		}
		allowed = l.remote.sockets[s.owner] < 2 && total < 8
		if allowed {
			l.remote.sockets[s.owner]++
		}
	}
	l.mu.Unlock()
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
	defer func() { lease.cancel(); l.mu.Lock(); delete(l.remote.leases, key); l.mu.Unlock() }()
	stopRequest := context.AfterFunc(r.Context(), lease.cancel)
	defer stopRequest()
	stopSocket := context.AfterFunc(ctx, func() { _ = socket.CloseNow() })
	defer stopSocket()
	setupTimer := time.AfterFunc(10*time.Second, lease.cancel)
	stream, e := l.openRemote(ctx, target, credential)
	setupTimer.Stop()
	if e != nil || stream == nil || ctx.Err() != nil {
		if stream != nil {
			_ = stream.Close()
		}
		return
	}
	if socket.Write(ctx, websocket.MessageText, []byte(`{"type":"ready"}`)) != nil {
		_ = stream.Close()
		return
	}
	terminalweb.Relay(ctx, socket, &remoteActivity{Stream: stream, l: l, id: id, ctx: ctx})
}

type remoteActivity struct {
	ctx context.Context
	terminalweb.Stream
	l  *Lab
	id [32]byte
}

func (s *remoteActivity) Write(p []byte) (int, error) {
	s.l.mu.Lock()
	live := s.ctx.Err() == nil && s.l.readyLocked(s.id, false) != nil
	if live && len(p) > 0 {
		s.l.sessions[s.id].last = s.l.now()
	}
	s.l.mu.Unlock()
	if !live {
		return 0, errRefused
	}
	return s.Stream.Write(p)
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
	if r.Method == "GET" && r.URL.Path == "/api/targets" {
		type summary struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Protocol string `json:"protocol"`
		}
		items := make([]summary, 0, len(l.remote.targets))
		for _, t := range l.remote.targets {
			items = append(items, summary{t.ID, t.Name, t.Protocol})
		}
		result = items
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/connections" {
		items, e := l.store.listConnections(s.owner)
		if e != nil {
			status = 503
			return
		}
		result = items
		return
	}
	if l.readyLocked(id, true) != s {
		status = 403
		return
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/api/connections":
		fields, ok := readFields(w, r, 2048, "name", "target", "credential")
		if !ok {
			status = 400
			return
		}
		defer clear(fields)
		target, ok := l.remote.targets[fields["target"]]
		if !ok {
			status = 403
			return
		}
		credential, e := l.store.readCredential(s.owner, fields["credential"])
		if e != nil || !compatible(target, credential) {
			status = 403
			return
		}
		record, e := l.store.putConnection(s.owner, connection{Name: fields["name"], Target: fields["target"], Credential: fields["credential"], Approval: approvalFingerprint(target)})
		if e != nil {
			status = 400
			return
		}
		result = struct {
			ID string `json:"id"`
		}{record}
	case r.Method == "POST" && r.URL.Path == "/api/remote/open":
		fields, ok := readFields(w, r, 1024, "connection")
		if !ok {
			status = 400
			return
		}
		raw, e := l.grantRemoteLocked(id, fields["connection"])
		clear(fields)
		if e != nil {
			status = 401
			if e == errLimited {
				status = 429
			}
			return
		}
		result = struct {
			Lease string `json:"lease"`
		}{raw}
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/connections/"):
		record := strings.TrimPrefix(r.URL.Path, "/api/connections/")
		if _, ok := readFields(w, r, 1024); !ok || !validID(record) {
			status = 400
			return
		}
		if l.store.deleteConnection(s.owner, record) != nil {
			status = 404
			return
		}
		l.revokeRemotesLocked(s.owner, record, "")
		status = 204
	default:
		status = 404
	}
}
