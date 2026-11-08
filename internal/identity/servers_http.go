package identity

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/denyfirst/keybash/internal/rdpcert"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

const (
	serverAttempts = 20 // server changes and scans per administrator and minute
	scanAttempts   = 10 // identity scans per administrator and minute
	maxScans       = 2  // scans running at once in the whole gateway
	// uncheckedPrint stands in an RDP server's fingerprint field when an
	// administrator adds or accepts it without the console check. It is never
	// a fingerprint, so neither can be taken for the other.
	uncheckedPrint = "unchecked"
)

// TargetNetworks names the networks root lets the gateway reach (its unit's
// --target-networks, which the kernel enforces as well) and the protected
// networks it must never reach. Administrators add servers from the web only
// inside the first and outside the second; without this option, nowhere.
func TargetNetworks(networks, protected []netip.Prefix) Option {
	return func(l *Lab) error {
		checked, e := targetguard.ParseNetworks(targetguard.JoinNetworks(networks), protected)
		if e != nil || len(protected) > 64 || l.networks != nil {
			return errRefused
		}
		for _, prefix := range protected {
			if !prefix.IsValid() || prefix.Masked() != prefix || prefix.Addr().Is4In6() {
				return errRefused
			}
		}
		l.networks, l.protected = checked, slices.Clone(protected)
		return nil
	}
}

// guardedTarget is the target guard's approval of one literal endpoint inside
// the target networks, or false.
func guardedTarget(endpoint netip.AddrPort, networks, protected []netip.Prefix) (*targetguard.NamedTarget, bool) {
	if !targetguard.Within(networks, endpoint.Addr()) {
		return nil, false
	}
	policy, e := targetguard.New([]netip.AddrPort{endpoint}, protected)
	if e != nil {
		return nil, false
	}
	target, e := targetguard.NewAddressTarget(policy, endpoint.Addr(), endpoint.Port())
	return target, e == nil
}

// listedLocked reports whether a reachable server already answers at endpoint.
func (l *Lab) listedLocked(endpoint netip.AddrPort) bool {
	for _, t := range l.remote.targets {
		snapshot := t.Target.Snapshot()
		if snapshot.Port == endpoint.Port() && slices.Contains(snapshot.Addresses, endpoint.Addr().String()) {
			return true
		}
	}
	return false
}

// webTargetLocked makes a listed server dialable: every address inside the
// target networks and outside every address the guard refuses, and a worker
// for its protocol. Otherwise it stays listed and nobody can reach it.
func (l *Lab) webTargetLocked(w webServer) (RemoteTarget, bool) {
	if w.Removed || w.Protocol == "ssh" && l.remote.ssh == nil || w.Protocol == "rdp" && l.remote.rdp == nil {
		return RemoteTarget{}, false
	}
	var target *targetguard.NamedTarget
	endpoints := w.endpoints()
	if w.Hostname == "" {
		var ok bool
		if target, ok = guardedTarget(endpoints[0], l.remote.networks, l.remote.protected); !ok {
			return RemoteTarget{}, false
		}
	} else {
		pins := make([]netip.Addr, 0, len(endpoints))
		for _, at := range endpoints {
			if !targetguard.Within(l.remote.networks, at.Addr()) {
				return RemoteTarget{}, false
			}
			pins = append(pins, at.Addr())
		}
		policy, e := targetguard.New(endpoints, l.remote.protected)
		if e != nil {
			return RemoteTarget{}, false
		}
		if target, e = targetguard.NewNamedTarget(policy, w.Hostname, w.Port, pins); e != nil {
			return RemoteTarget{}, false
		}
	}
	return RemoteTarget{ID: w.ID, Name: w.Name, Protocol: w.Protocol, Target: target, Identity: bytes.Clone(w.identity())}, true
}

// reloadServersLocked rebuilds the reachable servers from the store, then
// ends every lease whose owner may no longer use its server or whose server's
// identity changed since it was granted. A store whose servers cannot be read
// leaves none.
func (l *Lab) reloadServersLocked() error {
	list, e := l.store.listServers()
	if e != nil {
		list = nil
	}
	targets, access, unchecked := make(map[string]RemoteTarget), make(map[string]map[string]bool), make(map[string]bool)
	for _, w := range list {
		if t, ok := l.webTargetLocked(w); ok {
			targets[w.ID], access[w.ID] = t, make(map[string]bool, len(w.Access))
			for _, person := range w.Access {
				access[w.ID][person] = true
			}
			if w.Unchecked {
				unchecked[w.ID] = true
			}
		}
	}
	l.remote.targets, l.remote.access, l.remote.unchecked = targets, access, unchecked
	for id := range l.remote.seen {
		if _, listed := targets[id]; !listed {
			delete(l.remote.seen, id)
		}
	}
	for key, lease := range l.remote.leases {
		if t, ok := l.mayUseLocked(lease.owner, lease.target); !ok || approvalFingerprint(t) != lease.approval {
			if lease.cancel != nil {
				lease.cancel(terminalweb.ReasonAccessChanged)
			}
			delete(l.remote.leases, key)
		}
	}
	return e
}

// mayUseLocked is the server owner may connect to: a reachable server whose
// access list names owner. Administrators manage every server but connect
// only where they are listed.
func (l *Lab) mayUseLocked(owner, id string) (RemoteTarget, bool) {
	t, ok := l.remote.targets[id]
	if !ok || !l.remote.access[id][owner] {
		return RemoteTarget{}, false
	}
	return t, true
}

// targetLocked is mayUseLocked for a session that reaches servers at all.
func (l *Lab) targetLocked(s *session, id string) (RemoteTarget, bool) {
	if !l.serversLocked(s) {
		return RemoteTarget{}, false
	}
	return l.mayUseLocked(s.owner, id)
}

// serverView is one row of the Servers page: never a credential.
type serverView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	Hostname    string   `json:"hostname"`
	Port        uint16   `json:"port"`
	Addresses   []string `json:"addresses"`
	Fingerprint string   `json:"fingerprint"`
	Available   bool     `json:"available"`
	Certificate string   `json:"certificate,omitempty"` // RDP: see certificateStateLocked
	Expires     int64    `json:"expires,omitempty"`     // RDP: when the pinned certificate ends
	Unchecked   bool     `json:"unchecked,omitempty"`   // RDP: pinned without the console check
	Access      []string `json:"access"`                // who may use it
	AddedBy     string   `json:"added_by,omitempty"`    // empty when it came from the server file
	Added       int64    `json:"added"`
}
type serversView struct {
	Networks []string          `json:"networks"`
	Adding   bool              `json:"adding"` // the viewer administers, this installation serves a protocol and names target networks
	SSH      bool              `json:"ssh"`    // this installation serves SSH
	RDP      bool              `json:"rdp"`    // this installation serves RDP
	Servers  []serverView      `json:"servers"`
	Names    map[string]string `json:"names"` // username of everyone on a list, and of whoever added a server
}

// serversViewLocked is what an administrator manages and an auditor reads.
func (l *Lab) serversViewLocked(admin bool) (serversView, error) {
	list, e := l.store.listServers()
	if e != nil {
		return serversView{}, e
	}
	accounts, e := l.store.listAccounts(l.now())
	if e != nil {
		return serversView{}, e
	}
	view := serversView{Networks: make([]string, 0, len(l.remote.networks)), SSH: l.remote.ssh != nil, RDP: l.remote.rdp != nil,
		Servers: make([]serverView, 0, len(list)), Names: make(map[string]string)}
	view.Adding = admin && (view.SSH || view.RDP) && len(l.remote.networks) > 0
	for _, network := range l.remote.networks {
		view.Networks = append(view.Networks, network.String())
	}
	named := func(id string) {
		if i := slices.IndexFunc(accounts, func(a accountSummary) bool { return a.ID == id }); i >= 0 {
			view.Names[id] = accounts[i].Username
		}
	}
	for _, w := range list {
		if w.Removed {
			continue
		}
		_, reachable := l.remote.targets[w.ID]
		row := serverView{ID: w.ID, Name: w.Name, Protocol: w.Protocol, Hostname: w.Hostname, Port: w.Port, Addresses: slices.Clone(w.Pins),
			Fingerprint: identityFingerprint(RemoteTarget{Protocol: w.Protocol, Identity: w.identity()}), Available: reachable && usableTarget(l.remote.targets[w.ID], l.now()),
			Unchecked: w.Unchecked, Access: append([]string{}, w.Access...), AddedBy: w.AddedBy, Added: w.Added}
		row.Certificate, row.Expires = l.certificateStateLocked(w)
		if w.Hostname == "" {
			row.Hostname, row.Addresses = w.Address, []string{w.Address}
		}
		for _, id := range append(slices.Clone(w.Access), w.AddedBy) {
			named(id)
		}
		view.Servers = append(view.Servers, row)
	}
	slices.SortFunc(view.Servers, func(a, b serverView) int {
		if order := strings.Compare(a.Name, b.Name); order != 0 {
			return order
		}
		return strings.Compare(a.ID, b.ID)
	})
	return view, nil
}

func serverPort(value string) (uint16, bool) {
	n, e := strconv.ParseUint(value, 10, 16)
	return uint16(n), e == nil && n > 0 && strconv.FormatUint(n, 10) == value // #nosec G115 -- ParseUint's bit size 16 bounds n.
}

// serverProtocol reports a protocol a server on the page can use.
func serverProtocol(value string) bool { return value == "ssh" || value == "rdp" }

// newServerLocked checks where an administrator asks to add a server: a
// literal address and port, an installation that serves the protocol, inside
// the target networks and admitted by the guard, where no reachable server
// already answers. It returns the guarded target a scan dials, or the status
// to refuse with.
func (l *Lab) newServerLocked(protocol, address, port string) (*targetguard.NamedTarget, netip.AddrPort, int) {
	addr, addressOK := serverAddress(address)
	number, portOK := serverPort(port)
	endpoint := netip.AddrPortFrom(addr, number)
	if !addressOK || !portOK || !serverProtocol(protocol) {
		return nil, endpoint, 400
	}
	if protocol == "ssh" && l.remote.ssh == nil || protocol == "rdp" && l.remote.rdp == nil {
		return nil, endpoint, 409
	}
	target, ok := guardedTarget(endpoint, l.remote.networks, l.remote.protected)
	if !ok {
		return nil, endpoint, 403
	}
	if l.listedLocked(endpoint) {
		return nil, endpoint, 409
	}
	return target, endpoint, 0
}

// scanningLocked runs read with l.mu released, at most maxScans at once for the
// whole gateway, and returns with it held again: 0, or the status to refuse with.
func (l *Lab) scanningLocked(ctx context.Context, id [32]byte, s *session, read func()) int {
	if !l.attemptLocked("scan:"+s.username, scanAttempts) || l.remote.scans >= maxScans {
		return 429
	}
	l.remote.scans++
	l.mu.Unlock()
	read()
	l.mu.Lock()
	l.remote.scans--
	if l.closed || l.readyLocked(id, true) != s || ctx.Err() != nil {
		return 401
	}
	return 0
}

// scanLocked reads target's host key: the key, or the status to refuse with.
func (l *Lab) scanLocked(ctx context.Context, id [32]byte, s *session, target *targetguard.NamedTarget) (ssh.PublicKey, int) {
	var key ssh.PublicKey
	var e error
	scan := l.remote.scan
	if refused := l.scanningLocked(ctx, id, s, func() { key, e = scan(ctx, target) }); refused != 0 {
		return nil, refused
	}
	if e != nil || key == nil {
		return nil, 502
	}
	if _, ok := ed25519HostKey(key.Marshal()); !ok {
		return nil, 502
	}
	return key, 0
}

// scanCertificateLocked reads target's RDP certificate: the certificate, or the
// status to refuse with: 502 when nothing answered, 422 when an RDP server
// answered but cannot be used (it does not require NLA, or its handshake failed).
func (l *Lab) scanCertificateLocked(ctx context.Context, id [32]byte, s *session, target *targetguard.NamedTarget) (*x509.Certificate, int) {
	var cert *x509.Certificate
	var e error
	scan := l.remote.scanRDP
	if refused := l.scanningLocked(ctx, id, s, func() { cert, e = scan(ctx, target) }); refused != 0 {
		return nil, refused
	}
	switch {
	case errors.Is(e, rdpcert.ErrNegotiation), errors.Is(e, rdpcert.ErrIdentity):
		return nil, 422
	case e != nil || cert == nil:
		return nil, 502
	}
	return cert, 0
}

// serversHTTP is the Servers page's API, for a ready administrator only.
// Listing needs the ready session; every change and every scan also needs a
// factor proved within freshProof, as on the Users page. A scan dials only
// inside the target networks, through the target guard, and stops at the
// host key or the certificate. Adding or re-pinning scans again and stores what
// the server shows only if it is what the administrator compared. For RDP a
// scan never returns the fingerprint: the administrator brings it from the
// server's own console, so a change cannot be accepted without looking there.
// Returns with l.mu released.
func (l *Lab) serversHTTP(w http.ResponseWriter, r *http.Request, id [32]byte, s *session) {
	status := 204
	var result any
	defer func() {
		l.mu.Unlock()
		switch {
		case result != nil:
			jsonReply(w, result)
		case status == 204:
			w.WriteHeader(204)
		case status == 429:
			identityError(w, errLimited)
		default:
			refuse(w, status)
		}
	}()
	// An auditor reads the list; only an administrator changes it.
	role := l.roleLocked(s)
	if l.remote == nil || role != roleAdmin && (role != roleAuditor || r.URL.Path != "/api/servers" || r.Method != "GET") {
		status = 403
		return
	}
	if r.URL.Path == "/api/servers" && r.Method == "GET" {
		view, e := l.serversViewLocked(role == roleAdmin)
		if e != nil {
			status = 503
			return
		}
		result = view
		return
	}
	// "/api/servers" adds, "/api/servers/scan" reads a new server's identity;
	// "/api/servers/{id}" and "/api/servers/{id}/{action}" change one.
	var server, action string
	if rest := strings.TrimPrefix(r.URL.Path, "/api/servers"); rest == "" || rest == "/scan" {
		action = strings.TrimPrefix(rest, "/")
		if r.Method != "POST" {
			status = 404
			return
		}
	} else {
		parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
		if !strings.HasPrefix(rest, "/") || len(parts) > 2 || !validID(parts[0]) {
			status = 404
			return
		}
		server = parts[0]
		if len(parts) == 2 {
			action = parts[1]
		}
	}
	if l.readyLocked(id, true) != s {
		status = http.StatusPreconditionRequired
		return
	}
	if !l.attemptLocked("servers:"+s.username, serverAttempts) {
		status = 429
		return
	}
	s.last = l.now()
	actor := s.owner
	type identity struct {
		Fingerprint string `json:"fingerprint"`
		Algorithm   string `json:"algorithm"`
	}
	// rescan reads the current host key of a reachable SSH server.
	rescan := func() (ssh.PublicKey, int) {
		t, ok := l.remote.targets[server]
		if !ok || t.Protocol != "ssh" {
			return nil, 404
		}
		return l.scanLocked(r.Context(), id, s, t.Target)
	}
	// reread reads the current certificate of a reachable RDP server, and
	// remembers what it showed.
	listed, isRDP := l.remote.targets[server]
	isRDP = isRDP && listed.Protocol == "rdp"
	reread := func() (*x509.Certificate, int) {
		cert, refused := l.scanCertificateLocked(r.Context(), id, s, listed.Target)
		if refused == 0 {
			l.noteCertificateLocked(server, cert)
		}
		return cert, refused
	}
	var e error
	switch {
	case server == "" && action == "scan":
		fields, ok := readFields(w, r, 1024, "protocol", "address", "port")
		if !ok {
			status = 400
			return
		}
		target, _, refused := l.newServerLocked(fields["protocol"], fields["address"], fields["port"])
		if refused != 0 {
			status = refused
			return
		}
		if fields["protocol"] == "rdp" {
			cert, refused := l.scanCertificateLocked(r.Context(), id, s, target)
			if refused != 0 {
				status = refused
				return
			}
			if !usableLeaf(cert, target, l.now()) {
				status = 422
				return
			}
			result = struct {
				Expires int64 `json:"expires"`
			}{cert.NotAfter.Unix()}
			return
		}
		key, refused := l.scanLocked(r.Context(), id, s, target)
		if refused != 0 {
			status = refused
			return
		}
		result = identity{ssh.FingerprintSHA256(key), key.Type()}
		return
	case server == "" && action == "":
		fields, ok := readFields(w, r, 2048, "protocol", "name", "address", "port", "fingerprint")
		unchecked := fields["protocol"] == "rdp" && fields["fingerprint"] == uncheckedPrint
		if !ok || !serverName(fields["name"]) || !validFingerprint(fields["fingerprint"]) && !unchecked {
			status = 400
			return
		}
		target, endpoint, refused := l.newServerLocked(fields["protocol"], fields["address"], fields["port"])
		if refused != 0 {
			status = refused
			return
		}
		var made string
		// What the server shows now must be what the administrator compared,
		// unless they chose not to compare an RDP server: then it is pinned as
		// it answers now, and marked unchecked.
		if fields["protocol"] == "rdp" {
			cert, refused := l.scanCertificateLocked(r.Context(), id, s, target)
			if refused != 0 {
				status = refused
				return
			}
			if !unchecked && certificatePrint(cert) != fields["fingerprint"] {
				status = 409
				return
			}
			if !usableLeaf(cert, target, l.now()) {
				status = 422
				return
			}
			made, e = l.store.addRDPServer(actor, fields["name"], endpoint.Addr().String(), endpoint.Port(), cert.Raw, unchecked, l.now())
		} else {
			key, refused := l.scanLocked(r.Context(), id, s, target)
			if refused != 0 {
				status = refused
				return
			}
			if ssh.FingerprintSHA256(key) != fields["fingerprint"] {
				status = 409
				return
			}
			made, e = l.store.addServer(actor, fields["name"], endpoint.Addr().String(), endpoint.Port(), key.Marshal(), l.now())
		}
		if e == nil {
			result = struct {
				ID string `json:"id"`
			}{made}
		}
	case action == "name" && r.Method == "POST":
		fields, ok := readFields(w, r, 1024, "name")
		if !ok || !serverName(fields["name"]) {
			status = 400
			return
		}
		e = l.store.renameServer(actor, server, fields["name"])
	case action == "scan" && r.Method == "POST":
		if _, ok := readFields(w, r, 1024); !ok {
			status = 400
			return
		}
		if isRDP {
			cert, refused := reread()
			if refused != 0 {
				status = refused
				return
			}
			result = struct {
				Same    bool  `json:"same"`
				Expires int64 `json:"expires"`
			}{certificatePrint(cert) == identityFingerprint(listed), cert.NotAfter.Unix()}
			return
		}
		key, refused := rescan()
		if refused != 0 {
			status = refused
			return
		}
		result = identity{ssh.FingerprintSHA256(key), key.Type()}
		return
	case action == "key" && r.Method == "POST" && isRDP:
		fields, ok := readFields(w, r, 1024, "fingerprint")
		unchecked := fields["fingerprint"] == uncheckedPrint
		if !ok || !validFingerprint(fields["fingerprint"]) && !unchecked {
			status = 400
			return
		}
		cert, refused := reread()
		if refused != 0 {
			status = refused
			return
		}
		if !unchecked && certificatePrint(cert) != fields["fingerprint"] {
			status = 409
			return
		}
		if !usableLeaf(cert, listed.Target, l.now()) {
			status = 422
			return
		}
		e = l.store.repinCertificate(actor, server, cert.Raw, unchecked)
	case action == "key" && r.Method == "POST":
		fields, ok := readFields(w, r, 1024, "fingerprint")
		if !ok || !validFingerprint(fields["fingerprint"]) {
			status = 400
			return
		}
		key, refused := rescan()
		if refused != 0 {
			status = refused
			return
		}
		if ssh.FingerprintSHA256(key) != fields["fingerprint"] {
			status = 409
			return
		}
		e = l.store.repinServer(actor, server, key.Marshal())
	case (action == "grant" || action == "revoke") && r.Method == "POST":
		fields, ok := readFields(w, r, 1024, "account")
		if !ok || !validID(fields["account"]) {
			status = 400
			return
		}
		e = l.store.setServerAccess(actor, server, fields["account"], action == "grant")
	case action == "" && r.Method == "DELETE":
		if _, ok := readFields(w, r, 1024); !ok {
			status = 400
			return
		}
		e = l.store.deleteServer(actor, server)
	default:
		status = 404
		return
	}
	switch {
	case e == errMissing:
		status = 404
	case e == errDuplicate:
		status = 409
	case e != nil:
		status = 403
	default:
		// The change holds now: whoever lost the server, or a lease granted
		// for its old identity, is cut off at once.
		_ = l.reloadServersLocked()
	}
	if e != nil {
		result = nil
	}
}
