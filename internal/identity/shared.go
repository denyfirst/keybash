package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
	bolt "go.etcd.io/bbolt"
)

// Shared credentials (docs/adr/0009-shared-server-credentials.md). A server
// may have one, set by an administrator. Everyone on the server's access list
// connects with it, and nobody is ever shown it: no response, page or log
// carries its secret. An SSH key is made here and leaves only as signatures. An
// optional additive namespace like servers: a database stays as it was until
// the first one is set.
var sharedBucket = []byte("shared-credentials-v1")

// sharedOptions go before a shared key's line on the server: no forwarding of
// ports, agents or X11 and no user rc, but a terminal, which is all Keybash
// asks for. A key used through a compromised gateway can then do no more on
// the server than a person at its terminal.
const sharedOptions = "restrict,pty"

// sharedName is the name every shared credential carries; people never see a
// shared credential's record, only its server.
const sharedName = "shared"

// sharedCredential is one server's. Next is a key made to replace Current,
// waiting until the administrator has put it on the server and switches to
// it. Generation grows with every new secret, and a lease is bound to it, so a
// credential replaced between grant and redeem is never used.
type sharedCredential struct {
	Server     string      `json:"server"`
	Current    Credential  `json:"current"`
	Next       *Credential `json:"next,omitempty"`
	Generation uint64      `json:"generation"`
	SetBy      string      `json:"set_by"`
	Set        int64       `json:"set"`
}

func (sharedCredential) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[shared credential redacted]")
}

// sharedSecret checks one credential a shared record holds, for a server of
// this protocol: a key made here (Ed25519, SSH only), or a password typed by
// an administrator (SSH or RDP). The stored public half must be the key's own.
func sharedSecret(protocol string, c Credential) bool {
	if c.Name != sharedName || c.ID != "" || c.Username == "" || c.Passphrase != "" {
		return false
	}
	checked := c
	if validateCredential(&checked) != nil || checked.Fingerprint != c.Fingerprint || checked.Public != c.Public {
		return false
	}
	switch c.Kind {
	case "ssh-key":
		return protocol == "ssh" && c.Generated && strings.HasPrefix(c.Public, "ssh-ed25519 ")
	case "password":
		return (protocol == "ssh" || protocol == "rdp") && !c.Generated && !c.Used
	}
	return false
}

// valid checks a shared record against its server.
func (c sharedCredential) valid(w webServer) bool {
	if c.Server != w.ID || w.Removed || !validID(c.SetBy) || c.Set <= 0 || c.Generation == 0 || c.Generation >= 1<<31 || !sharedSecret(w.Protocol, c.Current) {
		return false
	}
	if c.Next == nil {
		return true
	}
	return c.Current.Kind == "ssh-key" && sharedSecret(w.Protocol, *c.Next) && c.Next.Kind == "ssh-key" && !c.Next.Used &&
		c.Next.Username == c.Current.Username && c.Next.Fingerprint != c.Current.Fingerprint
}

// sharedLine is what goes in the account's authorized_keys on the server.
func sharedLine(c Credential) string {
	if c.Kind != "ssh-key" || c.Public == "" {
		return ""
	}
	return sharedOptions + " " + c.Public + " keybash-shared"
}

// shared reads a server's shared credential and the record's revision.
// errMissing means the server has none.
func (s *Store) shared(tx *bolt.Tx, server string) (sharedCredential, uint64, error) {
	var c sharedCredential
	w, e := s.server(tx, server)
	if e != nil {
		return c, 0, e
	}
	b := tx.Bucket(sharedBucket)
	if b == nil || b.Get([]byte(server)) == nil {
		return c, 0, errMissing
	}
	plain, revision, e := s.unseal("shared", server, server, b.Get([]byte(server)))
	if e != nil {
		return c, 0, e
	}
	defer clear(plain)
	if decodeRecord(plain, &c, 24*1024) != nil || !c.valid(w) {
		return sharedCredential{}, 0, errRefused
	}
	return c, revision, nil
}

// readShared is shared in its own transaction; errMissing still means none.
func (s *Store) readShared(server string) (sharedCredential, error) {
	var c sharedCredential
	var why error
	e := s.view(func(tx *bolt.Tx) error { c, _, why = s.shared(tx, server); return why })
	if why == errMissing {
		return sharedCredential{}, errMissing
	}
	return c, e
}

// listShared is every server's shared credential, by server.
func (s *Store) listShared() (map[string]sharedCredential, error) {
	list := map[string]sharedCredential{}
	e := s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket(sharedBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			c, _, e := s.shared(tx, string(k))
			if e != nil || len(list) >= maxServers {
				return errRefused
			}
			list[c.Server] = c
			return nil
		})
	})
	return list, e
}

// putShared seals c at the revision after revision (0 for a new record).
func (s *Store) putShared(tx *bolt.Tx, c sharedCredential, revision uint64) error {
	w, e := s.server(tx, c.Server)
	if e != nil || !c.valid(w) || revision >= 1<<31 {
		return errRefused
	}
	b, e := tx.CreateBucketIfNotExists(sharedBucket)
	if e != nil {
		return errRefused
	}
	plain, e := json.Marshal(c) // #nosec G117 -- intentional bounded secret serialization solely into the authenticated encrypted envelope; no logs or metadata response.
	if e != nil {
		return errRefused
	}
	defer clear(plain)
	sealed, e := s.seal(tx, "shared", c.Server, c.Server, revision+1, plain)
	if e != nil {
		return errRefused
	}
	return b.Put([]byte(c.Server), sealed)
}

// newSharedSecret makes the credential an administrator asked for: a key made
// here for an SSH server, or the password they typed.
func newSharedSecret(protocol, kind, username, secret string) (Credential, error) {
	var c Credential
	switch {
	case kind == "ssh-key" && protocol == "ssh" && secret == "":
		var e error
		if c, e = newGeneratedKey(sharedName, username); e != nil {
			return Credential{}, errRefused
		}
	case kind == "password":
		c = Credential{Name: sharedName, Kind: "password", Username: username, Secret: secret}
		if validateCredential(&c) != nil {
			return Credential{}, errRefused
		}
	default:
		return Credential{}, errRefused
	}
	if !sharedSecret(protocol, c) {
		return Credential{}, errRefused
	}
	return c, nil
}

// sharedRequest checks what an administrator sent before anything is made: a
// kind, an account name, and a password, or nothing for a key made here.
func sharedRequest(kind, username, secret string) bool {
	if !label(username, 128, false) || strings.TrimSpace(username) != username {
		return false
	}
	switch kind {
	case "ssh-key":
		return secret == ""
	case "password":
		return secret != "" && len(secret) <= 4096 && !strings.ContainsRune(secret, 0)
	}
	return false
}

// setShared gives a server without one its shared credential.
func (s *Store) setShared(actor, server, kind, username, secret string, now time.Time) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, server)
		if e != nil || w.Removed {
			return errMissing
		}
		if _, _, e := s.shared(tx, server); e != errMissing {
			if e == nil {
				return errDuplicate
			}
			return errRefused
		}
		c, e := newSharedSecret(w.Protocol, kind, username, secret)
		if e != nil {
			return e
		}
		return s.putShared(tx, sharedCredential{Server: server, Current: c, Generation: 1, SetBy: actor, Set: now.Unix()}, 0)
	})
}

// changeShared applies one change to a server's existing shared credential.
func (s *Store) changeShared(actor, server string, now time.Time, change func(w webServer, c *sharedCredential) error) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, server)
		if e != nil || w.Removed {
			return errMissing
		}
		c, revision, e := s.shared(tx, server)
		if e != nil {
			return e
		}
		if e := change(w, &c); e != nil {
			return e
		}
		c.SetBy, c.Set = actor, now.Unix()
		return s.putShared(tx, c, revision)
	})
}

// replaceSharedPassword takes a new password at once: the administrator
// changed it on the server first.
func (s *Store) replaceSharedPassword(actor, server, username, secret string, now time.Time) error {
	return s.changeShared(actor, server, now, func(w webServer, c *sharedCredential) error {
		if c.Current.Kind != "password" {
			return errRefused
		}
		next, e := newSharedSecret(w.Protocol, "password", username, secret)
		if e != nil {
			return e
		}
		c.Current, c.Generation = next, c.Generation+1
		return nil
	})
}

// nextSharedKey makes the key that will replace the current one, which keeps
// working until the switch. A key made earlier and not switched to is
// replaced.
func (s *Store) nextSharedKey(actor, server string, now time.Time) error {
	return s.changeShared(actor, server, now, func(w webServer, c *sharedCredential) error {
		if c.Current.Kind != "ssh-key" {
			return errRefused
		}
		next, e := newSharedSecret(w.Protocol, "ssh-key", c.Current.Username, "")
		if e != nil {
			return e
		}
		c.Next = &next
		return nil
	})
}

// switchSharedKey makes the waiting key the one used, and destroys the old
// one. The fingerprint is the one the administrator saw, so a key made again
// meanwhile is not switched to unseen.
func (s *Store) switchSharedKey(actor, server, fingerprint string, now time.Time) error {
	return s.changeShared(actor, server, now, func(_ webServer, c *sharedCredential) error {
		if c.Next == nil {
			return errMissing
		}
		if c.Next.Fingerprint != fingerprint {
			return errDuplicate
		}
		c.Current, c.Next, c.Generation = *c.Next, nil, c.Generation+1
		return nil
	})
}

// dropNextSharedKey destroys a waiting key; the current one stays.
func (s *Store) dropNextSharedKey(actor, server string, now time.Time) error {
	return s.changeShared(actor, server, now, func(_ webServer, c *sharedCredential) error {
		if c.Next == nil {
			return errMissing
		}
		c.Next = nil
		return nil
	})
}

// removeShared destroys a server's shared credential, even one that no longer
// reads: removing it can only take access away.
func (s *Store) removeShared(actor, server string) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, server)
		b := tx.Bucket(sharedBucket)
		if e != nil || w.Removed || b == nil || b.Get([]byte(server)) == nil {
			return errMissing
		}
		return b.Delete([]byte(server))
	})
}

// dropShared removes a server's shared credential, if any, in the
// transaction that removes the server.
func dropShared(tx *bolt.Tx, server string) error {
	if b := tx.Bucket(sharedBucket); b != nil {
		return b.Delete([]byte(server))
	}
	return nil
}

// markSharedUsed records, once, that the shared key with this fingerprint has
// opened a session on its server. Its secret and generation stay as they are.
func (s *Store) markSharedUsed(server, fingerprint string) error {
	return s.update(func(tx *bolt.Tx) error {
		c, revision, e := s.shared(tx, server)
		if e != nil || c.Current.Kind != "ssh-key" || c.Current.Fingerprint != fingerprint {
			return errRefused
		}
		if c.Current.Used {
			return nil
		}
		c.Current.Used = true
		return s.putShared(tx, c, revision)
	})
}

// sharedView is what administrators and auditors see of a server's shared
// credential: never its secret.
type sharedView struct {
	Kind            string `json:"kind"`
	Username        string `json:"username"`
	Line            string `json:"line,omitempty"`        // a key's line for the server's authorized_keys
	Fingerprint     string `json:"fingerprint,omitempty"` // a key's
	Used            bool   `json:"used,omitempty"`        // a key has opened a session
	Next            string `json:"next,omitempty"`        // the line of a key waiting for the switch
	NextFingerprint string `json:"next_fingerprint,omitempty"`
	SetBy           string `json:"set_by"`
	Set             int64  `json:"set"`
}

func (c sharedCredential) view() *sharedView {
	v := &sharedView{Kind: c.Current.Kind, Username: c.Current.Username, Line: sharedLine(c.Current), Fingerprint: c.Current.Fingerprint,
		Used: c.Current.Used, SetBy: c.SetBy, Set: c.Set}
	if c.Next != nil {
		v.Next, v.NextFingerprint = sharedLine(*c.Next), c.Next.Fingerprint
	}
	return v
}

// sharedLocked is the server and its shared credential, when s's person may
// connect with it now: listed on the server's access list, the server usable,
// and the credential one its protocol takes.
func (l *Lab) sharedLocked(s *session, server string) (RemoteTarget, sharedCredential, bool) {
	t, ok := l.targetLocked(s, server)
	if !ok || !usableTarget(t, l.now()) {
		return RemoteTarget{}, sharedCredential{}, false
	}
	c, e := l.store.readShared(server)
	if e != nil || !compatible(t, c.Current) {
		return RemoteTarget{}, sharedCredential{}, false
	}
	return t, c, true
}

// grantSharedLocked is grantRemoteLocked for a server's shared credential:
// the same ready session, rate and capacity, and a lease bound to the
// server's approval and the credential's generation. redeemRemoteLocked
// checks both again, with the access list.
func (l *Lab) grantSharedLocked(id [32]byte, server string) (string, error) {
	s := l.readyLocked(id, false)
	if s == nil || l.remote == nil || !l.serversLocked(s) || !validID(server) {
		return "", errRefused
	}
	if !l.attemptLocked("remote:"+s.username, remoteAttempts) {
		return "", errLimited
	}
	l.sweepRemotesLocked()
	t, c, ok := l.sharedLocked(s, server)
	if !ok {
		return "", errRefused
	}
	return l.issueLeaseLocked(s, &remoteLease{session: id, owner: s.owner, target: server, shared: server, approval: approvalFingerprint(t), generation: c.Generation})
}

// revokeSharedLocked ends every session and lease on a server's shared
// credential, once it is removed.
func (l *Lab) revokeSharedLocked(server string) {
	if l.remote == nil {
		return
	}
	for key, lease := range l.remote.leases {
		if lease.shared == server {
			if lease.cancel != nil {
				lease.cancel(terminalweb.ReasonAccessChanged)
			}
			delete(l.remote.leases, key)
		}
	}
}

// sharedConnection is one server a person connects to with its shared
// credential: its account name, and nothing of the secret.
type sharedConnection struct {
	Server   string `json:"server"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Username string `json:"username"`
	// Trust is what the card says, in the words of a person's own
	// connections: "verified" (ready), "stopped" (a desktop shows another
	// certificate than its pin, so nothing is sent until an administrator
	// checks it) or "unavailable".
	Trust string `json:"trust"`
}

// sharedConnectionsLocked lists them for s's person: every server on whose
// access list they are that has a shared credential.
func (l *Lab) sharedConnectionsLocked(s *session) ([]sharedConnection, error) {
	shared, e := l.store.listShared()
	if e != nil {
		return nil, e
	}
	rows := make([]sharedConnection, 0)
	for server, c := range shared {
		t, ok := l.targetLocked(s, server)
		if !ok {
			continue
		}
		trust := "unavailable"
		if usableTarget(t, l.now()) && compatible(t, c.Current) {
			trust = "verified"
			if l.certificateChangedLocked(t) {
				trust = "stopped"
			}
		}
		rows = append(rows, sharedConnection{Server: server, Name: t.Name, Protocol: t.Protocol, Username: c.Current.Username, Trust: trust})
	}
	slices.SortFunc(rows, func(a, b sharedConnection) int {
		if order := strings.Compare(a.Name, b.Name); order != 0 {
			return order
		}
		return strings.Compare(a.Server, b.Server)
	})
	return rows, nil
}
