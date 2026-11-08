package identity

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/rdpcert"
	"github.com/denyfirst/keybash/internal/targetguard"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// Every server people connect to is a record here, managed on the Servers
// page (docs/adr/0005-web-managed-servers.md). An optional additive namespace
// like connections: a database stays as it was until the first server is
// added or moved in from the operator's server file. Nothing in a record is
// secret, but it decides where the gateway dials and whose sessions may use
// it, so it is sealed like an account and cannot be changed on disk without
// the instance key.
var serverBucket = []byte("servers-v1")

const maxServers = 256

var errDuplicate = errors.New("server already listed")

// webServer is one server: at one literal address, where its pinned key or
// exact certificate is the whole identity, or at a DNS name that resolves only
// to its pinned addresses and that its certificate also names. It is reachable
// only inside the target networks root set for the gateway, and only by the
// accounts on its access list: none when an administrator adds it. A server
// moved in from the file keeps its ID, so connections to it keep their
// approval; one removed on the page stays as a marker so the file never brings
// it back.
type webServer struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	Address     string   `json:"address,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Pins        []string `json:"pins,omitempty"` // sorted, with Hostname
	Port        uint16   `json:"port"`
	HostKey     []byte   `json:"host_key,omitempty"`    // SSH: wire format, Ed25519 only
	Certificate []byte   `json:"certificate,omitempty"` // RDP: the pinned leaf, DER
	Unchecked   bool     `json:"unchecked,omitempty"`   // RDP at an address: pinned without the console check
	Access      []string `json:"access,omitempty"`      // account IDs, sorted
	AddedBy     string   `json:"added_by,omitempty"`    // empty when moved from the file
	Added       int64    `json:"added"`
	FromFile    bool     `json:"from_file,omitempty"`
	Removed     bool     `json:"removed,omitempty"`
	Revision    uint64   `json:"-"`
}

// serverName is a name people see, as the operator catalog accepts one.
func serverName(name string) bool { return label(name, 160, false) && strings.TrimSpace(name) == name }

// serverAddress reads a canonical literal address: no zone, no IPv4 written
// inside IPv6. The target guard refuses what no server can be.
func serverAddress(value string) (netip.Addr, bool) {
	addr, e := netip.ParseAddr(value)
	return addr, e == nil && addr.Zone() == "" && !addr.Is4In6() && addr.String() == value
}

// ed25519HostKey parses an SSH wire-format Ed25519 public key in its one
// canonical encoding.
func ed25519HostKey(wire []byte) (ssh.PublicKey, bool) {
	if len(wire) == 0 || len(wire) > 256 {
		return nil, false
	}
	key, e := ssh.ParsePublicKey(wire)
	return key, e == nil && key.Type() == ssh.KeyAlgoED25519 && bytes.Equal(key.Marshal(), wire)
}

// endpoints are where the server may be dialled.
func (w webServer) endpoints() []netip.AddrPort {
	var out []netip.AddrPort
	for _, value := range append([]string{w.Address}, w.Pins...) {
		if addr, ok := serverAddress(value); ok {
			out = append(out, netip.AddrPortFrom(addr, w.Port))
		}
	}
	return out
}

func (w webServer) valid() bool {
	if !validID(w.ID) || !serverName(w.Name) || w.Port == 0 || w.Added <= 0 || len(w.Access) > 256 ||
		w.FromFile != (w.AddedBy == "") || w.AddedBy != "" && !validID(w.AddedBy) || w.Removed && (!w.FromFile || len(w.Access) != 0) {
		return false
	}
	if !increasing(w.Access) || slices.ContainsFunc(w.Access, func(id string) bool { return !validID(id) }) {
		return false
	}
	// One literal address, or a DNS name with its pinned addresses.
	if w.Hostname == "" {
		if _, ok := serverAddress(w.Address); !ok || len(w.Pins) != 0 {
			return false
		}
	} else if w.Address != "" || !targetguard.CanonicalHostname(w.Hostname) || len(w.Pins) == 0 || len(w.Pins) > 16 || !increasing(w.Pins) || len(w.endpoints()) != len(w.Pins) {
		return false
	}
	switch w.Protocol {
	case "ssh":
		_, ok := ed25519HostKey(w.HostKey)
		return ok && len(w.Certificate) == 0 && !w.Unchecked
	case "rdp":
		// Only an administrator's own choice leaves a server unchecked: never a
		// server from the file, and never one with a name to verify.
		if len(w.HostKey) != 0 || len(w.Certificate) == 0 || len(w.Certificate) > rdpcert.MaxCertificate || w.Unchecked && (w.FromFile || w.Hostname != "") {
			return false
		}
		cert, e := x509.ParseCertificate(w.Certificate)
		if e != nil {
			return false
		}
		// At a literal address the exact certificate is the identity; with a
		// DNS name the certificate must also name the server.
		if w.Hostname == "" {
			return rdpcert.Check(cert) == nil
		}
		return cert.VerifyHostname(w.Hostname) == nil
	}
	return false
}

// increasing: sorted, each value once.
func increasing(list []string) bool {
	for i := 1; i < len(list); i++ {
		if list[i-1] >= list[i] {
			return false
		}
	}
	return true
}

// identity is the pinned key or certificate a connection approves.
func (w webServer) identity() []byte {
	if w.Protocol == "rdp" {
		return w.Certificate
	}
	return w.HostKey
}

func (s *Store) server(tx *bolt.Tx, id string) (webServer, error) {
	var w webServer
	if _, e := s.meta(tx); e != nil {
		return w, e
	}
	b := tx.Bucket(serverBucket)
	if !validID(id) || b == nil || b.Get([]byte(id)) == nil {
		return w, errMissing
	}
	plain, revision, e := s.unseal("server", id, id, b.Get([]byte(id)))
	if e != nil {
		return w, e
	}
	defer clear(plain)
	if decodeRecord(plain, &w, 64*1024) != nil || w.ID != id || !w.valid() {
		return webServer{}, errRefused
	}
	w.Revision = revision
	return w, nil
}

// saveServer seals w at its next revision.
func (s *Store) saveServer(tx *bolt.Tx, w webServer) error {
	if !w.valid() || w.Revision >= 1<<31 {
		return errRefused
	}
	b, e := tx.CreateBucketIfNotExists(serverBucket)
	if e != nil {
		return errRefused
	}
	plain, e := json.Marshal(w)
	if e != nil {
		return errRefused
	}
	defer clear(plain)
	sealed, e := s.seal(tx, "server", w.ID, w.ID, w.Revision+1, plain)
	if e != nil {
		return errRefused
	}
	return b.Put([]byte(w.ID), sealed)
}

// servers is every record, the removed markers too.
func (s *Store) servers(tx *bolt.Tx) ([]webServer, error) {
	list := make([]webServer, 0)
	b := tx.Bucket(serverBucket)
	if b == nil {
		return list, nil
	}
	e := b.ForEach(func(k, _ []byte) error {
		w, e := s.server(tx, string(k))
		if e != nil || len(list) >= maxServers {
			return errRefused
		}
		list = append(list, w)
		return nil
	})
	return list, e
}

func (s *Store) listServers() ([]webServer, error) {
	var list []webServer
	e := s.view(func(tx *bolt.Tx) error { var e error; list, e = s.servers(tx); return e })
	return list, e
}

// changeServers runs one change by an administrator who is active when it
// commits, and keeps the reason fn refused with.
func (s *Store) changeServers(actor string, fn func(*bolt.Tx) error) error {
	return s.updateWhy(func(tx *bolt.Tx) error {
		if by, e := s.readAccount(tx, actor); e != nil || !activeAdmin(by) {
			return errRefused
		}
		return fn(tx)
	})
}

// overlaps reports whether a listed server already answers at one of w's endpoints.
func overlaps(list []webServer, w webServer) bool {
	return slices.ContainsFunc(list, func(other webServer) bool {
		return !other.Removed && slices.ContainsFunc(other.endpoints(), func(at netip.AddrPort) bool { return slices.Contains(w.endpoints(), at) })
	})
}

// addServer stores a new SSH server at a literal address with nobody on its
// access list. A listed server at the same address and port is refused.
func (s *Store) addServer(actor, name, address string, port uint16, hostKey []byte, now time.Time) (string, error) {
	return s.addWebServer(actor, webServer{Name: name, Protocol: "ssh", Address: address, Port: port, HostKey: bytes.Clone(hostKey)}, now)
}

// addRDPServer stores a new RDP server at a literal address, identified by its
// exact certificate, with nobody on its access list. Unchecked records that the
// administrator chose not to compare it on the server's own screen.
func (s *Store) addRDPServer(actor, name, address string, port uint16, certificate []byte, unchecked bool, now time.Time) (string, error) {
	return s.addWebServer(actor, webServer{Name: name, Protocol: "rdp", Address: address, Port: port, Certificate: bytes.Clone(certificate), Unchecked: unchecked}, now)
}

func (s *Store) addWebServer(actor string, w webServer, now time.Time) (string, error) {
	id, e := randomID()
	if e != nil {
		return "", e
	}
	w.ID, w.AddedBy, w.Added = id, actor, now.Unix()
	if !w.valid() {
		return "", errRefused
	}
	e = s.changeServers(actor, func(tx *bolt.Tx) error {
		list, e := s.servers(tx)
		if e != nil || len(list) >= maxServers {
			return errRefused
		}
		if overlaps(list, w) {
			return errDuplicate
		}
		return s.saveServer(tx, w)
	})
	if e != nil {
		return "", e
	}
	return id, nil
}

// editServer changes one listed server; change refuses with a reason.
func (s *Store) editServer(actor, id string, change func(*bolt.Tx, *webServer) error) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, id)
		if e != nil {
			return e
		}
		if w.Removed {
			return errMissing
		}
		if e = change(tx, &w); e != nil {
			return e
		}
		return s.saveServer(tx, w)
	})
}

func (s *Store) renameServer(actor, id, name string) error {
	if !serverName(name) {
		return errRefused
	}
	return s.editServer(actor, id, func(_ *bolt.Tx, w *webServer) error { w.Name = name; return nil })
}

// repinServer replaces an SSH server's pinned host key. Connections to it then
// show it as changed until each owner accepts the new one.
func (s *Store) repinServer(actor, id string, hostKey []byte) error {
	if _, ok := ed25519HostKey(hostKey); !ok {
		return errRefused
	}
	return s.editServer(actor, id, func(_ *bolt.Tx, w *webServer) error {
		if w.Protocol != "ssh" {
			return errRefused
		}
		w.HostKey = bytes.Clone(hostKey)
		return nil
	})
}

// repinCertificate replaces an RDP server's pinned certificate. Connections to
// it then show it as changed until each owner accepts the new one. Checked on
// the console, the server is checked from then on; pinned without that check,
// a new certificate leaves it unchecked, and the same one leaves it as it was.
func (s *Store) repinCertificate(actor, id string, certificate []byte, unchecked bool) error {
	return s.editServer(actor, id, func(_ *bolt.Tx, w *webServer) error {
		if w.Protocol != "rdp" {
			return errRefused
		}
		w.Unchecked = unchecked && (w.Unchecked || !bytes.Equal(w.Certificate, certificate))
		w.Certificate = bytes.Clone(certificate)
		return nil
	})
}

// setServerAccess puts a person on a server's access list, or takes them off.
// An auditor reaches no server, so is never put on one.
func (s *Store) setServerAccess(actor, id, person string, allowed bool) error {
	return s.editServer(actor, id, func(tx *bolt.Tx, w *webServer) error {
		a, e := s.readAccount(tx, person)
		if e != nil {
			return errMissing
		}
		at, listed := slices.BinarySearch(w.Access, person)
		switch {
		case allowed && a.Role == roleAuditor:
			return errRefused
		case allowed && !listed:
			w.Access = slices.Insert(w.Access, at, person)
		case !allowed && listed:
			w.Access = slices.Delete(w.Access, at, at+1)
		}
		return nil
	})
}

// deleteServer removes a server. One that came from the file stays as a
// removed marker, so the file does not bring it back at the next start.
func (s *Store) deleteServer(actor, id string) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, id)
		if e != nil {
			return e
		}
		if w.Removed {
			return errMissing
		}
		if !w.FromFile {
			return tx.Bucket(serverBucket).Delete([]byte(id))
		}
		w.Removed, w.Access = true, nil
		return s.saveServer(tx, w)
	})
}

// dropAccess takes a deleted account off every access list, in the
// transaction that deletes it.
func (s *Store) dropAccess(tx *bolt.Tx, person string) error {
	list, e := s.servers(tx)
	if e != nil {
		return errRefused
	}
	for _, w := range list {
		if at, listed := slices.BinarySearch(w.Access, person); listed {
			w.Access = slices.Delete(w.Access, at, at+1)
			if s.saveServer(tx, w) != nil {
				return errRefused
			}
		}
	}
	return nil
}

// importServers moves the servers in the operator's file into the list, once
// each: the same ID, so every connection keeps its approval, and on its access
// list exactly the accounts that already have a connection to it, so nobody
// gains or loses a server. A server listed before, the removed markers
// included, is never imported again, and nothing is written when there is
// nothing new: a start then commits nothing.
func (s *Store) importServers(targets []RemoteTarget, now time.Time) error {
	if len(targets) == 0 {
		return nil
	}
	pending := false
	if s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket(serverBucket)
		pending = b == nil || slices.ContainsFunc(targets, func(t RemoteTarget) bool { return b.Get([]byte(t.ID)) == nil })
		return nil
	}) != nil {
		return errRefused
	}
	if !pending {
		return nil
	}
	return s.update(func(tx *bolt.Tx) error {
		list, e := s.servers(tx)
		if e != nil {
			return errRefused
		}
		users, e := s.connectedAccounts(tx)
		if e != nil {
			return errRefused
		}
		for _, t := range targets {
			if slices.ContainsFunc(list, func(w webServer) bool { return w.ID == t.ID }) {
				continue
			}
			w, ok := serverFromFile(t, now)
			if !ok || len(list) >= maxServers {
				return errRefused
			}
			w.Access = users[t.ID]
			if s.saveServer(tx, w) != nil {
				return errRefused
			}
			list = append(list, w)
		}
		return nil
	})
}

// connectedAccounts maps each server ID to the accounts with a connection to
// it, sorted; auditors reach no server and are left out.
func (s *Store) connectedAccounts(tx *bolt.Tx) (map[string][]string, error) {
	users := map[string][]string{}
	b := tx.Bucket(connectionBucket)
	if b == nil {
		return users, nil
	}
	e := b.ForEach(func(k, _ []byte) error {
		owner, id, ok := strings.Cut(string(k), "/")
		if !ok {
			return errRefused
		}
		c, e := s.connection(tx, owner, id)
		if e != nil {
			return e
		}
		a, e := s.readAccount(tx, owner)
		if e != nil {
			return e
		}
		if a.Role != roleAuditor && !slices.Contains(users[c.Target], owner) {
			users[c.Target] = append(users[c.Target], owner)
		}
		return nil
	})
	for _, list := range users {
		slices.Sort(list)
	}
	return users, e
}

// serverFromFile is the record for a server from the operator's file.
func serverFromFile(t RemoteTarget, now time.Time) (webServer, bool) {
	if t.Target == nil {
		return webServer{}, false
	}
	snapshot := t.Target.Snapshot()
	w := webServer{ID: t.ID, Name: t.Name, Protocol: t.Protocol, Port: snapshot.Port, Added: now.Unix(), FromFile: true}
	if t.Target.Literal() {
		w.Address = snapshot.Hostname
	} else {
		w.Hostname, w.Pins = snapshot.Hostname, snapshot.Addresses
	}
	if t.Protocol == "rdp" {
		w.Certificate = bytes.Clone(t.Identity)
	} else {
		w.HostKey = bytes.Clone(t.Identity)
	}
	return w, w.valid()
}
