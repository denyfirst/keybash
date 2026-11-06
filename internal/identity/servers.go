package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/targetguard"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// Servers an administrator added on the Servers page, beside the operator's
// root-owned catalog (docs/adr/0005-web-managed-servers.md). An optional
// additive namespace like connections: a database stays as it was until the
// first server is added. Nothing in a record is secret, but it decides where
// the gateway dials and whose sessions may use it, so it is sealed like an
// account and cannot be changed on disk without the instance key.
var serverBucket = []byte("servers-v1")

const maxServers = 256

var errDuplicate = errors.New("server already listed")

// webServer is an SSH server at one literal address. It is reachable only
// inside the target networks root set for the gateway, and only by the
// accounts on its access list: none when it is added.
type webServer struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Protocol string   `json:"protocol"`
	Address  string   `json:"address"`
	Port     uint16   `json:"port"`
	HostKey  []byte   `json:"host_key"`         // SSH wire format, Ed25519 only
	Access   []string `json:"access,omitempty"` // account IDs, sorted
	AddedBy  string   `json:"added_by"`
	Added    int64    `json:"added"`
	Revision uint64   `json:"-"`
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

func (w webServer) valid() bool {
	_, addressOK := serverAddress(w.Address)
	_, keyOK := ed25519HostKey(w.HostKey)
	if !validID(w.ID) || !serverName(w.Name) || w.Protocol != "ssh" || !addressOK || w.Port == 0 || !keyOK || !validID(w.AddedBy) || w.Added <= 0 || len(w.Access) > 256 {
		return false
	}
	for i, id := range w.Access {
		if !validID(id) || i > 0 && w.Access[i-1] >= id {
			return false
		}
	}
	return true
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
	if decodeRecord(plain, &w, 16*1024) != nil || w.ID != id || !w.valid() {
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

// addServer stores a new server with nobody on its access list. Another web
// server at the same address and port is refused.
func (s *Store) addServer(actor, name, address string, port uint16, hostKey []byte, now time.Time) (string, error) {
	id, e := randomID()
	if e != nil {
		return "", e
	}
	w := webServer{ID: id, Name: name, Protocol: "ssh", Address: address, Port: port, HostKey: bytes.Clone(hostKey), AddedBy: actor, Added: now.Unix()}
	if !w.valid() {
		return "", errRefused
	}
	e = s.changeServers(actor, func(tx *bolt.Tx) error {
		list, e := s.servers(tx)
		if e != nil || len(list) >= maxServers {
			return errRefused
		}
		if slices.ContainsFunc(list, func(other webServer) bool { return other.Address == address && other.Port == port }) {
			return errDuplicate
		}
		return s.saveServer(tx, w)
	})
	if e != nil {
		return "", e
	}
	return id, nil
}

// editServer changes one stored server; change refuses with a reason.
func (s *Store) editServer(actor, id string, change func(*bolt.Tx, *webServer) error) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, id)
		if e != nil {
			return e
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

// repinServer replaces the pinned host key. Connections to the server then
// show it as changed until each owner accepts the new one.
func (s *Store) repinServer(actor, id string, hostKey []byte) error {
	if _, ok := ed25519HostKey(hostKey); !ok {
		return errRefused
	}
	return s.editServer(actor, id, func(_ *bolt.Tx, w *webServer) error { w.HostKey = bytes.Clone(hostKey); return nil })
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

func (s *Store) deleteServer(actor, id string) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		if _, e := s.server(tx, id); e != nil {
			return e
		}
		return tx.Bucket(serverBucket).Delete([]byte(id))
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

var errHostKeyRead = errors.New("host key read")

// scanHostKey reads an SSH server's Ed25519 host key through the guarded
// target, as `keybash server-add` does on the host: the handshake offers only
// Ed25519 and Curve25519, proves the server holds the key it shows, and stops
// before authentication. It reads at most 64 KiB within 10 seconds.
func scanHostKey(ctx context.Context, target *targetguard.NamedTarget) (ssh.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, e := target.DialContext(ctx)
	if e != nil {
		return nil, errRefused
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return readHostKey(&cappedConn{Conn: conn, left: 64 << 10})
}

func readHostKey(conn net.Conn) (ssh.PublicKey, error) {
	var key ssh.PublicKey
	config := &ssh.ClientConfig{User: "keybash-host-key", HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Config:          ssh.Config{KeyExchanges: []string{ssh.KeyExchangeCurve25519}}, // its libssh.org alias comes with it
		HostKeyCallback: func(_ string, _ net.Addr, offered ssh.PublicKey) error { key = offered; return errHostKeyRead }}
	if _, _, _, e := ssh.NewClientConn(conn, "server", config); !errors.Is(e, errHostKeyRead) || key == nil || key.Type() != ssh.KeyAlgoED25519 {
		return nil, errRefused
	}
	return key, nil
}

// cappedConn ends a connection's input after a fixed number of bytes.
type cappedConn struct {
	net.Conn
	left int
}

func (c *cappedConn) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, io.EOF
	}
	n, e := c.Conn.Read(p[:min(len(p), c.left)])
	c.left -= n
	return n, e
}
