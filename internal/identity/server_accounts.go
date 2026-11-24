package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Server accounts (docs/adr/0010-server-accounts.md). An account is one
// sign-in on one server: its name there, and a key made here or a password an
// administrator typed once. It lists the people who may use it, and nothing
// else gives anyone a server. Nobody is ever shown its secret: no response,
// page or log carries it, and a key leaves only as signatures. An optional
// additive namespace like servers: a database stays as it was until the first
// account is added.
var serverAccountBucket = []byte("server-accounts-v1")

const (
	maxServerAccounts = 16   // on one server
	maxAllAccounts    = 2048 // on every server together
	maxAccountPeople  = 256
)

// accountOptions go before a key's line on the server: no forwarding of
// ports, agents or X11 and no user rc, but a terminal, which is all Keybash
// asks for. A key used through a compromised gateway can then do no more on
// the server than a person at its terminal.
const accountOptions = "restrict,pty"

// serverAccount is one account on one server. Next is a key made to replace
// Current, waiting until the administrator has put it on the server and
// switches to it. Generation grows with every new secret, and a lease is bound
// to it, so a secret replaced between grant and redeem is never used. People
// are the IDs of everyone who may use it, sorted; changing them leaves the
// generation as it is.
type serverAccount struct {
	ID         string      `json:"id"`
	Server     string      `json:"server"`
	Current    Credential  `json:"current"`
	Next       *Credential `json:"next,omitempty"`
	Generation uint64      `json:"generation"`
	People     []string    `json:"people,omitempty"`
	SetBy      string      `json:"set_by"`
	Set        int64       `json:"set"`
}

func (serverAccount) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[server account redacted]")
}

func accountKey(server, id string) []byte { return []byte(server + "/" + id) }

// accountName is an account's name on its server, as a person types it.
func accountName(username string) bool {
	return label(username, 128, false) && strings.TrimSpace(username) == username
}

// accountSecret checks one secret an account holds, for a server of this
// protocol: a key made here (Ed25519, SSH only), or a password typed by an
// administrator (SSH or RDP). The stored public half must be the key's own.
func accountSecret(protocol string, c Credential) bool {
	if !accountName(c.Username) {
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

// valid checks an account against its server.
func (a serverAccount) valid(w webServer) bool {
	if !validID(a.ID) || a.Server != w.ID || w.Removed || !validID(a.SetBy) || a.Set <= 0 || a.Generation == 0 || a.Generation >= 1<<31 ||
		!accountSecret(w.Protocol, a.Current) || len(a.People) > maxAccountPeople || !increasing(a.People) || slices.ContainsFunc(a.People, func(id string) bool { return !validID(id) }) {
		return false
	}
	if a.Next == nil {
		return true
	}
	return a.Current.Kind == "ssh-key" && accountSecret(w.Protocol, *a.Next) && a.Next.Kind == "ssh-key" && !a.Next.Used &&
		a.Next.Username == a.Current.Username && a.Next.Fingerprint != a.Current.Fingerprint
}

// accountLine is what goes in the account's authorized_keys on the server.
func accountLine(c Credential) string {
	if c.Kind != "ssh-key" || c.Public == "" {
		return ""
	}
	return accountOptions + " " + c.Public + " keybash"
}

// serverAccount reads one account and its record's revision. errMissing means
// there is none.
func (s *Store) serverAccount(tx *bolt.Tx, server, id string) (serverAccount, uint64, error) {
	var a serverAccount
	w, e := s.server(tx, server)
	if e != nil {
		return a, 0, e
	}
	b := tx.Bucket(serverAccountBucket)
	if !validID(id) || b == nil || b.Get(accountKey(server, id)) == nil {
		return a, 0, errMissing
	}
	plain, revision, e := s.unseal("server-account", server, id, b.Get(accountKey(server, id)))
	if e != nil {
		return a, 0, e
	}
	defer clear(plain)
	if decodeRecord(plain, &a, 24*1024) != nil || a.ID != id || !a.valid(w) {
		return serverAccount{}, 0, errRefused
	}
	return a, revision, nil
}

// serverAccounts is every account, each read as the service would; with a
// server, only that server's.
func (s *Store) serverAccounts(tx *bolt.Tx, server string) ([]serverAccount, error) {
	list := make([]serverAccount, 0)
	b := tx.Bucket(serverAccountBucket)
	if b == nil {
		return list, nil
	}
	read := func(k []byte) error {
		owner, id, ok := strings.Cut(string(k), "/")
		if !ok || len(list) >= maxAllAccounts {
			return errRefused
		}
		a, _, e := s.serverAccount(tx, owner, id)
		if e != nil {
			return errRefused
		}
		list = append(list, a)
		return nil
	}
	if server == "" {
		return list, b.ForEach(func(k, _ []byte) error { return read(k) })
	}
	prefix := []byte(server + "/")
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		if e := read(k); e != nil {
			return nil, e
		}
	}
	return list, nil
}

// listServerAccounts is every account, in its own transaction.
func (s *Store) listServerAccounts() ([]serverAccount, error) {
	var list []serverAccount
	e := s.view(func(tx *bolt.Tx) error { var e error; list, e = s.serverAccounts(tx, ""); return e })
	return list, e
}

// readServerAccount is serverAccount in its own transaction; errMissing
// still means there is none.
func (s *Store) readServerAccount(server, id string) (serverAccount, error) {
	var a serverAccount
	var why error
	e := s.view(func(tx *bolt.Tx) error { a, _, why = s.serverAccount(tx, server, id); return why })
	if why == errMissing {
		return serverAccount{}, errMissing
	}
	return a, e
}

// putServerAccount seals a at the revision after revision (0 for a new one).
func (s *Store) putServerAccount(tx *bolt.Tx, a serverAccount, revision uint64) error {
	w, e := s.server(tx, a.Server)
	if e != nil || !a.valid(w) || revision >= 1<<31 {
		return errRefused
	}
	b, e := tx.CreateBucketIfNotExists(serverAccountBucket)
	if e != nil {
		return errRefused
	}
	plain, e := json.Marshal(a) // #nosec G117 -- intentional bounded secret serialization solely into the authenticated encrypted envelope; no logs or metadata response.
	if e != nil {
		return errRefused
	}
	defer clear(plain)
	sealed, e := s.seal(tx, "server-account", a.Server, a.ID, revision+1, plain)
	if e != nil {
		return errRefused
	}
	return b.Put(accountKey(a.Server, a.ID), sealed)
}

// newAccountSecret makes the secret an administrator asked for: a key made
// here for an SSH server, or the password they typed.
func newAccountSecret(protocol, kind, username, secret string) (Credential, error) {
	var c Credential
	switch {
	case kind == "ssh-key" && protocol == "ssh" && secret == "":
		var e error
		if c, e = newGeneratedKey(username); e != nil {
			return Credential{}, errRefused
		}
	case kind == "password":
		c = Credential{Kind: "password", Username: username, Secret: secret}
		if validateCredential(&c) != nil {
			return Credential{}, errRefused
		}
	default:
		return Credential{}, errRefused
	}
	if !accountSecret(protocol, c) {
		return Credential{}, errRefused
	}
	return c, nil
}

// accountRequest checks what an administrator sent before anything is made: a
// kind, an account name, and a password, or nothing for a key made here.
func accountRequest(kind, username, secret string) bool {
	if !accountName(username) {
		return false
	}
	switch kind {
	case "ssh-key":
		return secret == ""
	case "password":
		return passwordSecret(secret)
	}
	return false
}

// passwordSecret is a password as an administrator may type one.
func passwordSecret(secret string) bool {
	return secret != "" && len(secret) <= 4096 && !strings.ContainsRune(secret, 0)
}

// peopleInput reads the people an administrator ticked, sent as their IDs
// joined by commas: each once, at most maxAccountPeople, possibly none.
func peopleInput(value string) ([]string, bool) {
	if value == "" {
		return nil, true
	}
	people := strings.Split(value, ",")
	if len(people) > maxAccountPeople || slices.ContainsFunc(people, func(id string) bool { return !validID(id) }) {
		return nil, false
	}
	slices.Sort(people)
	return people, len(slices.Compact(slices.Clone(people))) == len(people)
}

// mayHoldAccess is a person who may be put on an account: one that exists and
// is not an auditor, who reaches no server.
func (s *Store) mayHoldAccess(tx *bolt.Tx, person string) error {
	a, e := s.readAccount(tx, person)
	if e != nil {
		return errMissing
	}
	if a.Role == roleAuditor {
		return errRefused
	}
	return nil
}

// addServerAccount gives a server a new account, with the people ticked. Its
// name must differ from every other account's on the server, ignoring case.
func (s *Store) addServerAccount(actor, server, kind, username, secret string, people []string, now time.Time) (string, error) {
	id, e := randomID()
	if e != nil {
		return "", e
	}
	e = s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, server)
		if e != nil || w.Removed {
			return errMissing
		}
		all, e := s.serverAccounts(tx, "")
		if e != nil {
			return errRefused
		}
		here := slices.DeleteFunc(slices.Clone(all), func(a serverAccount) bool { return a.Server != server })
		if len(all) >= maxAllAccounts || len(here) >= maxServerAccounts {
			return errRefused
		}
		if slices.ContainsFunc(here, func(a serverAccount) bool { return strings.EqualFold(a.Current.Username, username) }) {
			return errDuplicate
		}
		for _, person := range people {
			if e := s.mayHoldAccess(tx, person); e != nil {
				return e
			}
		}
		c, e := newAccountSecret(w.Protocol, kind, username, secret)
		if e != nil {
			return e
		}
		return s.putServerAccount(tx, serverAccount{ID: id, Server: server, Current: c, Generation: 1, People: people, SetBy: actor, Set: now.Unix()}, 0)
	})
	if e != nil {
		return "", e
	}
	return id, nil
}

// changeServerAccount applies one change to an existing account. stamp says
// the change is to its secret, which records who made it and when.
func (s *Store) changeServerAccount(actor, server, id string, now time.Time, stamp bool, change func(tx *bolt.Tx, w webServer, a *serverAccount) error) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, server)
		if e != nil || w.Removed {
			return errMissing
		}
		a, revision, e := s.serverAccount(tx, server, id)
		if e != nil {
			return e
		}
		if e := change(tx, w, &a); e != nil {
			return e
		}
		if stamp {
			a.SetBy, a.Set = actor, now.Unix()
		}
		return s.putServerAccount(tx, a, revision)
	})
}

// setAccountPerson puts a person on an account, or takes them off.
func (s *Store) setAccountPerson(actor, server, id, person string, allowed bool, now time.Time) error {
	if !validID(person) {
		return errRefused
	}
	return s.changeServerAccount(actor, server, id, now, false, func(tx *bolt.Tx, _ webServer, a *serverAccount) error {
		at, listed := slices.BinarySearch(a.People, person)
		switch {
		case allowed && !listed:
			if e := s.mayHoldAccess(tx, person); e != nil {
				return e
			}
			if len(a.People) >= maxAccountPeople {
				return errRefused
			}
			a.People = slices.Insert(a.People, at, person)
		case !allowed && listed:
			a.People = slices.Delete(a.People, at, at+1)
		}
		return nil
	})
}

// replaceAccountPassword takes a new password at once: the administrator
// changed it on the server first.
func (s *Store) replaceAccountPassword(actor, server, id, secret string, now time.Time) error {
	return s.changeServerAccount(actor, server, id, now, true, func(_ *bolt.Tx, w webServer, a *serverAccount) error {
		if a.Current.Kind != "password" {
			return errRefused
		}
		next, e := newAccountSecret(w.Protocol, "password", a.Current.Username, secret)
		if e != nil {
			return e
		}
		a.Current, a.Generation = next, a.Generation+1
		return nil
	})
}

// nextAccountKey makes the key that will replace the current one, which keeps
// working until the switch. A key made earlier and not switched to is
// replaced.
func (s *Store) nextAccountKey(actor, server, id string, now time.Time) error {
	return s.changeServerAccount(actor, server, id, now, true, func(_ *bolt.Tx, w webServer, a *serverAccount) error {
		if a.Current.Kind != "ssh-key" {
			return errRefused
		}
		next, e := newAccountSecret(w.Protocol, "ssh-key", a.Current.Username, "")
		if e != nil {
			return e
		}
		a.Next = &next
		return nil
	})
}

// switchAccountKey makes the waiting key the one used, and destroys the old
// one. The fingerprint is the one the administrator saw, so a key made again
// meanwhile is not switched to unseen.
func (s *Store) switchAccountKey(actor, server, id, fingerprint string, now time.Time) error {
	return s.changeServerAccount(actor, server, id, now, true, func(_ *bolt.Tx, _ webServer, a *serverAccount) error {
		if a.Next == nil {
			return errMissing
		}
		if a.Next.Fingerprint != fingerprint {
			return errDuplicate
		}
		a.Current, a.Next, a.Generation = *a.Next, nil, a.Generation+1
		return nil
	})
}

// dropNextAccountKey destroys a waiting key; the current one stays.
func (s *Store) dropNextAccountKey(actor, server, id string, now time.Time) error {
	return s.changeServerAccount(actor, server, id, now, true, func(_ *bolt.Tx, _ webServer, a *serverAccount) error {
		if a.Next == nil {
			return errMissing
		}
		a.Next = nil
		return nil
	})
}

// removeServerAccount destroys an account, even one that no longer reads:
// removing it can only take access away.
func (s *Store) removeServerAccount(actor, server, id string) error {
	return s.changeServers(actor, func(tx *bolt.Tx) error {
		w, e := s.server(tx, server)
		b := tx.Bucket(serverAccountBucket)
		if e != nil || w.Removed || !validID(id) || b == nil || b.Get(accountKey(server, id)) == nil {
			return errMissing
		}
		return b.Delete(accountKey(server, id))
	})
}

// dropServerAccounts removes a server's accounts, in the transaction that
// removes the server.
func dropServerAccounts(tx *bolt.Tx, server string) error {
	b := tx.Bucket(serverAccountBucket)
	if b == nil {
		return nil
	}
	prefix := []byte(server + "/")
	var keys [][]byte
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		keys = append(keys, slices.Clone(k))
	}
	for _, k := range keys {
		if b.Delete(k) != nil {
			return errRefused
		}
	}
	return nil
}

// dropPerson takes a person off every account, in the transaction that
// deletes them or makes them an auditor.
func (s *Store) dropPerson(tx *bolt.Tx, person string) error {
	list, e := s.serverAccounts(tx, "")
	if e != nil {
		return errRefused
	}
	for _, a := range list {
		at, listed := slices.BinarySearch(a.People, person)
		if !listed {
			continue
		}
		_, revision, e := s.serverAccount(tx, a.Server, a.ID)
		if e != nil {
			return errRefused
		}
		a.People = slices.Delete(a.People, at, at+1)
		if s.putServerAccount(tx, a, revision) != nil {
			return errRefused
		}
	}
	return nil
}

// markAccountUsed records, once, that the account's key with this fingerprint
// has opened a session on its server. Its secret and generation stay as they
// are.
func (s *Store) markAccountUsed(server, id, fingerprint string) error {
	return s.update(func(tx *bolt.Tx) error {
		a, revision, e := s.serverAccount(tx, server, id)
		if e != nil || a.Current.Kind != "ssh-key" || a.Current.Fingerprint != fingerprint {
			return errRefused
		}
		if a.Current.Used {
			return nil
		}
		a.Current.Used = true
		return s.putServerAccount(tx, a, revision)
	})
}

// accountView is what administrators and auditors see of an account: never
// its secret.
type accountView struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Username        string   `json:"username"`
	Line            string   `json:"line,omitempty"`        // a key's line for the server's authorized_keys
	Fingerprint     string   `json:"fingerprint,omitempty"` // a key's
	Used            bool     `json:"used,omitempty"`        // a key has opened a session
	Next            string   `json:"next,omitempty"`        // the line of a key waiting for the switch
	NextFingerprint string   `json:"next_fingerprint,omitempty"`
	People          []string `json:"people"`
	SetBy           string   `json:"set_by"`
	Set             int64    `json:"set"`
}

func (a serverAccount) view() accountView {
	v := accountView{ID: a.ID, Kind: a.Current.Kind, Username: a.Current.Username, Line: accountLine(a.Current), Fingerprint: a.Current.Fingerprint,
		Used: a.Current.Used, People: append([]string{}, a.People...), SetBy: a.SetBy, Set: a.Set}
	if a.Next != nil {
		v.Next, v.NextFingerprint = accountLine(*a.Next), a.Next.Fingerprint
	}
	return v
}
