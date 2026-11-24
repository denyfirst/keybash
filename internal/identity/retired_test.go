package identity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// writeRetired stores, as an earlier version did, a personal key record, a
// connection, a shared credential and an access list on server. The records
// are sealed opaque bytes: nothing reads them any more.
func writeRetired(t *testing.T, s *Store, owner, server string) {
	t.Helper()
	if e := s.update(func(tx *bolt.Tx) error {
		sealed, e := s.seal(tx, "credential", owner, strings.Repeat("1", 32), 1, []byte(`{"secret":"Synthetic-retired-canary"}`))
		if e != nil {
			return e
		}
		if e := tx.Bucket(credentialBucket).Put([]byte(owner+"/"+strings.Repeat("1", 32)), sealed); e != nil {
			return e
		}
		for _, name := range [][]byte{connectionBucket, sharedBucket} {
			b, e := tx.CreateBucketIfNotExists(name)
			if e != nil {
				return e
			}
			if e := b.Put([]byte(server), sealed); e != nil {
				return e
			}
		}
		w, e := s.server(tx, server)
		if e != nil {
			return e
		}
		w.Access = []string{owner}
		// Sealed directly: saveServer never writes an access list.
		plain, e := json.Marshal(w)
		if e != nil {
			return e
		}
		record, e := s.seal(tx, "server", server, server, w.Revision+1, plain)
		if e != nil {
			return e
		}
		return tx.Bucket(serverBucket).Put([]byte(server), record)
	}); e != nil {
		t.Fatalf("fixture retired records failed: %v", e)
	}
}

// What earlier versions stored for the personal path is erased when a
// database opens, once; a database with nothing left is not written.
func TestRetiredRecordsAreErasedOnOpen(t *testing.T) {
	s, key, dir := bootstrapped(t)
	alice, _ := s.lookup("alice")
	server, e := s.addServer(alice.ID, "Web", "10.20.0.7", 22, hostKeyFixture(t).Marshal(), time.Now())
	if e != nil {
		t.Fatal("fixture server refused")
	}
	writeRetired(t, s, alice.ID, server)
	if s.view(func(tx *bolt.Tx) error {
		w, e := s.server(tx, server)
		if e != nil || len(w.Access) != 1 {
			return errRefused
		}
		return nil
	}) != nil {
		t.Fatal("the fixture access list did not read")
	}
	// A saved server never carries one.
	if s.update(func(tx *bolt.Tx) error {
		w, e := s.server(tx, server)
		if e != nil {
			return e
		}
		return s.saveServer(tx, w)
	}) == nil {
		t.Fatal("a server was saved with an access list")
	}
	// The backup check refuses a store that still holds them.
	if s.view(func(tx *bolt.Tx) error { _, e := s.verifyAll(tx); return e }) == nil {
		t.Fatal("a store with personal records verified")
	}
	_ = s.Close()
	reopened, e := openStore(dir, key)
	if e != nil {
		t.Fatal("reopen refused")
	}
	defer reopened.Close()
	committed := func() int {
		var id int
		_ = reopened.view(func(tx *bolt.Tx) error { id = tx.ID(); return nil })
		return id
	}
	if reopened.view(func(tx *bolt.Tx) error {
		if b := tx.Bucket(credentialBucket); b == nil {
			return errRefused // kept, for an earlier binary put back
		} else if k, _ := b.Cursor().First(); k != nil {
			return errRefused
		}
		if tx.Bucket(connectionBucket) != nil || tx.Bucket(sharedBucket) != nil {
			return errRefused
		}
		w, e := reopened.server(tx, server)
		if e != nil || len(w.Access) != 0 || w.Name != "Web" {
			return errRefused
		}
		_, e = reopened.verifyAll(tx)
		return e
	}) != nil {
		t.Fatal("opening did not erase the personal records, or erased more")
	}
	// Nothing left: opening again commits nothing.
	before := committed()
	if reopened.eraseRetiredOnOpen() != nil || committed() != before {
		t.Fatal("an open with nothing to erase wrote")
	}
	if _, e := NewPersistent("https://127.0.0.1:8443", reopened); e != nil || committed() != before {
		t.Fatal("a start with nothing to erase wrote, or refused")
	}
	data, e := os.ReadFile(filepath.Join(dir, "custody.db"))
	if e != nil || bytes.Contains(data, []byte("Synthetic-retired-canary")) {
		t.Fatal("a retired record was ever in plaintext")
	}
}

// A start erases them too, for a store opened before this version.
func TestRetiredRecordsAreErasedOnStart(t *testing.T) {
	s, _, _ := bootstrapped(t)
	alice, _ := s.lookup("alice")
	server, e := s.addServer(alice.ID, "Web", "10.20.0.7", 22, hostKeyFixture(t).Marshal(), time.Now())
	if e != nil {
		t.Fatal("fixture server refused")
	}
	writeRetired(t, s, alice.ID, server)
	l, e := NewPersistent("https://127.0.0.1:8443", s)
	if e != nil {
		t.Fatal("the start refused")
	}
	defer l.Close()
	left := true
	if s.view(func(tx *bolt.Tx) error { var e error; left, e = s.retiredLeft(tx); return e }) != nil || left {
		t.Fatal("a start left personal records")
	}
}
