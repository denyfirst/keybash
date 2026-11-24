package identity

import (
	bolt "go.etcd.io/bbolt"
)

// What earlier versions stored for personal keys and passwords, personal
// connections, server access lists and the one shared credential per server
// (ADR 0010). This version erases it on opening a database, and never writes
// it. The credentials namespace itself stays, empty: an earlier binary put
// back without a restore requires it, and then finds no personal records.
var (
	connectionBucket = []byte("connections-v1")
	sharedBucket     = []byte("shared-credentials-v1")
)

// retiredLeft reports whether tx still holds anything eraseRetired erases.
func (s *Store) retiredLeft(tx *bolt.Tx) (bool, error) {
	if b := tx.Bucket(credentialBucket); b != nil {
		if k, _ := b.Cursor().First(); k != nil {
			return true, nil
		}
	}
	if tx.Bucket(connectionBucket) != nil || tx.Bucket(sharedBucket) != nil {
		return true, nil
	}
	list, e := s.servers(tx)
	if e != nil {
		return false, errRefused
	}
	for _, w := range list {
		if len(w.Access) != 0 {
			return true, nil
		}
	}
	return false, nil
}

// eraseRetired erases, in tx, every personal key, password and connection,
// every shared credential and every access list. The records are not read:
// nothing in them is kept. A server whose record no longer reads refuses the
// whole erase, as it would refuse the service.
func (s *Store) eraseRetired(tx *bolt.Tx) error {
	if b := tx.Bucket(credentialBucket); b != nil {
		var keys [][]byte
		if b.ForEach(func(k, _ []byte) error { keys = append(keys, append([]byte(nil), k...)); return nil }) != nil {
			return errRefused
		}
		for _, k := range keys {
			if b.Delete(k) != nil {
				return errRefused
			}
		}
	}
	for _, name := range [][]byte{connectionBucket, sharedBucket} {
		if tx.Bucket(name) != nil && tx.DeleteBucket(name) != nil {
			return errRefused
		}
	}
	list, e := s.servers(tx)
	if e != nil {
		return errRefused
	}
	for _, w := range list {
		if len(w.Access) == 0 {
			continue
		}
		w.Access = nil
		if s.saveServer(tx, w) != nil {
			return errRefused
		}
	}
	return nil
}

// eraseRetiredOnOpen runs eraseRetired once, when there is something to erase;
// a database with nothing left is not written.
func (s *Store) eraseRetiredOnOpen() error {
	left := false
	if e := s.view(func(tx *bolt.Tx) error {
		if _, e := s.meta(tx); e != nil {
			return e
		}
		var e error
		left, e = s.retiredLeft(tx)
		return e
	}); e != nil {
		return errRefused
	}
	if !left {
		return nil
	}
	return s.update(func(tx *bolt.Tx) error {
		if _, e := s.meta(tx); e != nil {
			return e
		}
		return s.eraseRetired(tx)
	})
}
