package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"

	bolt "go.etcd.io/bbolt"
)

// Optional additive namespace: an old v1 database is unchanged on open. The
// first authorized connection write creates it transactionally. Missing rows
// always refuse launch; neither a database row nor a browser approves targets.
var connectionBucket = []byte("connections-v1")

type connection struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Target      string `json:"target"`
	Credential  string `json:"credential"`
	Approval    string `json:"approval"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Revision    uint64 `json:"-"`
}

func validApproval(raw string) bool {
	data, e := hex.DecodeString(raw)
	return e == nil && len(data) == 32 && hex.EncodeToString(data) == raw
}

func (s *Store) connection(tx *bolt.Tx, owner, id string) (connection, error) {
	var c connection
	if _, e := s.readAccount(tx, owner); e != nil {
		return c, e
	}
	bucket := tx.Bucket(connectionBucket)
	if bucket == nil {
		return c, errRefused
	}
	plain, revision, e := s.unseal("connection", owner, id, bucket.Get(credentialKey(owner, id)))
	if e != nil {
		return c, e
	}
	defer clear(plain)
	if decodeRecord(plain, &c, 2048) != nil || c.ID != id || !validID(c.Target) || !validID(c.Credential) || !validApproval(c.Approval) || !label(c.Name, 160, false) || c.Fingerprint != "" && !validFingerprint(c.Fingerprint) {
		return connection{}, errRefused
	}
	c.Revision = revision
	return c, nil
}
func (s *Store) putConnection(owner string, c connection) (string, error) {
	if !validID(owner) || c.ID != "" || c.Revision != 0 || !validID(c.Target) || !validID(c.Credential) || !validApproval(c.Approval) || !label(c.Name, 160, false) || !validFingerprint(c.Fingerprint) {
		return "", errRefused
	}
	id, e := randomID()
	if e != nil {
		return "", e
	}
	c.ID = id
	e = s.update(func(tx *bolt.Tx) error {
		if _, e := s.readAccount(tx, owner); e != nil {
			return e
		}
		if _, e := s.credential(tx, owner, c.Credential); e != nil {
			return e
		}
		b, e := tx.CreateBucketIfNotExists(connectionBucket)
		if e != nil {
			return e
		}
		if b.Stats().KeyN >= 2048 || b.Get(credentialKey(owner, id)) != nil {
			return errRefused
		}
		count := 0
		cursor := b.Cursor()
		prefix := []byte(owner + "/")
		for k, _ := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = cursor.Next() {
			count++
		}
		if count >= 128 {
			return errRefused
		}
		plain, e := json.Marshal(c)
		if e != nil {
			return e
		}
		defer clear(plain)
		sealed, e := s.seal(tx, "connection", owner, id, 1, plain)
		if e != nil {
			return e
		}
		return b.Put(credentialKey(owner, id), sealed)
	})
	if e != nil {
		return "", errRefused
	}
	return id, nil
}

// A fresh owner's explicit comparison is bound to the current catalog snapshot
// and to the exact previous encrypted revision. A stale browser cannot replace
// a newer decision. No target address, credential or owner is accepted here.
func (s *Store) trustConnection(owner, id, expected, approval, fingerprint string) error {
	revision, e := strconv.ParseUint(expected, 10, 64)
	if e != nil || revision == 0 || revision >= 1<<31 || strconv.FormatUint(revision, 10) != expected || !validApproval(approval) || !validFingerprint(fingerprint) {
		return errRefused
	}
	return s.update(func(tx *bolt.Tx) error {
		c, e := s.connection(tx, owner, id)
		if e != nil || c.Revision != revision {
			return errRefused
		}
		if _, e = s.credential(tx, owner, c.Credential); e != nil {
			return errRefused
		}
		c.Approval, c.Fingerprint = approval, fingerprint
		plain, e := json.Marshal(c)
		if e != nil {
			return errRefused
		}
		defer clear(plain)
		sealed, e := s.seal(tx, "connection", owner, id, revision+1, plain)
		if e != nil {
			return errRefused
		}
		return tx.Bucket(connectionBucket).Put(credentialKey(owner, id), sealed)
	})
}
func (s *Store) readConnection(owner, id string) (connection, error) {
	var c connection
	e := s.view(func(tx *bolt.Tx) error { var e error; c, e = s.connection(tx, owner, id); return e })
	return c, e
}
func (s *Store) listConnections(owner string) ([]connection, error) {
	result := make([]connection, 0)
	e := s.view(func(tx *bolt.Tx) error {
		if _, e := s.readAccount(tx, owner); e != nil {
			return e
		}
		b := tx.Bucket(connectionBucket)
		if b == nil {
			return nil
		}
		cursor := b.Cursor()
		prefix := []byte(owner + "/")
		for k, _ := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = cursor.Next() {
			if len(result) >= 128 {
				return errRefused
			}
			c, e := s.connection(tx, owner, string(k[len(prefix):]))
			if e != nil {
				return e
			}
			result = append(result, c)
		}
		return nil
	})
	return result, e
}
func (s *Store) deleteConnection(owner, id string) error {
	return s.update(func(tx *bolt.Tx) error {
		if _, e := s.connection(tx, owner, id); e != nil {
			return e
		}
		return tx.Bucket(connectionBucket).Delete(credentialKey(owner, id))
	})
}
