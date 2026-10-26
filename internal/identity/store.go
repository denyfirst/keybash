package identity

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var metaBucket = []byte("meta-v1")
var accountBucket = []byte("accounts-v1")
var nameBucket = []byte("names-v1")
var credentialBucket = []byte("credentials-v1")
var metaKey = []byte("state")

type storeMeta struct {
	Version      int
	Instance     string
	Bootstrap    [32]byte
	BootstrapEnd int64
	Initialized  bool
	Seals        uint64
	MAC          []byte
}

// Store uses an exclusive, fsynced bbolt file. Only authenticated encrypted
// account/credential envelopes and keyed username indexes enter that file.
// The 32-byte instance key belongs outside the data directory and DB backups.
type Store struct {
	mu                 sync.RWMutex
	db                 *bolt.DB
	root               *os.Root
	instance           string
	wrap               cipher.AEAD
	indexKey, checkKey [32]byte
	recoveryKey        [32]byte
	closed             bool
}

func (*Store) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[custody store redacted]") }

type sealedRecord struct {
	Version   int
	Revision  uint64
	Key, Data []byte
}
type storedHash struct {
	Version byte
	Salt    [16]byte
	Sum     [32]byte
}
type durableAccount struct {
	ID, Username string
	Hash         storedHash
	Revision     uint64
	Seed         string
	LastCounter  int64
	Recovery     [][32]byte
	FactorWindow int64
	FactorCount  int
	// Digest and expiry of the one-time setup code an operator hands over
	// with a new or factor-reset account; zero once MFA is enrolled.
	Enrollment    [32]byte
	EnrollmentEnd int64
}

// A password alone must not let whoever learns it first enroll their own
// factor. Operator-created and factor-reset accounts need this separate
// one-time code, which expires so an unclaimed account cannot be taken later.
const enrollmentLife = 72 * time.Hour

func issueEnrollment(a *durableAccount, now time.Time) (string, error) {
	code, e := token()
	if e != nil {
		return "", errRefused
	}
	a.Enrollment, _ = tokenID(code)
	a.EnrollmentEnd = now.Add(enrollmentLife).Unix()
	return code, nil
}

func (durableAccount) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[account redacted]") }
func storedPassword(p PasswordHash) storedHash    { return storedHash{p.version, p.salt, p.sum} }
func (a durableAccount) password() PasswordHash {
	return PasswordHash{a.Hash.Version, a.Hash.Salt, a.Hash.Sum}
}
func randomID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", errRefused
	}
	return hex.EncodeToString(b[:]), nil
}
func validID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == id
}

func decodeRecord(data []byte, value any, limit int) error {
	if len(data) == 0 || len(data) > limit || !scalarJSON(data) {
		return errRefused
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errRefused
	}
	return nil
}
func (s *Store) meta(tx *bolt.Tx) (storeMeta, error) {
	var m storeMeta
	for _, name := range [][]byte{metaBucket, accountBucket, nameBucket, credentialBucket} {
		if tx.Bucket(name) == nil {
			return m, errRefused
		}
	}
	if tx.Bucket(metaBucket) == nil || decodeRecord(tx.Bucket(metaBucket).Get(metaKey), &m, 2048) != nil || m.Version != 1 || m.Instance != s.instance || m.Seals > 1<<31 {
		return m, errRefused
	}
	tag := m.MAC
	m.MAC = nil
	data, _ := json.Marshal(m)
	h := hmac.New(sha256.New, s.checkKey[:])
	_, _ = h.Write(data)
	if subtle.ConstantTimeCompare(tag, h.Sum(nil)) != 1 {
		return m, errRefused
	}
	m.MAC = tag
	return m, nil
}
func (s *Store) putMeta(tx *bolt.Tx, m storeMeta) error {
	m.MAC = nil
	data, err := json.Marshal(m)
	if err != nil {
		return errRefused
	}
	h := hmac.New(sha256.New, s.checkKey[:])
	_, _ = h.Write(data)
	m.MAC = h.Sum(nil)
	data, err = json.Marshal(m)
	if err != nil {
		return errRefused
	}
	return tx.Bucket(metaBucket).Put(metaKey, data)
}
func (s *Store) nameIndex(name string) []byte {
	h := hmac.New(sha256.New, s.indexKey[:])
	_, _ = h.Write([]byte(name))
	return h.Sum(nil)
}
func (s *Store) aad(kind, owner, id string, revision uint64) []byte {
	return []byte(fmt.Sprintf("keybash/v1/%s/%s/%s/%s/%d", s.instance, kind, owner, id, revision))
}
func randomGCM(key []byte) (cipher.AEAD, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, errRefused
	}
	return cipher.NewGCMWithRandomNonce(b)
}
func (s *Store) seal(tx *bolt.Tx, kind, owner, id string, revision uint64, plain []byte) ([]byte, error) {
	if !validID(owner) || !validID(id) || revision == 0 || len(plain) > 96*1024 {
		return nil, errRefused
	}
	m, e := s.meta(tx)
	if e != nil || m.Seals >= 1<<31 {
		return nil, errRefused
	}
	var key [32]byte
	if _, e = rand.Read(key[:]); e != nil {
		return nil, errRefused
	}
	defer clear(key[:])
	aead, e := randomGCM(key[:])
	if e != nil {
		return nil, e
	}
	aad := s.aad(kind, owner, id, revision)
	// Both AEADs are exclusively constructed by NewGCMWithRandomNonce;
	// its API requires a nil nonce and internally generates/prefixes randomness.
	wrapped := s.wrap.Seal(nil, nil, key[:], append([]byte("wrap/"), aad...)) // #nosec G407 -- required random-nonce GCM API, never a fixed IV.
	data := aead.Seal(nil, nil, plain, append([]byte("data/"), aad...))       // #nosec G407 -- required random-nonce GCM API, never a fixed IV.
	r := sealedRecord{Version: 1, Revision: revision, Key: wrapped, Data: data}
	m.Seals++
	if s.putMeta(tx, m) != nil {
		return nil, errRefused
	}
	return json.Marshal(r)
}
func (s *Store) unseal(kind, owner, id string, data []byte) ([]byte, uint64, error) {
	var r sealedRecord
	if !validID(owner) || !validID(id) || decodeRecord(data, &r, 160*1024) != nil || r.Version != 1 || r.Revision == 0 || len(r.Key) != 60 || len(r.Data) < 28 || len(r.Data) > 96*1024+28 {
		return nil, 0, errRefused
	}
	aad := s.aad(kind, owner, id, r.Revision)
	key, e := s.wrap.Open(nil, nil, r.Key, append([]byte("wrap/"), aad...))
	if e != nil {
		return nil, 0, errRefused
	}
	defer clear(key)
	aead, e := randomGCM(key)
	if e != nil {
		return nil, 0, errRefused
	}
	plain, e := aead.Open(nil, nil, r.Data, append([]byte("data/"), aad...))
	if e != nil {
		return nil, 0, errRefused
	}
	return plain, r.Revision, nil
}

// InitializeStore requires an existing private Linux directory and a separately
// provisioned instance key. It never replaces an existing file. The returned
// bootstrap code is for the local operator, not a URL, environment or service log.
func InitializeStore(dir string, key []byte) (*Store, string, error) {
	if privateDirectory(dir) != nil {
		return nil, "", errRefused
	}
	return createStore(dir, key)
}
func OpenStore(dir string, key []byte) (*Store, error) {
	if privateDirectory(dir) != nil {
		return nil, errRefused
	}
	return openStore(dir, key, false)
}
func createStore(dir string, key []byte) (*Store, string, error) {
	if len(key) != 32 {
		return nil, "", errRefused
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, "", errRefused
	}
	f, e := r.OpenFile("custody.db", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		_ = r.Close()
		return nil, "", errRefused
	}
	if f.Sync() != nil {
		_ = f.Close()
		_ = r.Close()
		return nil, "", errRefused
	}
	_ = f.Close()
	_ = r.Close()
	s, e := openStore(dir, key, true)
	if e != nil {
		return nil, "", errRefused
	}
	code, e := token()
	if e != nil {
		_ = s.Close()
		return nil, "", errRefused
	}
	digest, _ := tokenID(code)
	e = s.update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{metaBucket, accountBucket, nameBucket, credentialBucket} {
			if _, e := tx.CreateBucket(name); e != nil {
				return e
			}
		}
		return s.putMeta(tx, storeMeta{Version: 1, Instance: s.instance, Bootstrap: digest, BootstrapEnd: time.Now().Add(15 * time.Minute).Unix()})
	})
	if e != nil {
		_ = s.Close()
		return nil, "", errRefused
	}
	return s, code, nil
}
func openStore(dir string, key []byte, initial bool) (*Store, error) {
	if len(key) != 32 {
		return nil, errRefused
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, errRefused
	}
	if runtime.GOOS == "linux" && privateRoot(r) != nil {
		_ = r.Close()
		return nil, errRefused
	}
	s := &Store{root: r}
	ok := false
	defer func() {
		if !ok {
			if s.db != nil {
				_ = s.db.Close()
			}
			_ = r.Close()
		}
	}()
	info, e := r.Lstat("custody.db")
	if e != nil || !info.Mode().IsRegular() {
		return nil, errRefused
	}
	s.db, e = bolt.Open("custody.db", 0600, &bolt.Options{Timeout: time.Second, MaxSize: 256 * 1024 * 1024,
		OpenFile: func(_ string, flags int, mode os.FileMode) (*os.File, error) {
			// Root prevents escaping the pinned directory. Reject symlinks and
			// changed entries as well; host administrator compromise is excluded.
			f, e := r.OpenFile("custody.db", flags&^os.O_CREATE, mode)
			if e != nil {
				return nil, e
			}
			now, e := r.Lstat("custody.db")
			actual, se := f.Stat()
			if e != nil || se != nil || !now.Mode().IsRegular() || !os.SameFile(info, actual) || !os.SameFile(now, actual) {
				_ = f.Close()
				return nil, errRefused
			}
			return f, nil
		}})
	if e != nil {
		return nil, errRefused
	}
	if initial {
		s.instance, e = randomID()
	} else {
		e = s.db.View(func(tx *bolt.Tx) error {
			var m storeMeta
			if tx.Bucket(metaBucket) == nil || decodeRecord(tx.Bucket(metaBucket).Get(metaKey), &m, 2048) != nil || m.Version != 1 || !validID(m.Instance) {
				return errRefused
			}
			s.instance = m.Instance
			return nil
		})
	}
	if e != nil {
		return nil, errRefused
	}
	salt, _ := hex.DecodeString(s.instance)
	for _, item := range []struct {
		name   string
		target *[32]byte
	}{{"index", &s.indexKey}, {"check", &s.checkKey}, {"recovery", &s.recoveryKey}} {
		b, e := hkdf.Key(sha256.New, key, salt, "keybash/custody/v1/"+item.name, 32)
		if e != nil {
			return nil, errRefused
		}
		copy(item.target[:], b)
		clear(b)
	}
	wrapKey, e := hkdf.Key(sha256.New, key, salt, "keybash/custody/v1/wrap", 32)
	if e != nil {
		return nil, errRefused
	}
	s.wrap, e = randomGCM(wrapKey)
	clear(wrapKey)
	if e != nil {
		return nil, errRefused
	}
	if !initial {
		if e = s.db.View(func(tx *bolt.Tx) error { _, e := s.meta(tx); return e }); e != nil {
			return nil, errRefused
		}
	}
	ok = true
	return s, nil
}
func (s *Store) view(fn func(*bolt.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errRefused
	}
	if s.db.View(fn) != nil {
		return errRefused
	}
	return nil
}
func (s *Store) update(fn func(*bolt.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errRefused
	}
	if s.db.Update(fn) != nil {
		return errRefused
	}
	return nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	e := s.db.Close()
	_ = s.root.Close()
	clear(s.indexKey[:])
	clear(s.checkKey[:])
	clear(s.recoveryKey[:])
	s.wrap = nil
	if e != nil {
		return errRefused
	}
	return nil
}

func (s *Store) readAccount(tx *bolt.Tx, id string) (durableAccount, error) {
	var a durableAccount
	if _, e := s.meta(tx); e != nil {
		return a, e
	}
	b := tx.Bucket(accountBucket)
	if b == nil {
		return a, errRefused
	}
	plain, rev, e := s.unseal("account", id, id, b.Get([]byte(id)))
	if e != nil {
		return a, e
	}
	defer clear(plain)
	if decodeRecord(plain, &a, 16*1024) != nil || a.ID != id || !usernameInput(a.Username) || !a.password().valid() || a.Revision != rev || len(a.Recovery) > 10 || a.LastCounter < -1 || a.FactorCount < 0 || a.FactorCount > 5 {
		return durableAccount{}, errRefused
	}
	if a.Seed != "" && !validSeed(a.Seed) || a.EnrollmentEnd < 0 || a.Seed != "" && (a.EnrollmentEnd != 0 || a.Enrollment != [32]byte{}) {
		return durableAccount{}, errRefused
	}
	return a, nil
}
func (s *Store) saveAccount(tx *bolt.Tx, a durableAccount) error {
	plain, e := json.Marshal(a)
	if e != nil {
		return errRefused
	}
	defer clear(plain)
	sealed, e := s.seal(tx, "account", a.ID, a.ID, a.Revision, plain)
	if e != nil {
		return e
	}
	return tx.Bucket(accountBucket).Put([]byte(a.ID), sealed)
}
func (s *Store) lookup(username string) (durableAccount, error) {
	var a durableAccount
	e := s.view(func(tx *bolt.Tx) error {
		if _, e := s.meta(tx); e != nil {
			return e
		}
		b := tx.Bucket(nameBucket)
		if b == nil {
			return errRefused
		}
		id := b.Get(s.nameIndex(username))
		if id == nil {
			return errRefused
		}
		var e error
		a, e = s.readAccount(tx, string(id))
		if e != nil || a.Username != username {
			return errRefused
		}
		return nil
	})
	return a, e
}
func (s *Store) initialized() (bool, error) {
	var ready bool
	e := s.view(func(tx *bolt.Tx) error { m, e := s.meta(tx); ready = m.Initialized; return e })
	return ready, e
}
func (s *Store) bootstrapValid(code string, now time.Time) bool {
	digest, ok := tokenID(code)
	if !ok {
		return false
	}
	return s.view(func(tx *bolt.Tx) error {
		m, e := s.meta(tx)
		if e != nil || m.Initialized || now.Unix() >= m.BootstrapEnd || subtle.ConstantTimeCompare(digest[:], m.Bootstrap[:]) != 1 {
			return errRefused
		}
		return nil
	}) == nil
}

// setup is the one-time enrollment code to issue, or "" when the caller has
// already proved operator authority (the bootstrap code).
func (s *Store) createAccount(tx *bolt.Tx, name string, hash PasswordHash, now time.Time, withSetup bool) (durableAccount, string, error) {
	a := durableAccount{}
	if !usernameInput(name) || !hash.valid() || tx.Bucket(nameBucket).Get(s.nameIndex(name)) != nil || tx.Bucket(accountBucket).Stats().KeyN >= 256 {
		return a, "", errRefused
	}
	id, e := randomID()
	if e != nil {
		return a, "", e
	}
	if tx.Bucket(accountBucket).Get([]byte(id)) != nil {
		return a, "", errRefused
	}
	a = durableAccount{ID: id, Username: name, Hash: storedPassword(hash), Revision: 1, LastCounter: -1}
	setup := ""
	if withSetup {
		if setup, e = issueEnrollment(&a, now); e != nil {
			return durableAccount{}, "", e
		}
	}
	if s.saveAccount(tx, a) != nil || tx.Bucket(nameBucket).Put(s.nameIndex(name), []byte(id)) != nil {
		return durableAccount{}, "", errRefused
	}
	return a, setup, nil
}

// enrollmentValid checks an operator-issued first-enrollment code for an
// account that has no factor yet. It never consumes the code; enroll does.
func (s *Store) enrollmentValid(id, code string, now time.Time) bool {
	digest, ok := tokenID(code)
	if !ok {
		return false
	}
	return s.view(func(tx *bolt.Tx) error {
		a, e := s.readAccount(tx, id)
		if e != nil || a.Seed != "" || now.Unix() >= a.EnrollmentEnd || subtle.ConstantTimeCompare(digest[:], a.Enrollment[:]) != 1 {
			return errRefused
		}
		return nil
	}) == nil
}
func (s *Store) bootstrap(code, name string, hash PasswordHash, now time.Time) error {
	digest, ok := tokenID(code)
	if !ok {
		return errRefused
	}
	return s.update(func(tx *bolt.Tx) error {
		m, e := s.meta(tx)
		if e != nil || m.Initialized || now.Unix() >= m.BootstrapEnd || subtle.ConstantTimeCompare(digest[:], m.Bootstrap[:]) != 1 || tx.Bucket(accountBucket).Stats().KeyN != 0 {
			return errRefused
		}
		if _, _, e = s.createAccount(tx, name, hash, now, false); e != nil {
			return e
		}
		m, e = s.meta(tx)
		if e != nil {
			return e
		}
		m.Initialized = true
		clear(m.Bootstrap[:])
		m.BootstrapEnd = 0
		return s.putMeta(tx, m)
	})
}

// CreateAccount is an offline operator operation: the exclusive DB lock prevents
// running it beside the service. HTTP has no registration or owner selector.
// The returned one-time setup code is required, with the password, for the
// account's first MFA enrollment; hand both over separately.
func (s *Store) CreateAccount(name, password string) (string, error) {
	h, e := HashPassword(password)
	if e != nil {
		return "", e
	}
	var setup string
	e = s.update(func(tx *bolt.Tx) error {
		m, e := s.meta(tx)
		if e != nil || !m.Initialized {
			return errRefused
		}
		_, setup, e = s.createAccount(tx, name, h, time.Now(), true)
		return e
	})
	if e != nil {
		return "", errRefused
	}
	return setup, nil
}

// RenewBootstrap is an offline operator action. It cannot reopen registration
// after the first account has been created. Prior setup codes are invalidated.
func (s *Store) RenewBootstrap() (string, error) {
	code, e := token()
	if e != nil {
		return "", errRefused
	}
	digest, _ := tokenID(code)
	e = s.update(func(tx *bolt.Tx) error {
		m, e := s.meta(tx)
		if e != nil || m.Initialized || tx.Bucket(accountBucket).Stats().KeyN != 0 {
			return errRefused
		}
		m.Bootstrap, m.BootstrapEnd = digest, time.Now().Add(15*time.Minute).Unix()
		return s.putMeta(tx, m)
	})
	if e != nil {
		return "", errRefused
	}
	return code, nil
}

// RecoverAccount requires the local instance key and exclusive DB lock. This
// trusted operator operation is deliberately absent from the HTTP router.
// Password replacement and optional lost-factor reset commit atomically. An
// account left without a factor gets a fresh one-time setup code, returned
// here; one that keeps its factor returns "".
func (s *Store) RecoverAccount(name, password string, lostFactor bool) (string, error) {
	next, e := HashPassword(password)
	if e != nil {
		return "", e
	}
	var setup string
	e = s.update(func(tx *bolt.Tx) error {
		if _, e := s.meta(tx); e != nil {
			return e
		}
		id := tx.Bucket(nameBucket).Get(s.nameIndex(name))
		a, e := s.readAccount(tx, string(id))
		if e != nil || a.Username != name {
			return errRefused
		}
		a.Hash = storedPassword(next)
		a.Revision++
		if lostFactor {
			a.Seed = ""
			a.Recovery = nil
			a.LastCounter = -1
		}
		if a.Seed == "" {
			if setup, e = issueEnrollment(&a, time.Now()); e != nil {
				return e
			}
		}
		return s.saveAccount(tx, a)
	})
	if e != nil {
		return "", errRefused
	}
	return setup, nil
}
