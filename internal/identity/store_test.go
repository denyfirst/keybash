package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// Portable fixtures bypass only production OS permission admission, using
// synthetic keys/files. Exported custody initialization remains Linux-only.
func custodyFixture(t *testing.T) (*Store, []byte, string, string) {
	t.Helper()
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal("fixture entropy failed")
	}
	dir := t.TempDir()
	s, code, e := createStore(dir, key)
	if e != nil {
		t.Fatal("valid custody initialization refused")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, key, dir, code
}
func bootstrapped(t *testing.T) (*Store, []byte, string) {
	t.Helper()
	s, key, dir, code := custodyFixture(t)
	if s.bootstrap(code, "alice", accounts(t)[0].Password, time.Now()) != nil {
		t.Fatal("valid bootstrap refused")
	}
	return s, key, dir
}
func otpCode(t *testing.T, seed string, counter int64) string {
	t.Helper()
	code, e := hotp.GenerateCode(seed, uint64(counter))
	if e != nil {
		t.Fatal("fixture OTP failed")
	}
	return code
}
func enrollFixture(t *testing.T, s *Store, name string, now time.Time) (durableAccount, string, recoveryCodes) {
	t.Helper()
	a, e := s.lookup(name)
	if e != nil {
		t.Fatal("fixture account absent")
	}
	seed, e := newSeed()
	if e != nil {
		t.Fatal("fixture MFA entropy failed")
	}
	codes, e := s.enroll(a.ID, a.Revision, seed, otpCode(t, seed, now.Unix()/30-1), now, false)
	if e != nil {
		t.Fatal("valid MFA enrollment refused")
	}
	a, e = s.lookup(name)
	if e != nil {
		t.Fatal("enrolled account absent")
	}
	return a, seed, codes
}
func TestCustodyBootstrapSingleUseExpiryAndExclusiveOpen(t *testing.T) {
	s, key, dir, code := custodyFixture(t)
	if s.bootstrapValid(strings.Repeat("a", 43), time.Now()) || s.bootstrapValid(code, time.Now().Add(16*time.Minute)) {
		t.Fatal("wrong or expired bootstrap accepted")
	}
	if !s.bootstrapValid(code, time.Now()) {
		t.Fatal("valid bootstrap denied")
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for _, name := range []string{"alice", "bob"} {
		wg.Go(func() {
			if s.bootstrap(code, name, accounts(t)[0].Password, time.Now()) == nil {
				success.Add(1)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 || s.bootstrapValid(code, time.Now()) {
		t.Fatal("bootstrap was not consumed atomically once")
	}
	if duplicate, e := openStore(dir, key, false); e == nil {
		_ = duplicate.Close()
		t.Fatal("second database writer admitted")
	}
	if replacement, _, e := createStore(dir, key); e == nil {
		_ = replacement.Close()
		t.Fatal("existing custody store replaced")
	}
	_ = s.Close()
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	before, e := os.ReadFile(filepath.Join(dir, "custody.db"))
	if e != nil {
		t.Fatal("fixture DB read failed")
	}
	if other, e := openStore(dir, wrong, false); e == nil {
		_ = other.Close()
		t.Fatal("wrong instance key opened custody")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "custody.db"))
	if !bytes.Equal(before, after) {
		t.Fatal("failed key check changed database")
	}
	reopened, e := openStore(dir, key, false)
	if e != nil {
		t.Fatal("correct key could not reopen custody")
	}
	defer reopened.Close()
	ready, e := reopened.initialized()
	if e != nil || !ready {
		t.Fatal("bootstrap state did not persist")
	}
}
func TestCustodyMFAReplayRecoveryAndRestart(t *testing.T) {
	s, key, dir := bootstrapped(t)
	now := time.Now()
	a, seed, codes := enrollFixture(t, s, "alice", now)
	if s.consumeFactor(a.ID, a.Revision, otpCode(t, seed, now.Unix()/30-1), now) == nil {
		t.Fatal("enrollment OTP replay accepted")
	}
	code := otpCode(t, seed, now.Unix()/30)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if s.consumeFactor(a.ID, a.Revision, code, now) == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("concurrent TOTP was not single-use")
	}
	_ = s.Close()
	s, e := openStore(dir, key, false)
	if e != nil {
		t.Fatal("MFA store restart failed")
	}
	defer s.Close()
	if s.consumeFactor(a.ID, a.Revision, code, now.Add(time.Minute)) == nil {
		t.Fatal("old TOTP accepted after restart")
	}
	if s.consumeFactor(a.ID, a.Revision, codes[0], now.Add(2*time.Minute)) != nil {
		t.Fatal("valid recovery code refused")
	}
	if s.consumeFactor(a.ID, a.Revision, codes[0], now.Add(3*time.Minute)) == nil {
		t.Fatal("recovery code replay accepted")
	}
	if s.consumeFactor(a.ID, a.Revision, otpCode(t, seed, now.Add(4*time.Minute).Unix()/30), now.Add(4*time.Minute)) != nil {
		t.Fatal("later valid TOTP refused")
	}
}
func TestCustodyFactorFailuresPersistAndReplacementKeepsOldMFA(t *testing.T) {
	s, key, dir := bootstrapped(t)
	now := time.Now()
	a, seed, _ := enrollFixture(t, s, "alice", now)
	for range 4 {
		if s.consumeFactor(a.ID, a.Revision, "invalid", now) == nil {
			t.Fatal("invalid MFA accepted")
		}
	}
	_ = s.Close()
	s, e := openStore(dir, key, false)
	if e != nil {
		t.Fatal("factor budget restart failed")
	}
	defer s.Close()
	if s.consumeFactor(a.ID, a.Revision, otpCode(t, seed, now.Unix()/30), now) == nil {
		t.Fatal("factor budget reset on process restart")
	}
	newSeed, e := newSeed()
	if e != nil {
		t.Fatal("fixture seed failed")
	}
	if s.enrollAcceptsWrongMode(t, a, newSeed, now) {
		t.Fatal("active MFA replaced without replacement authority")
	}
	if _, e = s.enroll(a.ID, a.Revision, newSeed, otpCode(t, newSeed, now.Add(time.Minute).Unix()/30), now.Add(time.Minute), true); e != nil {
		t.Fatal("authorized MFA replacement refused")
	}
	updated, e := s.lookup("alice")
	if e != nil || updated.ID != a.ID || updated.Revision <= a.Revision || updated.Seed != newSeed {
		t.Fatal("MFA replacement lost stable identity or revision")
	}
	if s.consumeFactor(a.ID, a.Revision, otpCode(t, seed, now.Add(2*time.Minute).Unix()/30), now.Add(2*time.Minute)) == nil {
		t.Fatal("old MFA generation remained usable")
	}
}
func (s *Store) enrollAcceptsWrongMode(t *testing.T, a durableAccount, seed string, now time.Time) bool {
	t.Helper()
	_, e := s.enroll(a.ID, a.Revision, seed, otpCode(t, seed, now.Unix()/30), now, false)
	return e == nil
}

func TestCustodyCiphertextOwnerBindingTamperAndPlaintextAbsence(t *testing.T) {
	s, key, dir := bootstrapped(t)
	if s.CreateAccount("bob", bobPassword) != nil {
		t.Fatal("offline account creation refused")
	}
	now := time.Now()
	alice, seed, codes := enrollFixture(t, s, "alice", now)
	bob, e := s.lookup("bob")
	if e != nil {
		t.Fatal("second account absent")
	}
	canary := "CUSTODY-SYNTHETIC-SECRET-CANARY-91d"
	c := Credential{Name: "private-label-canary-84c", Kind: "password", Username: "remote-user", Secret: canary}
	if validateCredential(&c) != nil {
		t.Fatal("valid password credential refused")
	}
	id, e := s.putCredential(alice.ID, c)
	if e != nil {
		t.Fatal("valid owned credential refused")
	}
	got, e := s.readCredential(alice.ID, id)
	if e != nil || got.Secret != canary {
		t.Fatal("credential content changed")
	}
	if _, e = s.readCredential(bob.ID, id); e == nil {
		t.Fatal("cross-owner credential opened")
	}
	if s.deleteCredential(bob.ID, id) == nil {
		t.Fatal("cross-owner credential deleted")
	}
	items, e := s.listCredentials(alice.ID)
	if e != nil || len(items) != 1 || items[0].Name != c.Name {
		t.Fatal("credential metadata listing failed")
	}
	meta, _ := json.Marshal(items)
	if bytes.Contains(meta, []byte(canary)) || bytes.Contains(meta, []byte("passphrase")) {
		t.Fatal("metadata endpoint leaked secret fields")
	}
	data, e := os.ReadFile(filepath.Join(dir, "custody.db"))
	if e != nil {
		t.Fatal("fixture DB read failed")
	}
	for _, secret := range []string{canary, c.Name, seed, codes[0], alicePassword, string(key)} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("plaintext secret entered database")
		}
	}
	var original []byte
	if e = s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(credentialBucket)
		original = append([]byte(nil), b.Get(credentialKey(alice.ID, id))...)
		return b.Put(credentialKey(bob.ID, id), original)
	}); e != nil {
		t.Fatal("tamper fixture failed")
	}
	if _, e = s.readCredential(bob.ID, id); e == nil {
		t.Fatal("ciphertext rebind to another owner accepted")
	}
	if e = s.update(func(tx *bolt.Tx) error {
		var record sealedRecord
		if json.Unmarshal(original, &record) != nil {
			return errRefused
		}
		record.Data[len(record.Data)-1] ^= 1
		b, _ := json.Marshal(record)
		return tx.Bucket(credentialBucket).Put(credentialKey(alice.ID, id), b)
	}); e != nil {
		t.Fatal("tamper fixture failed")
	}
	if _, e = s.readCredential(alice.ID, id); e == nil {
		t.Fatal("modified ciphertext accepted")
	}
	if strings.Contains(fmt.Sprintf("%+v", got), canary) || strings.Contains(fmt.Sprintf("%+v", alice), seed) {
		t.Fatal("secret formatting was not redacted")
	}
}
func TestCustodySSHImportBoundsAndPasswordBlocklist(t *testing.T) {
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture key generation failed")
	}
	for _, encrypted := range []bool{false, true} {
		var block *pem.Block
		pass := ""
		if encrypted {
			pass = "Synthetic private passphrase"
			block, e = ssh.MarshalPrivateKeyWithPassphrase(private, "synthetic", []byte(pass))
		} else {
			block, e = ssh.MarshalPrivateKey(private, "synthetic")
		}
		if e != nil {
			t.Fatal("fixture key encoding failed")
		}
		c := Credential{Name: "ssh-test", Kind: "ssh-key", Secret: string(pem.EncodeToMemory(block)), Passphrase: pass}
		if validateCredential(&c) != nil || !strings.HasPrefix(c.Fingerprint, "SHA256:") {
			t.Fatal("valid Ed25519 key import refused")
		}
		if encrypted {
			c.Passphrase = "wrong"
			if validateCredential(&c) == nil {
				t.Fatal("wrong key passphrase accepted")
			}
		}
	}
	for _, c := range []Credential{{Name: "bad", Kind: "ssh-key", Secret: "not a private key"}, {Name: "bad", Kind: "password", Secret: "ok", Passphrase: "unexpected"}, {Name: "bad\u202e", Kind: "password", Secret: "ok"}} {
		if validateCredential(&c) == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	for _, password := range []string{"passwordpassword", "correcthorsebatterystaple", strings.Repeat("ş", 15)} {
		if _, e := HashPassword(password); e == nil {
			t.Fatal("blocked password accepted")
		}
	}
	data, e := os.ReadFile("password-blocklist.txt")
	if e != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != "68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce" {
		t.Fatal("password blocklist inventory changed")
	}
}
func TestPersistentPasswordSessionsCannotOpenVault(t *testing.T) {
	s, _, _ := bootstrapped(t)
	l, e := NewPersistent("https://127.0.0.1:9443", s)
	if e != nil {
		t.Fatal("persistent identity refused")
	}
	defer l.Close()
	raw := signIn(t, l, "alice", alicePassword, "")
	if respond(l, request(l, "GET", "/api/credentials", "", raw)).Code != 403 {
		t.Fatal("password-only session opened vault")
	}
	l.mu.Lock()
	id, _ := tokenID(raw)
	active := l.sessions[id]
	l.mu.Unlock()
	if active.stage != "enroll" {
		t.Fatal("MFA enrollment not required")
	}
	_ = l.Close()
	ctx := context.Background()
	if _, e = l.login(ctx, "alice", alicePassword, ""); e == nil {
		t.Fatal("closed persistent service accepted login")
	}
}
