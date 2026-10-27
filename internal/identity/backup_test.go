package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

func emptyDataDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "restore")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("private fixture directory creation failed")
	}
	return dir
}

func backupOf(t *testing.T, s *Store, now time.Time) []byte {
	t.Helper()
	var out bytes.Buffer
	if _, e := s.Backup(&out, now); e != nil {
		t.Fatal("valid backup refused")
	}
	return out.Bytes()
}

func encodeBody(schema uint32, program string, entries []backupEntry) []byte {
	var raw []byte
	for _, entry := range entries {
		raw = append(raw, ssh.Marshal(&backupEntry{Bucket: entry.Bucket, Key: entry.Key, Value: entry.Value})...)
	}
	return ssh.Marshal(&backupBody{Schema: schema, Program: program, Entries: raw})
}

// openBackup decrypts a fixture backup with the store's own key, so a test
// can change the body and seal it again: only the change can refuse.
func openBackup(t *testing.T, s *Store, data []byte) (backupHeader, []byte, []backupEntry) {
	t.Helper()
	header, aad, sealed, e := parseBackupFile(data)
	if e != nil {
		t.Fatal("fixture backup did not parse")
	}
	aead, e := backupAEAD(s.backupKey[:], header.Salt)
	if e != nil {
		t.Fatal("fixture backup key failed")
	}
	body, e := aead.Open(nil, nil, sealed, aad)
	if e != nil {
		t.Fatal("fixture backup did not open")
	}
	entries, _, e := parseBackupBody(body)
	if e != nil {
		t.Fatal("fixture backup body did not parse")
	}
	return header, aad, entries
}

func sealBackup(t *testing.T, s *Store, header backupHeader, body []byte) []byte {
	t.Helper()
	aad := ssh.Marshal(&header)
	aead, e := backupAEAD(s.backupKey[:], header.Salt)
	if e != nil {
		t.Fatal("fixture backup key failed")
	}
	return ssh.Marshal(&backupFile{Header: aad, Sealed: aead.Seal(nil, nil, body, aad)})
}

func refuseRestore(t *testing.T, name string, key, data []byte) {
	t.Helper()
	dir := emptyDataDir(t)
	if s, _, _, e := restoreStore(dir, key, data, time.Now()); e == nil {
		_ = s.Close()
		t.Fatalf("%s backup restored", name)
	}
	if left, e := os.ReadDir(dir); e != nil || len(left) != 0 {
		t.Fatalf("refused %s restore left files behind", name)
	}
}

func TestBackupRestoresEveryRecordAndResetsMFA(t *testing.T) {
	s, key, _ := bootstrapped(t)
	now := time.Now()
	alice, seed, recovery := enrollFixture(t, s, "alice", now)
	if _, e := s.CreateAccount("bob", bobPassword); e != nil {
		t.Fatal("fixture second account refused")
	}
	_, userKey, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(userKey, "synthetic")
	saved := map[string]Credential{}
	var passwordID string
	for _, c := range []Credential{
		{Name: "Synthetic backup password canary", Kind: "password", Username: "deploy", Secret: "Synthetic remote şifrə 1!"},
		{Name: "Synthetic backup key canary", Kind: "ssh-key", Username: "deploy", Secret: string(pem.EncodeToMemory(block))},
	} {
		if validateCredential(&c) != nil {
			t.Fatal("fixture credential invalid")
		}
		id, e := s.putCredential(alice.ID, c)
		if e != nil {
			t.Fatal("fixture credential refused")
		}
		if c.Kind == "password" {
			passwordID = id
		}
		saved[id] = c
	}
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	ip := netip.MustParseAddr("10.34.0.9")
	policy, e := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 22)}, nil)
	if e != nil {
		t.Fatal(e)
	}
	named, e := targetguard.NewNamedTarget(policy, "ssh.invalid", 22, []netip.Addr{ip})
	if e != nil {
		t.Fatal(e)
	}
	target := RemoteTarget{strings.Repeat("c", 32), "Synthetic SSH", "ssh", named, hostSigner.PublicKey().Marshal()}
	connectionName := "Synthetic backup connection canary"
	connectionID, e := s.putConnection(alice.ID, connection{Name: connectionName, Target: target.ID, Credential: passwordID, Approval: approvalFingerprint(target), Fingerprint: identityFingerprint(target)})
	if e != nil {
		t.Fatal("fixture connection refused")
	}

	data := backupOf(t, s, now)
	for _, canary := range []string{"alice", "bob", "deploy", "Synthetic", "BEGIN OPENSSH", seed} {
		if bytes.Contains(data, []byte(canary)) {
			t.Fatalf("backup carries %q in plaintext", canary)
		}
	}
	// A recovery code used after the backup must not come back with it.
	if s.consumeFactor(alice.ID, alice.Revision, recovery[0], now) != nil {
		t.Fatal("fixture recovery use refused")
	}

	dir := emptyDataDir(t)
	restored, codes, summary, e := restoreStore(dir, key, data, now)
	if e != nil {
		t.Fatal("valid backup was not restored")
	}
	defer restored.Close()
	if summary.Instance != s.instance || summary.Accounts != 2 || summary.Credentials != 2 || summary.Connections != 1 || !summary.Created.Equal(now.UTC().Truncate(time.Second)) || summary.Program == "" {
		t.Fatalf("restore summary %+v", summary)
	}
	if len(codes) != 2 || codes[0].Username != "alice" || codes[1].Username != "bob" || codes[0].Code == codes[1].Code {
		t.Fatal("restore did not issue one setup code per account")
	}
	for _, c := range codes {
		a, e := restored.lookup(c.Username)
		if e != nil || a.Seed != "" || len(a.Recovery) != 0 || a.LastCounter != -1 || !restored.enrollmentValid(a.ID, c.Code, now) {
			t.Fatalf("%s kept a factor or got no valid setup code", c.Username)
		}
		original, _ := s.lookup(c.Username)
		if a.Hash != original.Hash || a.Revision != original.Revision+1 && c.Username == "bob" {
			t.Fatalf("%s password or revision changed unexpectedly", c.Username)
		}
	}
	restoredAlice, _ := restored.lookup("alice")
	if restored.consumeFactor(alice.ID, restoredAlice.Revision, recovery[0], now) == nil || restored.consumeFactor(alice.ID, restoredAlice.Revision, recovery[1], now) == nil || restored.consumeFactor(alice.ID, restoredAlice.Revision, otpCode(t, seed, now.Unix()/30), now) == nil {
		t.Fatal("an old factor or recovery code works after restore")
	}
	if original, _ := s.lookup("alice"); original.Seed != seed {
		t.Fatal("restore changed the source store")
	}
	for id, c := range saved {
		got, e := restored.readCredential(alice.ID, id)
		if e != nil || got.Secret != c.Secret || got.Kind != c.Kind || got.Username != c.Username || got.Name != c.Name {
			t.Fatalf("%s credential did not survive restore", c.Kind)
		}
	}
	if got, e := restored.readConnection(alice.ID, connectionID); e != nil || got.Name != connectionName || got.Credential != passwordID {
		t.Fatal("connection did not survive restore")
	}
	// The restored credential still opens a connection: it reaches the worker.
	worker := &recordingSSHWorker{}
	l, e := NewRemoteLab("https://127.0.0.1:8443", restored, []RemoteTarget{target}, worker, nil)
	if e != nil {
		t.Fatal("remote lab refused the restored store")
	}
	defer l.Close()
	credential, _ := restored.readCredential(alice.ID, passwordID)
	_, _ = l.openRemote(context.Background(), target, credential)
	if _, ok := worker.got.(*sshkey.Password); !ok {
		t.Fatal("restored password did not reach the SSH worker")
	}
	if again, _, _, e := restoreStore(dir, key, data, now); e == nil {
		_ = again.Close()
		t.Fatal("restore replaced an existing database")
	}
}

func TestRestoreRefusesWrongKeyTamperingAndExistingFiles(t *testing.T) {
	s, key, _ := bootstrapped(t)
	data := backupOf(t, s, time.Now())
	wrong := bytes.Clone(key)
	wrong[0] ^= 1
	refuseRestore(t, "wrong-key", wrong, data)
	refuseRestore(t, "empty", key, nil)
	refuseRestore(t, "truncated", key, data[:len(data)-1])
	refuseRestore(t, "trailing", key, append(bytes.Clone(data), 0))
	flipped := bytes.Clone(data)
	flipped[len(flipped)-20] ^= 1
	refuseRestore(t, "sealed-bit", key, flipped)
	header, _, sealed, e := parseBackupFile(data)
	if e != nil {
		t.Fatal("fixture backup did not parse")
	}
	// Every header field is bound to the sealed body.
	for name, change := range map[string]func(*backupHeader){
		"magic":    func(h *backupHeader) { h.Magic = "keybash-custody-backup-v2" },
		"instance": func(h *backupHeader) { h.Instance = strings.Repeat("e", 32) },
		"created":  func(h *backupHeader) { h.Created = "2001-01-01T00:00:00Z" },
		"salt":     func(h *backupHeader) { h.Salt = bytes.Repeat([]byte{7}, 32) },
		"time":     func(h *backupHeader) { h.Created = "yesterday" },
	} {
		changed := header
		change(&changed)
		refuseRestore(t, name, key, ssh.Marshal(&backupFile{Header: ssh.Marshal(&changed), Sealed: sealed}))
	}
	// An existing database is never replaced, whatever it holds.
	dir := emptyDataDir(t)
	if os.WriteFile(filepath.Join(dir, "custody.db"), []byte("existing"), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if restored, _, _, e := restoreStore(dir, key, data, time.Now()); e == nil {
		_ = restored.Close()
		t.Fatal("restore replaced an existing database")
	}
	if kept, e := os.ReadFile(filepath.Join(dir, "custody.db")); e != nil || string(kept) != "existing" {
		t.Fatal("refused restore changed an existing file")
	}
	// The unchanged backup and key restore: each refusal above is the change.
	restored, _, _, e := restoreStore(emptyDataDir(t), key, data, time.Now())
	if e != nil {
		t.Fatal("valid backup refused")
	}
	_ = restored.Close()
}

func TestRestoreRefusesMalformedOrInconsistentBodies(t *testing.T) {
	s, key, _ := bootstrapped(t)
	if _, e := s.CreateAccount("bob", bobPassword); e != nil {
		t.Fatal("fixture second account refused")
	}
	alice, _ := s.lookup("alice")
	bob, _ := s.lookup("bob")
	for _, owner := range []string{alice.ID, bob.ID} {
		if _, e := s.putCredential(owner, Credential{Name: "fixture", Kind: "password", Secret: "synthetic"}); e != nil {
			t.Fatal("fixture credential refused")
		}
	}
	header, _, entries := openBackup(t, s, backupOf(t, s, time.Now()))
	find := func(bucket uint8, key []byte) int {
		for i, entry := range entries {
			if entry.Bucket == bucket && bytes.Equal(entry.Key, key) {
				return i
			}
		}
		t.Fatal("fixture entry absent")
		return -1
	}
	without := func(drop ...int) []backupEntry {
		var kept []backupEntry
		for i, entry := range entries {
			if !slices.Contains(drop, i) {
				kept = append(kept, entry)
			}
		}
		return kept
	}
	with := func(i int, entry backupEntry) []backupEntry {
		return append(append(append([]backupEntry(nil), entries[:i]...), entry), entries[i:]...)
	}
	replaced := func(i int, value []byte) []backupEntry {
		changed := append([]backupEntry(nil), entries...)
		changed[i].Value = value
		return changed
	}
	aliceAt, bobAt := find(2, []byte(alice.ID)), find(2, []byte(bob.ID))
	nameAt := find(3, s.nameIndex("bob"))
	credentialAt := -1
	for i, entry := range entries {
		if entry.Bucket == 4 && bytes.HasPrefix(entry.Key, []byte(alice.ID)) {
			credentialAt = i
		}
	}
	otherOwner := append([]byte(strings.Repeat("d", 32)), entries[credentialAt].Key[32:]...)
	orphan := entries[credentialAt]
	orphan.Key = otherOwner
	for name, body := range map[string][]byte{
		"schema":             encodeBody(2, "keybash", entries),
		"empty-program":      encodeBody(backupSchema, "", entries),
		"unknown-bucket":     encodeBody(backupSchema, "keybash", append(append([]backupEntry(nil), entries...), backupEntry{Bucket: 6, Key: []byte("x"), Value: []byte("y")})),
		"zero-bucket":        encodeBody(backupSchema, "keybash", with(0, backupEntry{Bucket: 0, Key: []byte("x"), Value: []byte("y")})),
		"duplicate":          encodeBody(backupSchema, "keybash", with(aliceAt, entries[aliceAt])),
		"unsorted":           encodeBody(backupSchema, "keybash", with(0, entries[aliceAt])),
		"no-meta":            encodeBody(backupSchema, "keybash", without(0)),
		"extra-meta":         encodeBody(backupSchema, "keybash", with(1, backupEntry{Bucket: 1, Key: []byte("stats"), Value: entries[0].Value})),
		"missing-index":      encodeBody(backupSchema, "keybash", without(nameAt)),
		"extra-index":        encodeBody(backupSchema, "keybash", with(nameAt, backupEntry{Bucket: 3, Key: bytes.Repeat([]byte{0}, 32), Value: []byte(alice.ID)})),
		"swapped-account":    encodeBody(backupSchema, "keybash", replaced(aliceAt, entries[bobAt].Value)),
		"broken-credential":  encodeBody(backupSchema, "keybash", replaced(credentialAt, []byte(`{"Version":1}`))),
		"rebound-credential": encodeBody(backupSchema, "keybash", append(without(credentialAt), orphan)),
		// Bob's own credential stays valid for him; only his account is gone.
		"orphan-credential": encodeBody(backupSchema, "keybash", without(bobAt, nameAt)),
		// The count still matches; bob's entry names alice.
		"misplaced-index": encodeBody(backupSchema, "keybash", replaced(nameAt, []byte(alice.ID))),
		"no-accounts":     encodeBody(backupSchema, "keybash", entries[:1]),
		"trailing":        append(encodeBody(backupSchema, "keybash", entries), 1),
	} {
		refuseRestore(t, name, key, sealBackup(t, s, header, body))
	}
	// The same entries, sealed the same way, restore.
	restored, _, _, e := restoreStore(emptyDataDir(t), key, sealBackup(t, s, header, encodeBody(backupSchema, "keybash", entries)), time.Now())
	if e != nil {
		t.Fatal("re-sealed valid body refused")
	}
	_ = restored.Close()
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic write failure") }

func TestBackupRefusesWhatItCouldNotRestore(t *testing.T) {
	fresh, _, _, _ := custodyFixture(t)
	if _, e := fresh.Backup(&bytes.Buffer{}, time.Now()); e == nil {
		t.Fatal("uninitialized store backed up")
	}
	s, _, _ := bootstrapped(t)
	alice, _ := s.lookup("alice")
	id, e := s.putCredential(alice.ID, Credential{Name: "fixture", Kind: "password", Secret: "synthetic"})
	if e != nil {
		t.Fatal("fixture credential refused")
	}
	if _, e := s.Backup(failingWriter{}, time.Now()); e == nil {
		t.Fatal("failed write reported success")
	}
	var original []byte
	for name, change := range map[string]func(*bolt.Tx) error{
		"unknown-namespace": func(tx *bolt.Tx) error { _, e := tx.CreateBucket([]byte("audit-v1")); return e },
		"nested-namespace":  func(tx *bolt.Tx) error { _, e := tx.Bucket(credentialBucket).CreateBucket([]byte("nested")); return e },
		"broken-record": func(tx *bolt.Tx) error {
			original = bytes.Clone(tx.Bucket(credentialBucket).Get(credentialKey(alice.ID, id)))
			return tx.Bucket(credentialBucket).Put(credentialKey(alice.ID, id), []byte(`{"Version":1}`))
		},
	} {
		if s.update(change) != nil {
			t.Fatal("fixture change failed")
		}
		if _, e := s.Backup(&bytes.Buffer{}, time.Now()); e == nil {
			t.Fatalf("store with %s backed up", name)
		}
		if s.update(func(tx *bolt.Tx) error {
			switch name {
			case "unknown-namespace":
				return tx.DeleteBucket([]byte("audit-v1"))
			case "nested-namespace":
				return tx.Bucket(credentialBucket).DeleteBucket([]byte("nested"))
			}
			return tx.Bucket(credentialBucket).Put(credentialKey(alice.ID, id), original)
		}) != nil {
			t.Fatal("fixture restore failed")
		}
		if _, e := s.Backup(&bytes.Buffer{}, time.Now()); e != nil {
			t.Fatalf("store refused after undoing %s", name)
		}
	}
}

func TestInstanceKeyCodeRoundTripAndTypos(t *testing.T) {
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal("fixture entropy failed")
	}
	code, e := instanceKeyCode(key)
	if e != nil || !strings.HasPrefix(code, "KB1-") || len(code) != 3+58+12 {
		t.Fatalf("recovery code shape %q", code)
	}
	for _, form := range []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", ""), strings.ReplaceAll(code, "-", " "), " " + code + "\n"} {
		if got, e := parseInstanceKeyCode(form); e != nil || !bytes.Equal(got, key) {
			t.Fatalf("recovery code form %q refused", form)
		}
	}
	compact := strings.ReplaceAll(code, "-", "")
	for i := len(keyCodePrefix); i < len(compact); i++ {
		changed := []byte(compact)
		changed[i] = map[bool]byte{true: 'B', false: 'A'}[changed[i] == 'A']
		if _, e := parseInstanceKeyCode(string(changed)); e == nil {
			t.Fatalf("recovery code with character %d mistyped accepted", i)
		}
	}
	for name, bad := range map[string]string{
		"prefix":    "KB2" + compact[3:],
		"no-prefix": compact[3:],
		"short":     compact[:len(compact)-1],
		"long":      compact + "A",
		"alphabet":  compact[:10] + "0" + compact[11:],
	} {
		if _, e := parseInstanceKeyCode(bad); e == nil {
			t.Fatalf("%s recovery code accepted", name)
		}
	}
	// The last character carries two padding bits; only zero bits are canonical.
	last := compact[len(compact)-1]
	index := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", last)
	padded := compact[:len(compact)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index|1])
	if _, e := parseInstanceKeyCode(padded); e == nil {
		t.Fatal("non-canonical recovery code accepted")
	}
	if _, e := instanceKeyCode(key[:31]); e == nil {
		t.Fatal("short key encoded")
	}
}

func FuzzBackupFile(f *testing.F) {
	f.Add(ssh.Marshal(&backupFile{Header: ssh.Marshal(&backupHeader{Magic: backupMagic, Instance: strings.Repeat("a", 32), Created: "2026-10-27T00:00:00Z", Salt: make([]byte, 32)}), Sealed: make([]byte, 64)}))
	f.Add(encodeBody(backupSchema, "keybash", []backupEntry{{Bucket: 1, Key: metaKey, Value: []byte("{}")}, {Bucket: 2, Key: []byte("a"), Value: []byte("b")}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if header, aad, sealed, e := parseBackupFile(data); e == nil {
			if !validID(header.Instance) || len(header.Salt) != 32 || !bytes.Equal(ssh.Marshal(&backupFile{Header: aad, Sealed: sealed}), data) {
				t.Fatal("non-canonical backup file accepted")
			}
		}
		if entries, program, e := parseBackupBody(data); e == nil {
			if !bytes.Equal(encodeBody(backupSchema, program, entries), data) {
				t.Fatal("non-canonical backup body accepted")
			}
		}
	})
}

// Records are written straight into the store here, because the write paths
// refuse to pass their quotas; each quota holds exactly at its limit.
func TestBackupHoldsTheWriteQuotas(t *testing.T) {
	hash := storedPassword(accounts(t)[0].Password)
	addAccount := func(s *Store, tx *bolt.Tx, n int) (string, error) {
		id, e := randomID()
		if e != nil {
			return "", e
		}
		a := durableAccount{ID: id, Username: fmt.Sprintf("user%04d", n), Hash: hash, Revision: 1, LastCounter: -1}
		if e := s.saveAccount(tx, a); e != nil {
			return "", e
		}
		return id, tx.Bucket(nameBucket).Put(s.nameIndex(a.Username), []byte(id))
	}
	addRecord := func(s *Store, tx *bolt.Tx, kind, owner string) error {
		id, e := randomID()
		if e != nil {
			return e
		}
		bucket, record := credentialBucket, any(Credential{ID: id, Name: "fixture", Kind: "password", Secret: "synthetic"})
		if kind == "connection" {
			bucket, record = connectionBucket, connection{ID: id, Name: "fixture", Target: strings.Repeat("a", 32), Credential: strings.Repeat("b", 32), Approval: strings.Repeat("c", 64)}
		}
		plain, e := json.Marshal(record)
		if e != nil {
			return e
		}
		sealed, e := s.seal(tx, kind, owner, id, 1, plain)
		if e != nil {
			return e
		}
		b, e := tx.CreateBucketIfNotExists(bucket)
		if e != nil {
			return e
		}
		return b.Put(credentialKey(owner, id), sealed)
	}
	// owners accounts each hold perOwner records of kind: total owners*perOwner.
	fill := func(kind string, owners, perOwner int) func(*Store, *bolt.Tx) error {
		return func(s *Store, tx *bolt.Tx) error {
			alice, e := s.readAccount(tx, string(tx.Bucket(nameBucket).Get(s.nameIndex("alice"))))
			if e != nil {
				return e
			}
			for o := range owners {
				owner := alice.ID
				if o > 0 {
					if owner, e = addAccount(s, tx, o); e != nil {
						return e
					}
				}
				for range perOwner {
					if e := addRecord(s, tx, kind, owner); e != nil {
						return e
					}
				}
			}
			return nil
		}
	}
	for _, quota := range []struct {
		name        string
		limit, over func(*Store, *bolt.Tx) error
	}{
		{"accounts", func(s *Store, tx *bolt.Tx) error {
			for n := 1; n < 256; n++ {
				if _, e := addAccount(s, tx, n); e != nil {
					return e
				}
			}
			return nil
		}, func(s *Store, tx *bolt.Tx) error { _, e := addAccount(s, tx, 256); return e }},
		{"credentials-per-owner", fill("credential", 1, 256), fill("credential", 1, 1)},
		{"credentials-total", fill("credential", 16, 256), func(s *Store, tx *bolt.Tx) error {
			owner, e := addAccount(s, tx, 99)
			if e != nil {
				return e
			}
			return addRecord(s, tx, "credential", owner)
		}},
		{"connections-per-owner", fill("connection", 1, 128), fill("connection", 1, 1)},
		{"connections-total", fill("connection", 16, 128), func(s *Store, tx *bolt.Tx) error {
			owner, e := addAccount(s, tx, 99)
			if e != nil {
				return e
			}
			return addRecord(s, tx, "connection", owner)
		}},
	} {
		t.Run(quota.name, func(t *testing.T) {
			s, _, _ := bootstrapped(t)
			if s.update(func(tx *bolt.Tx) error { return quota.limit(s, tx) }) != nil {
				t.Fatal("fixture failed")
			}
			if _, e := s.Backup(&bytes.Buffer{}, time.Now()); e != nil {
				t.Fatal("store at its quota refused")
			}
			if s.update(func(tx *bolt.Tx) error { return quota.over(s, tx) }) != nil {
				t.Fatal("fixture failed")
			}
			if _, e := s.Backup(&bytes.Buffer{}, time.Now()); e == nil {
				t.Fatal("store beyond its quota backed up")
			}
		})
	}
}

func TestBackupNeverBesideItsKey(t *testing.T) {
	base := t.TempDir()
	keys, offsite := filepath.Join(base, "keys"), filepath.Join(base, "offsite")
	for _, dir := range []string{keys, offsite} {
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("fixture mkdir failed")
		}
	}
	key := filepath.Join(keys, "instance.key")
	if sameDirectory(filepath.Join(offsite, "custody.backup"), key) {
		t.Fatal("a separate backup directory was refused")
	}
	for name, path := range map[string]string{
		"beside":  filepath.Join(keys, "custody.backup"),
		"dotted":  filepath.Join(offsite, "..", "keys", "custody.backup"),
		"missing": filepath.Join(base, "absent", "custody.backup"),
	} {
		if !sameDirectory(path, key) {
			t.Fatalf("%s backup path allowed beside the key", name)
		}
	}
	link := filepath.Join(base, "link")
	if os.Symlink(keys, link) == nil && !sameDirectory(filepath.Join(link, "custody.backup"), key) {
		t.Fatal("a symlink to the key directory was allowed")
	}
}
