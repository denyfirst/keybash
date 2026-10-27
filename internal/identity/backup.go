package identity

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// A backup is a logical copy of every custody namespace, read in one
// transaction, verified record by record, and sealed with a key derived from
// the instance key for that one file. It holds no key and no plaintext
// secret: the records inside are the store's own envelopes, and the file
// encryption also hides their names, counts and sizes. Restoring needs the
// instance key, which is kept and recovered separately (instanceKeyCode).
//
// Restore writes a new database in one transaction that also resets every
// account's MFA. An old backup would otherwise bring back recovery codes
// consumed since it was made, or a factor replaced because it leaked; instead
// each account needs a fresh operator setup code, with its password, to
// enroll again. No database holding the backup's old factors is ever written.

const (
	backupMagic  = "keybash-custody-backup-v1"
	backupSchema = 1
	// The quotas bound the records: at most 64 MiB of credentials, 256
	// accounts and 2048 connections stay under this.
	maxBackupBody = 96 << 20
	// MaxBackupFile bounds what restore reads.
	MaxBackupFile   = maxBackupBody + 4096
	maxBackupRecord = 160 * 1024
)

// backupBuckets is every namespace a backup carries, in file order. A store
// holding anything else is refused rather than copied in part. The
// connections namespace is optional, as on open.
type backupBucket struct {
	id       uint8
	name     []byte
	optional bool
}

var backupBuckets = []backupBucket{{1, metaBucket, false}, {2, accountBucket, false}, {3, nameBucket, false}, {4, credentialBucket, false}, {5, connectionBucket, true}}

type backupFile struct {
	Header, Sealed []byte // Header is also the sealed body's associated data
}
type backupHeader struct {
	Magic, Instance, Created string
	Salt                     []byte
}
type backupBody struct {
	Schema  uint32
	Program string
	Entries []byte `ssh:"rest"`
}
type backupEntry struct {
	Bucket     uint8
	Key, Value []byte
	Rest       []byte `ssh:"rest"`
}

// BackupSummary describes a backup without anything secret.
type BackupSummary struct {
	Instance                           string
	Created                            time.Time
	Program                            string
	Accounts, Credentials, Connections int
}

// SetupCode is one account's fresh one-time enrollment code after a restore.
type SetupCode struct{ Username, Code string }

func (SetupCode) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[setup code redacted]") }

// backupAEAD seals one file. Its key is unique to the file (a random salt), on
// top of GCM's random nonce.
func backupAEAD(backupKey, salt []byte) (cipher.AEAD, error) {
	key, e := hkdf.Key(sha256.New, backupKey, salt, "keybash/backup/v1/file", 32)
	if e != nil {
		return nil, errRefused
	}
	defer clear(key)
	return randomGCM(key)
}

// programVersion is the version manifest a backup records: module version and
// source revision when the build has them.
func programVersion() string {
	version := "keybash"
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	if label(info.Main.Version, 64, false) {
		version += " " + info.Main.Version
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" && len(setting.Value) >= 12 && label(setting.Value, 64, false) {
			version += " " + setting.Value[:12]
		}
	}
	return version
}

// Backup writes a sealed copy of the whole store to w. It refuses a store
// that is not initialized or holds any record it could not restore.
func (s *Store) Backup(w io.Writer, now time.Time) (BackupSummary, error) {
	var out []byte
	var summary BackupSummary
	e := s.view(func(tx *bolt.Tx) error {
		var e error
		if summary, e = s.verifyAll(tx); e != nil {
			return e
		}
		entries, e := snapshotBuckets(tx)
		if e != nil {
			return e
		}
		salt := make([]byte, 32)
		if _, e = rand.Read(salt); e != nil {
			return errRefused
		}
		aead, e := backupAEAD(s.backupKey[:], salt)
		if e != nil {
			return e
		}
		created := now.UTC().Truncate(time.Second)
		header := ssh.Marshal(&backupHeader{Magic: backupMagic, Instance: s.instance, Created: created.Format(time.RFC3339), Salt: salt})
		summary.Instance, summary.Created, summary.Program = s.instance, created, programVersion()
		body := ssh.Marshal(&backupBody{Schema: backupSchema, Program: summary.Program, Entries: entries})
		// NewGCMWithRandomNonce requires a nil nonce and generates its own.
		out = ssh.Marshal(&backupFile{Header: header, Sealed: aead.Seal(nil, nil, body, header)}) // #nosec G407 -- required random-nonce GCM API, never a fixed IV.
		return nil
	})
	if e != nil {
		return BackupSummary{}, errRefused
	}
	if n, e := w.Write(out); e != nil || n != len(out) {
		return BackupSummary{}, errRefused
	}
	return summary, nil
}

func snapshotBuckets(tx *bolt.Tx) ([]byte, error) {
	var out []byte
	for _, bucket := range backupBuckets {
		b := tx.Bucket(bucket.name)
		if b == nil {
			continue // verifyAll has already required the mandatory ones
		}
		if b.ForEach(func(k, v []byte) error {
			out = append(out, ssh.Marshal(&backupEntry{Bucket: bucket.id, Key: k, Value: v})...)
			if len(out) > maxBackupBody-1024 {
				return errRefused
			}
			return nil
		}) != nil {
			return nil, errRefused
		}
	}
	return out, nil
}

// verifyAll reads every record as the service would and checks that the
// namespaces hold nothing else, within the quotas writes enforce. A backup is
// taken, and a restore commits, only when this passes.
func (s *Store) verifyAll(tx *bolt.Tx) (BackupSummary, error) {
	var summary BackupSummary
	if m, e := s.meta(tx); e != nil || !m.Initialized {
		return summary, errRefused
	}
	if tx.ForEach(func(name []byte, b *bolt.Bucket) error {
		if !slices.ContainsFunc(backupBuckets, func(known backupBucket) bool { return bytes.Equal(known.name, name) }) {
			return errRefused
		}
		return b.ForEach(func(k, v []byte) error {
			if v == nil || bytes.Equal(name, metaBucket) && !bytes.Equal(k, metaKey) {
				return errRefused // a nested namespace, or meta beyond its state
			}
			return nil
		})
	}) != nil {
		return summary, errRefused
	}
	names := tx.Bucket(nameBucket)
	accounts := map[string]bool{}
	if tx.Bucket(accountBucket).ForEach(func(k, _ []byte) error {
		a, e := s.readAccount(tx, string(k))
		// Each account's own index entry must name it; with the count check
		// below, the index holds exactly one entry per account and nothing else.
		if e != nil || !bytes.Equal(names.Get(s.nameIndex(a.Username)), k) || len(accounts) >= 256 {
			return errRefused
		}
		accounts[a.ID] = true
		return nil
	}) != nil || len(accounts) == 0 {
		return summary, errRefused
	}
	indexed := 0
	if names.ForEach(func(_, _ []byte) error { indexed++; return nil }) != nil || indexed != len(accounts) {
		return summary, errRefused
	}
	summary.Accounts = len(accounts)
	owned := func(bucket []byte, perOwner, total int, read func(owner, id string) error) (int, error) {
		b := tx.Bucket(bucket)
		if b == nil {
			return 0, nil
		}
		counts := map[string]int{}
		n := 0
		e := b.ForEach(func(k, _ []byte) error {
			owner, id, ok := strings.Cut(string(k), "/")
			if !ok || !accounts[owner] || !validID(id) || read(owner, id) != nil {
				return errRefused
			}
			counts[owner]++
			n++
			if counts[owner] > perOwner || n > total {
				return errRefused
			}
			return nil
		})
		return n, e
	}
	var e error
	if summary.Credentials, e = owned(credentialBucket, 256, 4096, func(owner, id string) error { _, e := s.credential(tx, owner, id); return e }); e != nil {
		return BackupSummary{}, errRefused
	}
	if summary.Connections, e = owned(connectionBucket, 128, 2048, func(owner, id string) error { _, e := s.connection(tx, owner, id); return e }); e != nil {
		return BackupSummary{}, errRefused
	}
	return summary, nil
}

func parseBackupFile(data []byte) (backupHeader, []byte, []byte, error) {
	var file backupFile
	var header backupHeader
	if len(data) == 0 || len(data) > MaxBackupFile || ssh.Unmarshal(data, &file) != nil || len(file.Header) > 1024 || len(file.Sealed) < 28 || len(file.Sealed) > maxBackupBody+28 {
		return header, nil, nil, errRefused
	}
	if ssh.Unmarshal(file.Header, &header) != nil || header.Magic != backupMagic || !validID(header.Instance) || len(header.Salt) != 32 {
		return backupHeader{}, nil, nil, errRefused
	}
	created, e := time.Parse(time.RFC3339, header.Created)
	if e != nil || created.UTC().Format(time.RFC3339) != header.Created {
		return backupHeader{}, nil, nil, errRefused
	}
	return header, file.Header, file.Sealed, nil
}

// parseBackupBody accepts entries only in canonical order: buckets in file
// order, keys strictly increasing within each, so nothing repeats.
func parseBackupBody(body []byte) ([]backupEntry, string, error) {
	var b backupBody
	if ssh.Unmarshal(body, &b) != nil || b.Schema != backupSchema || !label(b.Program, 256, false) {
		return nil, "", errRefused
	}
	var entries []backupEntry
	for rest := b.Entries; len(rest) > 0; {
		var entry backupEntry
		if ssh.Unmarshal(rest, &entry) != nil {
			return nil, "", errRefused
		}
		rest, entry.Rest = entry.Rest, nil
		if entry.Bucket < 1 || int(entry.Bucket) > len(backupBuckets) || len(entry.Key) == 0 || len(entry.Key) > 128 || len(entry.Value) == 0 || len(entry.Value) > maxBackupRecord || len(entries) >= 8192 {
			return nil, "", errRefused
		}
		if n := len(entries); n > 0 {
			previous := entries[n-1]
			if entry.Bucket < previous.Bucket || entry.Bucket == previous.Bucket && bytes.Compare(entry.Key, previous.Key) <= 0 {
				return nil, "", errRefused
			}
		}
		entries = append(entries, entry)
	}
	return entries, b.Program, nil
}

// restoreStore creates dir/custody.db from a backup made with the same
// instance key. Nothing is created unless the file opens with that key. The
// copied records, their verification and the MFA reset then commit in one
// transaction. It never replaces a file and removes its own on failure.
func restoreStore(dir string, key, data []byte, now time.Time) (*Store, []SetupCode, BackupSummary, error) {
	header, aad, sealed, e := parseBackupFile(data)
	if e != nil || len(key) != 32 {
		return nil, nil, BackupSummary{}, errRefused
	}
	backupKey, e := instanceSubkey(key, header.Instance, "backup")
	if e != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	aead, e := backupAEAD(backupKey, header.Salt)
	clear(backupKey)
	if e != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	body, e := aead.Open(nil, nil, sealed, aad)
	if e != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	defer clear(body)
	entries, program, e := parseBackupBody(body)
	if e != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	defer root.Close()
	f, e := root.OpenFile("custody.db", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	created, se := f.Stat()
	ye := f.Sync()
	_ = f.Close()
	var s *Store
	ok := false
	defer func() {
		if ok {
			return
		}
		if s != nil {
			_ = s.Close()
		}
		if current, e := root.Lstat("custody.db"); e == nil && se == nil && os.SameFile(created, current) {
			_ = root.Remove("custody.db")
		}
	}()
	if se != nil || ye != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	if s, e = openDB(dir, key, header.Instance); e != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	var summary BackupSummary
	var codes []SetupCode
	e = s.update(func(tx *bolt.Tx) error {
		buckets := map[uint8]*bolt.Bucket{}
		for _, bucket := range backupBuckets {
			if bucket.optional && !slices.ContainsFunc(entries, func(entry backupEntry) bool { return entry.Bucket == bucket.id }) {
				continue
			}
			b, e := tx.CreateBucket(bucket.name)
			if e != nil {
				return e
			}
			buckets[bucket.id] = b
		}
		for _, entry := range entries {
			if buckets[entry.Bucket].Put(entry.Key, entry.Value) != nil {
				return errRefused
			}
		}
		var e error
		if summary, e = s.verifyAll(tx); e != nil {
			return e
		}
		codes, e = s.resetFactors(tx, now)
		return e
	})
	if e != nil {
		return nil, nil, BackupSummary{}, errRefused
	}
	summary.Instance, summary.Program = header.Instance, program
	summary.Created, _ = time.Parse(time.RFC3339, header.Created)
	ok = true
	return s, codes, summary, nil
}

// resetFactors clears every account's MFA seed and recovery codes, as offline
// lost-factor recovery does, and issues each a fresh one-time setup code.
// Passwords are kept: enrolling needs the password and that code together.
func (s *Store) resetFactors(tx *bolt.Tx, now time.Time) ([]SetupCode, error) {
	var ids []string
	if tx.Bucket(accountBucket).ForEach(func(k, _ []byte) error { ids = append(ids, string(k)); return nil }) != nil {
		return nil, errRefused
	}
	codes := make([]SetupCode, 0, len(ids))
	for _, id := range ids {
		a, e := s.readAccount(tx, id)
		if e != nil {
			return nil, e
		}
		a.Revision++
		a.Seed, a.Recovery, a.LastCounter = "", nil, -1
		code, e := issueEnrollment(&a, now)
		if e != nil || s.saveAccount(tx, a) != nil {
			return nil, errRefused
		}
		codes = append(codes, SetupCode{Username: a.Username, Code: code})
	}
	slices.SortFunc(codes, func(a, b SetupCode) int { return strings.Compare(a.Username, b.Username) })
	return codes, nil
}

// The instance key's recovery code: "KB1-" and the key with a four-byte check
// in base32, grouped by five. It is written down apart from the server and its
// backups (on paper or in a password manager). With a backup it restores
// everything; without it no backup can be opened.
const keyCodePrefix = "KB1"

var keyCodeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func keyCheck(key []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("keybash/instance-key-code/v1/"))
	_, _ = h.Write(key)
	return h.Sum(nil)[:4]
}

func instanceKeyCode(key []byte) (string, error) {
	if len(key) != 32 {
		return "", errRefused
	}
	raw := append(bytes.Clone(key), keyCheck(key)...)
	defer clear(raw)
	text := keyCodeEncoding.EncodeToString(raw)
	var code strings.Builder
	code.WriteString(keyCodePrefix)
	for i := 0; i < len(text); i += 5 {
		code.WriteByte('-')
		code.WriteString(text[i:min(i+5, len(text))])
	}
	return code.String(), nil
}

// parseInstanceKeyCode accepts the code as printed, in either case and with
// or without its separators, and refuses any other text or a failed check.
func parseInstanceKeyCode(code string) ([]byte, error) {
	compact := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	text, found := strings.CutPrefix(compact, keyCodePrefix)
	if !found || len(text) != 58 {
		return nil, errRefused
	}
	raw, e := keyCodeEncoding.DecodeString(text)
	if e != nil || len(raw) != 36 || keyCodeEncoding.EncodeToString(raw) != text || subtle.ConstantTimeCompare(keyCheck(raw[:32]), raw[32:]) != 1 {
		clear(raw)
		return nil, errRefused
	}
	key := bytes.Clone(raw[:32])
	clear(raw)
	return key, nil
}

// sameDirectory reports whether two paths' parents resolve to one directory,
// or cannot be resolved (then the caller refuses).
func sameDirectory(a, b string) bool {
	first, e := filepath.EvalSymlinks(filepath.Dir(a))
	if e != nil {
		return true
	}
	second, e := filepath.EvalSymlinks(filepath.Dir(b))
	if e != nil {
		return true
	}
	first, e = filepath.Abs(first)
	if e != nil {
		return true
	}
	second, e = filepath.Abs(second)
	return e != nil || first == second
}
