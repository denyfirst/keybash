package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/keybash/internal/sshkey"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

type Credential struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Username    string `json:"username"`
	Secret      string `json:"secret"`
	Passphrase  string `json:"passphrase"`
	Fingerprint string `json:"fingerprint"`
	// Public is an SSH key's authorized_keys line, kept so it can be shown
	// without opening the private key. A Generated key was made here: its
	// private half is never revealed or exported and leaves only as signatures.
	Public    string `json:"public,omitempty"`
	Generated bool   `json:"generated,omitempty"`
	// Used says a Generated key has opened a session on a server, so it is on
	// one: its row stops asking to be added. Set once, never by a request.
	Used bool `json:"used,omitempty"`
}

func (Credential) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[credential redacted]") }

type credentialSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Username    string `json:"username"`
	Fingerprint string `json:"fingerprint"`
	Public      string `json:"public,omitempty"`
	Generated   bool   `json:"generated,omitempty"`
	Used        bool   `json:"used,omitempty"`
}

func (c Credential) summary() credentialSummary {
	return credentialSummary{c.ID, c.Name, c.Kind, c.Username, c.Fingerprint, c.Public, c.Generated, c.Used}
}
func label(value string, maxBytes int, empty bool) bool {
	if !utf8.ValidString(value) || len(value) > maxBytes || !empty && len(value) == 0 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}
func validateCredential(c *Credential) error {
	key, e := checkCredential(c)
	if key != nil {
		key.Close()
	}
	return e
}

// checkCredential applies a credential's rules and, for an SSH key, returns
// it opened; the caller closes it. A key that came with its passphrase is
// unlocked here, once, and kept as the same key without one: the vault seals
// every record, and a passphrase kept beside its key in the same record
// protects nothing, while bcrypt on each connection costs a quarter of a
// second at 16 rounds and a second at 64.
func checkCredential(c *Credential) (*sshkey.Key, error) {
	if !label(c.Name, 160, false) || !label(c.Username, 128, true) || len(c.Secret) == 0 || len(c.Secret) > 64*1024 || !utf8.ValidString(c.Secret) || len(c.Passphrase) > 1024 || !utf8.ValidString(c.Passphrase) {
		return nil, errRefused
	}
	if c.Kind == "password" {
		if len(c.Secret) > 4096 || len(c.Passphrase) != 0 || strings.ContainsRune(c.Secret, 0) {
			return nil, errRefused
		}
		c.Fingerprint, c.Public = "", ""
		return nil, nil
	}
	if c.Kind != "ssh-key" {
		return nil, errRefused
	}
	raw, public, locked, e := parseSSHKey(*c)
	if e != nil {
		return nil, errRefused
	}
	defer sshkey.Discard(raw)
	key, e := openedKey(raw, public)
	if e != nil {
		return nil, errRefused
	}
	if locked {
		text, e := unlockedKey(raw)
		if e != nil {
			key.Close()
			return nil, errRefused
		}
		c.Secret, c.Passphrase = text, ""
	}
	c.Fingerprint = ssh.FingerprintSHA256(key.PublicKey())
	c.Public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
	return key, nil
}

// unlockedKey writes a parsed private key as an OpenSSH key without a
// passphrase.
func unlockedKey(raw any) (string, error) {
	if k, ok := raw.(*ed25519.PrivateKey); ok {
		raw = *k
	}
	block, e := ssh.MarshalPrivateKey(raw, "")
	if e != nil {
		return "", errRefused
	}
	text := pem.EncodeToMemory(block)
	clear(block.Bytes)
	defer clear(text)
	return string(text), nil
}

// newGeneratedKey makes an Ed25519 key here, for a person who has none. It is
// sealed like any record but never revealed or exported; the person puts its
// public line on their server.
func newGeneratedKey(name, username string) (Credential, error) {
	if username == "" {
		return Credential{}, errRefused // a key nobody can log in with is no use
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return Credential{}, errRefused
	}
	block, e := ssh.MarshalPrivateKey(private, "keybash")
	clear(private)
	if e != nil {
		return Credential{}, errRefused
	}
	c := Credential{Name: name, Kind: "ssh-key", Username: username, Secret: string(pem.EncodeToMemory(block)), Generated: true}
	clear(block.Bytes)
	if validateCredential(&c) != nil {
		return Credential{}, errRefused
	}
	return c, nil
}

// parseSSHKey bounds an OpenSSH private key's cost before parsing it, and
// says whether it was locked with a passphrase. Accepted: Ed25519, ECDSA
// P-256/384/521 and RSA 2048–8192 bits; unencrypted, or aes256-ctr with bcrypt
// of at most 64 rounds. The stored public half must be the private key's own.
// The caller discards the key it returns.
func parseSSHKey(c Credential) (any, []byte, bool, error) {
	text := strings.TrimSpace(c.Secret)
	if !strings.HasPrefix(text, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return nil, nil, false, errRefused
	}
	b, rest := pem.Decode([]byte(text))
	if b == nil || b.Type != "OPENSSH PRIVATE KEY" || len(b.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, nil, false, errRefused
	}
	defer clear(b.Bytes)
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b.Bytes, []byte(magic)) {
		return nil, nil, false, errRefused
	}
	var outer struct {
		Cipher, KDF, Options string
		Count                uint32
		Public, Private      []byte
		Rest                 []byte `ssh:"rest"`
	}
	// An 8192-bit RSA public key is about 1 KiB and its private section 4 KiB.
	if ssh.Unmarshal(b.Bytes[len(magic):], &outer) != nil || outer.Count != 1 || len(outer.Rest) != 0 || len(outer.Public) > 1100 || len(outer.Private) > 6144 || len(outer.Options) > 128 {
		return nil, nil, false, errRefused
	}
	public, e := ssh.ParsePublicKey(outer.Public)
	if e != nil || !sshkey.Allowed(public) {
		return nil, nil, false, errRefused
	}
	var raw any
	locked := outer.Cipher != "none"
	if !locked {
		if outer.KDF != "none" || outer.Options != "" || c.Passphrase != "" {
			return nil, nil, false, errRefused
		}
		raw, e = ssh.ParseRawPrivateKey([]byte(text))
	} else {
		if !encryptionAllowed(outer.Cipher, outer.KDF, outer.Options) || c.Passphrase == "" {
			return nil, nil, false, errRefused
		}
		raw, e = ssh.ParseRawPrivateKeyWithPassphrase([]byte(text), []byte(c.Passphrase))
	}
	if e != nil {
		return nil, nil, false, errRefused
	}
	// A copy: outer.Public is part of b.Bytes, which is cleared on return.
	return raw, bytes.Clone(outer.Public), locked, nil
}

// openedKey makes a parsed key a session key, if its public half is the one
// the key file names; the caller closes it.
func openedKey(raw any, public []byte) (*sshkey.Key, error) {
	key, e := sshkey.New(raw)
	if e != nil {
		return nil, errRefused
	}
	if !bytes.Equal(key.PublicKey().Marshal(), public) {
		key.Close()
		return nil, errRefused
	}
	return key, nil
}

// encryptionAllowed bounds a protected key's work before any decryption is
// tried. The SSH library itself accepts up to 2048 bcrypt rounds, seconds of
// CPU per attempt; 64 is well above what ssh-keygen writes by default (16).
func encryptionAllowed(cipher, kdf, rawOptions string) bool {
	var options struct {
		Salt   string
		Rounds uint32
	}
	return cipher == "aes256-ctr" && kdf == "bcrypt" && ssh.Unmarshal([]byte(rawOptions), &options) == nil && len(options.Salt) >= 16 && len(options.Salt) <= 64 && options.Rounds >= 1 && options.Rounds <= 64
}
func credentialKey(owner, id string) []byte { return []byte(owner + "/" + id) }
func (s *Store) credential(tx *bolt.Tx, owner, id string) (Credential, error) {
	var c Credential
	if _, e := s.meta(tx); e != nil {
		return c, e
	}
	plain, _, e := s.unseal("credential", owner, id, tx.Bucket(credentialBucket).Get(credentialKey(owner, id)))
	if e != nil {
		return c, e
	}
	defer clear(plain)
	if decodeRecord(plain, &c, 96*1024) != nil || c.ID != id || !label(c.Name, 160, false) || (c.Kind != "password" && c.Kind != "ssh-key") || c.Generated && c.Kind != "ssh-key" || c.Used && !c.Generated || len(c.Secret) > 64*1024 || len(c.Passphrase) > 1024 {
		return Credential{}, errRefused
	}
	return c, nil
}
func (s *Store) putCredential(owner string, c Credential) (string, error) {
	if !validID(owner) || c.ID != "" {
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
		b := tx.Bucket(credentialBucket)
		if b.Stats().KeyN >= 4096 || b.Get(credentialKey(owner, id)) != nil {
			return errRefused
		}
		count, total := 0, 0
		prefix := []byte(owner + "/")
		if e := b.ForEach(func(k, v []byte) error {
			total += len(v)
			if bytes.HasPrefix(k, prefix) {
				count++
			}
			return nil
		}); e != nil || count >= 256 || total >= 64*1024*1024 {
			return errRefused
		}
		plain, e := json.Marshal(c) // #nosec G117 -- intentional bounded secret serialization solely into the authenticated encrypted envelope; no logs or metadata response.
		if e != nil {
			return errRefused
		}
		defer clear(plain)
		sealed, e := s.seal(tx, "credential", owner, id, 1, plain)
		if e != nil || total+len(sealed) > 64*1024*1024 {
			return errRefused
		}
		return b.Put(credentialKey(owner, id), sealed)
	})
	if e != nil {
		return "", errRefused
	}
	return id, nil
}
func (s *Store) listCredentials(owner string) ([]credentialSummary, error) {
	result := make([]credentialSummary, 0)
	e := s.view(func(tx *bolt.Tx) error {
		if _, e := s.readAccount(tx, owner); e != nil {
			return e
		}
		cursor := tx.Bucket(credentialBucket).Cursor()
		prefix := []byte(owner + "/")
		for k, _ := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = cursor.Next() {
			if len(result) >= 256 {
				return errRefused
			}
			c, e := s.credential(tx, owner, string(k[len(prefix):]))
			if e != nil {
				return e
			}
			result = append(result, c.summary())
		}
		return nil
	})
	return result, e
}

// markKeyUsed records, once, that a key made here has opened a session on a
// server. Only a Generated key carries the mark; nothing else in the record
// changes, and it is resealed at the next revision.
func (s *Store) markKeyUsed(owner, id string) error {
	return s.update(func(tx *bolt.Tx) error {
		c, e := s.credential(tx, owner, id)
		if e != nil || !c.Generated {
			return errRefused
		}
		if c.Used {
			return nil
		}
		// Only the revision is needed; the plaintext holds the secret.
		previous, revision, e := s.unseal("credential", owner, id, tx.Bucket(credentialBucket).Get(credentialKey(owner, id)))
		clear(previous)
		if e != nil || revision >= 1<<31 {
			return errRefused
		}
		c.Used = true
		plain, e := json.Marshal(c) // #nosec G117 -- intentional bounded secret serialization solely into the authenticated encrypted envelope; no logs or metadata response.
		if e != nil {
			return errRefused
		}
		defer clear(plain)
		sealed, e := s.seal(tx, "credential", owner, id, revision+1, plain)
		if e != nil {
			return errRefused
		}
		return tx.Bucket(credentialBucket).Put(credentialKey(owner, id), sealed)
	})
}
func (s *Store) readCredential(owner, id string) (Credential, error) {
	var c Credential
	e := s.view(func(tx *bolt.Tx) error { var e error; c, e = s.credential(tx, owner, id); return e })
	return c, e
}
func (s *Store) deleteCredential(owner, id string) error {
	return s.update(func(tx *bolt.Tx) error {
		if _, e := s.credential(tx, owner, id); e != nil {
			return e
		}
		return tx.Bucket(credentialBucket).Delete(credentialKey(owner, id))
	})
}

// unlockStoredKeys keeps, once, every SSH key stored with its passphrase as
// the same key without one (checkCredential), at its next revision. A key that
// no longer opens is left as it was. A start with nothing to unlock rolls back
// and writes nothing, as adoptSoleAdmin does.
func (s *Store) unlockStoredKeys() error {
	nothing := errors.New("no locked key")
	e := s.updateWhy(func(tx *bolt.Tx) error {
		if _, e := s.meta(tx); e != nil {
			return e
		}
		b := tx.Bucket(credentialBucket)
		var locked [][2]string
		if e := b.ForEach(func(k, _ []byte) error {
			owner, id, ok := strings.Cut(string(k), "/")
			if !ok || !validID(owner) || !validID(id) {
				return errRefused
			}
			c, e := s.credential(tx, owner, id)
			if e != nil {
				return e
			}
			if c.Kind == "ssh-key" && c.Passphrase != "" {
				locked = append(locked, [2]string{owner, id})
			}
			return nil
		}); e != nil {
			return e
		}
		unlocked := 0
		for _, at := range locked {
			owner, id := at[0], at[1]
			c, e := s.credential(tx, owner, id)
			if e != nil {
				return e
			}
			key, e := checkCredential(&c)
			if e != nil {
				continue
			}
			key.Close()
			// Only the revision is needed; the plaintext holds the secret.
			previous, revision, e := s.unseal("credential", owner, id, b.Get(credentialKey(owner, id)))
			clear(previous)
			if e != nil || revision >= 1<<31 {
				return errRefused
			}
			plain, e := json.Marshal(c) // #nosec G117 -- intentional bounded secret serialization solely into the authenticated encrypted envelope; no logs or metadata response.
			if e != nil {
				return errRefused
			}
			sealed, e := s.seal(tx, "credential", owner, id, revision+1, plain)
			clear(plain)
			if e != nil {
				return errRefused
			}
			if e := b.Put(credentialKey(owner, id), sealed); e != nil {
				return e
			}
			unlocked++
		}
		if unlocked == 0 {
			return nothing
		}
		return nil
	})
	if e == nothing {
		return nil
	}
	return e
}
