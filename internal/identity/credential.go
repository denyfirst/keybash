package identity

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
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
}

func (Credential) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[credential redacted]") }

type credentialSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Username    string `json:"username"`
	Fingerprint string `json:"fingerprint"`
}

func (c Credential) summary() credentialSummary {
	return credentialSummary{c.ID, c.Name, c.Kind, c.Username, c.Fingerprint}
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
	if !label(c.Name, 160, false) || !label(c.Username, 128, true) || len(c.Secret) == 0 || len(c.Secret) > 64*1024 || !utf8.ValidString(c.Secret) || len(c.Passphrase) > 1024 || !utf8.ValidString(c.Passphrase) {
		return errRefused
	}
	if c.Kind == "password" {
		if len(c.Secret) > 4096 || len(c.Passphrase) != 0 || strings.ContainsRune(c.Secret, 0) {
			return errRefused
		}
		c.Fingerprint = ""
		return nil
	}
	if c.Kind != "ssh-key" {
		return errRefused
	}
	key, e := openSSHKey(*c)
	if e != nil {
		return errRefused
	}
	c.Fingerprint = ssh.FingerprintSHA256(key.PublicKey())
	key.Close()
	return nil
}

// openSSHKey bounds an OpenSSH private key's cost before parsing it and
// returns it as a session key. Accepted: Ed25519, ECDSA P-256/384/521 and RSA
// 2048–8192 bits; unencrypted, or aes256-ctr with bcrypt of at most 64 rounds.
// The stored public half must be the private key's own. The caller closes it.
func openSSHKey(c Credential) (*sshkey.Key, error) {
	text := strings.TrimSpace(c.Secret)
	if !strings.HasPrefix(text, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return nil, errRefused
	}
	b, rest := pem.Decode([]byte(text))
	if b == nil || b.Type != "OPENSSH PRIVATE KEY" || len(b.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errRefused
	}
	defer clear(b.Bytes)
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b.Bytes, []byte(magic)) {
		return nil, errRefused
	}
	var outer struct {
		Cipher, KDF, Options string
		Count                uint32
		Public, Private      []byte
		Rest                 []byte `ssh:"rest"`
	}
	// An 8192-bit RSA public key is about 1 KiB and its private section 4 KiB.
	if ssh.Unmarshal(b.Bytes[len(magic):], &outer) != nil || outer.Count != 1 || len(outer.Rest) != 0 || len(outer.Public) > 1100 || len(outer.Private) > 6144 || len(outer.Options) > 128 {
		return nil, errRefused
	}
	public, e := ssh.ParsePublicKey(outer.Public)
	if e != nil || !sshkey.Allowed(public) {
		return nil, errRefused
	}
	var raw any
	if outer.Cipher == "none" {
		if outer.KDF != "none" || outer.Options != "" || c.Passphrase != "" {
			return nil, errRefused
		}
		raw, e = ssh.ParseRawPrivateKey([]byte(text))
	} else {
		if !encryptionAllowed(outer.Cipher, outer.KDF, outer.Options) || c.Passphrase == "" {
			return nil, errRefused
		}
		raw, e = ssh.ParseRawPrivateKeyWithPassphrase([]byte(text), []byte(c.Passphrase))
	}
	if e != nil {
		return nil, errRefused
	}
	key, e := sshkey.New(raw)
	sshkey.Discard(raw)
	if e != nil {
		return nil, errRefused
	}
	if !bytes.Equal(key.PublicKey().Marshal(), outer.Public) {
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
	if decodeRecord(plain, &c, 96*1024) != nil || c.ID != id || !label(c.Name, 160, false) || (c.Kind != "password" && c.Kind != "ssh-key") || len(c.Secret) > 64*1024 || len(c.Passphrase) > 1024 {
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
