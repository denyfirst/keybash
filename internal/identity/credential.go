package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

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
	text := strings.TrimSpace(c.Secret)
	if !strings.HasPrefix(text, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return errRefused
	}
	b, rest := pem.Decode([]byte(text))
	if b == nil || b.Type != "OPENSSH PRIVATE KEY" || len(b.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return errRefused
	}
	defer clear(b.Bytes)
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b.Bytes, []byte(magic)) {
		return errRefused
	}
	var outer struct {
		Cipher, KDF, Options string
		Count                uint32
		Public, Private      []byte
		Rest                 []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(b.Bytes[len(magic):], &outer) != nil || outer.Count != 1 || len(outer.Rest) != 0 || len(outer.Public) > 128 || len(outer.Private) > 4096 || len(outer.Options) > 128 {
		return errRefused
	}
	var public struct {
		Type string
		Data []byte
	}
	if ssh.Unmarshal(outer.Public, &public) != nil || public.Type != ssh.KeyAlgoED25519 || len(public.Data) != 32 {
		return errRefused
	}
	var raw any
	var e error
	if outer.Cipher == "none" {
		if outer.KDF != "none" || outer.Options != "" || c.Passphrase != "" {
			return errRefused
		}
		raw, e = ssh.ParseRawPrivateKey([]byte(text))
	} else {
		var options struct {
			Salt   string
			Rounds uint32
		}
		if outer.Cipher != "aes256-ctr" || outer.KDF != "bcrypt" || ssh.Unmarshal([]byte(outer.Options), &options) != nil || len(options.Salt) < 16 || len(options.Salt) > 64 || options.Rounds < 1 || options.Rounds > 64 || c.Passphrase == "" {
			return errRefused
		}
		raw, e = ssh.ParseRawPrivateKeyWithPassphrase([]byte(text), []byte(c.Passphrase))
	}
	if e != nil {
		return errRefused
	}
	keyPointer, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		return errRefused
	}
	key := *keyPointer
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if subtle.ConstantTimeCompare(key, derived) != 1 {
		return errRefused
	}
	pub, e := ssh.NewPublicKey(key.Public())
	if e != nil || !bytes.Equal(pub.Marshal(), outer.Public) {
		return errRefused
	}
	c.Fingerprint = ssh.FingerprintSHA256(pub)
	return nil
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
