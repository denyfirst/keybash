package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/keybash/internal/sshkey"
	"golang.org/x/crypto/ssh"
)

// Credential is a server account's secret (ADR 0010): a key made here, or a
// password an administrator typed. It lives only inside a sealed account
// record and the gateway's memory while a session opens.
type Credential struct {
	Kind        string `json:"kind"`
	Username    string `json:"username"`
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
	// Public is an SSH key's authorized_keys line, kept so it can be shown
	// without opening the private key. A Generated key was made here: its
	// private half is never revealed or exported and leaves only as signatures.
	Public    string `json:"public,omitempty"`
	Generated bool   `json:"generated,omitempty"`
	// Used says a Generated key has opened a session on a server, so it is on
	// one: its account stops asking for it to be added. Set once, never by a
	// request.
	Used bool `json:"used,omitempty"`
}

func (Credential) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[credential redacted]") }

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
// it opened; the caller closes it. A key is an unencrypted OpenSSH key, as
// newGeneratedKey writes one: the record that holds it is sealed.
func checkCredential(c *Credential) (*sshkey.Key, error) {
	if !label(c.Username, 128, false) || len(c.Secret) == 0 || len(c.Secret) > 64*1024 || !utf8.ValidString(c.Secret) {
		return nil, errRefused
	}
	if c.Kind == "password" {
		if len(c.Secret) > 4096 || strings.ContainsRune(c.Secret, 0) {
			return nil, errRefused
		}
		c.Fingerprint, c.Public = "", ""
		return nil, nil
	}
	if c.Kind != "ssh-key" {
		return nil, errRefused
	}
	raw, public, e := parseSSHKey(*c)
	if e != nil {
		return nil, errRefused
	}
	defer sshkey.Discard(raw)
	key, e := openedKey(raw, public)
	if e != nil {
		return nil, errRefused
	}
	c.Fingerprint = ssh.FingerprintSHA256(key.PublicKey())
	c.Public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
	return key, nil
}

// newGeneratedKey makes an Ed25519 key here for a server account. It is
// sealed with the account but never revealed or exported; the administrator
// puts its public line on the server.
func newGeneratedKey(username string) (Credential, error) {
	if username == "" {
		return Credential{}, errRefused // a key nobody can sign in with is no use
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
	c := Credential{Kind: "ssh-key", Username: username, Secret: string(pem.EncodeToMemory(block)), Generated: true}
	clear(block.Bytes)
	if validateCredential(&c) != nil {
		return Credential{}, errRefused
	}
	return c, nil
}

// parseSSHKey bounds an OpenSSH private key's cost before parsing it: an
// unencrypted key of a type sshkey allows, whose stored public half is the
// private key's own. The caller discards the key it returns.
func parseSSHKey(c Credential) (any, []byte, error) {
	text := strings.TrimSpace(c.Secret)
	if !strings.HasPrefix(text, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return nil, nil, errRefused
	}
	b, rest := pem.Decode([]byte(text))
	if b == nil || b.Type != "OPENSSH PRIVATE KEY" || len(b.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, nil, errRefused
	}
	defer clear(b.Bytes)
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b.Bytes, []byte(magic)) {
		return nil, nil, errRefused
	}
	var outer struct {
		Cipher, KDF, Options string
		Count                uint32
		Public, Private      []byte
		Rest                 []byte `ssh:"rest"`
	}
	// An 8192-bit RSA public key is about 1 KiB and its private section 4 KiB.
	if ssh.Unmarshal(b.Bytes[len(magic):], &outer) != nil || outer.Count != 1 || len(outer.Rest) != 0 || len(outer.Public) > 1100 || len(outer.Private) > 6144 ||
		outer.Cipher != "none" || outer.KDF != "none" || outer.Options != "" {
		return nil, nil, errRefused
	}
	public, e := ssh.ParsePublicKey(outer.Public)
	if e != nil || !sshkey.Allowed(public) {
		return nil, nil, errRefused
	}
	raw, e := ssh.ParseRawPrivateKey([]byte(text))
	if e != nil {
		return nil, nil, errRefused
	}
	// A copy: outer.Public is part of b.Bytes, which is cleared on return.
	return raw, bytes.Clone(outer.Public), nil
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
