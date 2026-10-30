package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

func TestCustodyRecoveryVerifierPurposeAndOwnerBinding(t *testing.T) {
	one, _, _, _ := custodyFixture(t)
	two, _, _, _ := custodyFixture(t)
	owner := strings.Repeat("a", 32)
	code := "Synthetic-random-token"
	digest := one.recoveryDigest(owner, code)
	if digest == one.recoveryDigest(strings.Repeat("b", 32), code) || digest == two.recoveryDigest(owner, code) || one.recoveryKey == one.indexKey || one.recoveryKey == one.checkKey {
		t.Fatal("recovery verifier lost instance, owner or purpose binding")
	}
	if digest != one.recoveryDigest(owner, code) {
		t.Fatal("valid recovery verifier is not stable")
	}
}

func TestCustodySSHRejectsCostBombAndMismatchedPublic(t *testing.T) {
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture key generation failed")
	}
	block, e := ssh.MarshalPrivateKeyWithPassphrase(private, "synthetic", []byte("synthetic passphrase"))
	if e != nil {
		t.Fatal("fixture encoding failed")
	}
	const magic = "openssh-key-v1\x00"
	type outerKey struct {
		Cipher, KDF, Options string
		Count                uint32
		Public, Private      []byte
	}
	var original outerKey
	if ssh.Unmarshal(block.Bytes[len(magic):], &original) != nil {
		t.Fatal("fixture outer parse failed")
	}
	for _, rounds := range []uint32{0, 65, 0xffffffff} {
		outer := original
		outer.Options = string(ssh.Marshal(struct {
			Salt   string
			Rounds uint32
		}{strings.Repeat("s", 16), rounds}))
		raw := append([]byte(magic), ssh.Marshal(outer)...)
		c := Credential{Name: "fixture", Kind: "ssh-key", Passphrase: "synthetic passphrase", Secret: string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: raw}))}
		if validateCredential(&c) == nil {
			t.Fatal("unbounded bcrypt rounds accepted")
		}
	}
	// The bound itself, both ways: decryption above fails for a wrong salt
	// anyway, so only the predicate shows where the work limit sits.
	options := func(salt int, rounds uint32) string {
		return string(ssh.Marshal(struct {
			Salt   string
			Rounds uint32
		}{strings.Repeat("s", salt), rounds}))
	}
	if !encryptionAllowed("aes256-ctr", "bcrypt", original.Options) || !encryptionAllowed("aes256-ctr", "bcrypt", options(16, 64)) || !encryptionAllowed("aes256-ctr", "bcrypt", options(64, 1)) {
		t.Fatal("a bounded key encryption was refused")
	}
	for name, raw := range map[string][3]string{
		"rounds-65": {"aes256-ctr", "bcrypt", options(16, 65)},
		"rounds-0":  {"aes256-ctr", "bcrypt", options(16, 0)},
		"salt-15":   {"aes256-ctr", "bcrypt", options(15, 16)},
		"salt-65":   {"aes256-ctr", "bcrypt", options(65, 16)},
		"cipher":    {"aes128-ctr", "bcrypt", options(16, 16)},
		"kdf":       {"aes256-ctr", "none", options(16, 16)},
		"options":   {"aes256-ctr", "bcrypt", options(16, 16) + "x"},
	} {
		if encryptionAllowed(raw[0], raw[1], raw[2]) {
			t.Fatalf("%s key encryption allowed", name)
		}
	}
	plain, e := ssh.MarshalPrivateKey(private, "synthetic")
	if e != nil {
		t.Fatal("fixture encoding failed")
	}
	if ssh.Unmarshal(plain.Bytes[len(magic):], &original) != nil {
		t.Fatal("fixture parse failed")
	}
	for _, mutation := range []string{"outer-public", "private-public", "multi-key", "trailing"} {
		outer := original
		outer.Public = bytes.Clone(original.Public)
		outer.Private = bytes.Clone(original.Private)
		switch mutation {
		case "outer-public":
			outer.Public[len(outer.Public)-1] ^= 1
		case "private-public":
			// The ed25519 private blob contains seed || public; alter only its
			// public half, leaving seed and separate public fields unchanged.
			offset := bytes.Index(outer.Private, private)
			if offset < 0 {
				t.Fatal("fixture private blob absent")
			}
			outer.Private[offset+ed25519.SeedSize] ^= 1
		case "multi-key":
			outer.Count = 2
		}
		raw := append([]byte(magic), ssh.Marshal(outer)...)
		if mutation == "trailing" {
			raw = append(raw, 1)
		}
		c := Credential{Name: "fixture", Kind: "ssh-key", Secret: string(pem.EncodeToMemory(&pem.Block{Type: plain.Type, Bytes: raw}))}
		if validateCredential(&c) == nil {
			t.Fatalf("%s key confusion accepted", mutation)
		}
	}
}
func TestCustodyRandomEnvelopesQuotaAndHTTPIsolation(t *testing.T) {
	s, _, _ := bootstrapped(t)
	now := time.Now()
	alice, _, aliceCodes := enrollFixture(t, s, "alice", now)
	if s.update(func(tx *bolt.Tx) error {
		_, _, e := s.createAccount(tx, "bob", accounts(t)[0].Password, time.Now(), true)
		return e
	}) != nil {
		t.Fatal("fixture second account failed")
	}
	bob, _, bobCodes := enrollFixture(t, s, "bob", now)
	c := Credential{Name: "synthetic", Kind: "password", Secret: "synthetic-envelope-canary"}
	if validateCredential(&c) != nil {
		t.Fatal("valid password credential refused")
	}
	record, e := s.putCredential(alice.ID, c)
	if e != nil {
		t.Fatal("valid credential refused")
	}
	// Two equal plaintexts require independent data keys and nonces, and the
	// data and wrapping tags cannot be interchanged.
	if s.update(func(tx *bolt.Tx) error {
		one, e := s.seal(tx, "credential", alice.ID, record, 1, []byte("synthetic"))
		if e != nil {
			return e
		}
		two, e := s.seal(tx, "credential", alice.ID, record, 1, []byte("synthetic"))
		if e != nil {
			return e
		}
		var a, b sealedRecord
		_ = json.Unmarshal(one, &a)
		_ = json.Unmarshal(two, &b)
		if bytes.Equal(a.Key, b.Key) || bytes.Equal(a.Data, b.Data) {
			t.Fatal("random envelopes reused key/nonce ciphertext")
		}
		a.Data = b.Data
		bad, _ := json.Marshal(a)
		if _, _, e = s.unseal("credential", alice.ID, record, bad); e == nil {
			t.Fatal("mixed envelope accepted")
		}
		return nil
	}) != nil {
		t.Fatal("envelope fixture failed")
	}
	l, e := NewPersistent("https://127.0.0.1:8443", s)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	defer l.Close()
	owner := custodyClient{t: t, l: l}
	owner.expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": alicePassword}), 204)
	owner.session("challenge")
	owner.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": bobCodes[0]}), 204)
	owner.session("ready")
	owner.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": bobCodes[1]}), 204)
	owner.expect("POST", "/api/credentials/"+record+"/reveal", "{}", 404)
	owner.expect("DELETE", "/api/credentials/"+record, "{}", 404)
	if _, e = s.readCredential(alice.ID, record); e != nil {
		t.Fatal("cross-account delete removed owner's record")
	}
	if items, e := s.listCredentials(bob.ID); e != nil || len(items) != 0 {
		t.Fatal("cross-account listing exposed metadata")
	}
	owner = custodyClient{t: t, l: l}
	owner.login()
	owner.session("challenge")
	owner.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": aliceCodes[0]}), 204)
	owner.session("ready")
	owner.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": aliceCodes[1]}), 204)
	// Replacement/regen rotate the cookie and revoke every old account session.
	stale := owner.cookie
	w := owner.expect("POST", "/api/mfa/recovery", "{}", 200)
	var newCodes struct{ Codes []string }
	if json.Unmarshal(w.Body.Bytes(), &newCodes) != nil || len(newCodes.Codes) != 10 {
		t.Fatal("regenerated recovery codes absent")
	}
	owner.session("ready")
	if owner.cookie.Value == stale.Value {
		t.Fatal("recovery regeneration kept old session")
	}
	other := custodyClient{t: t, l: l, cookie: stale}
	other.expect("GET", "/api/session", "", 401)
	a, _ := s.lookup("alice")
	if s.consumeFactor(a.ID, a.Revision, aliceCodes[2], now) == nil {
		t.Fatal("old recovery codes survived regeneration")
	}
	if s.consumeFactor(a.ID, a.Revision, newCodes.Codes[0], now) != nil {
		t.Fatal("new recovery codes refused")
	}
	// Avoid crypto-work noise while verifying owner quota: these are synthetic
	// opaque rows; count checks must run before attempting another encryption.
	if s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(credentialBucket)
		for i := 1; i < 256; i++ {
			id, e := randomID()
			if e != nil {
				return e
			}
			if e = b.Put(credentialKey(alice.ID, id), []byte("synthetic quota row")); e != nil {
				return e
			}
		}
		return nil
	}) != nil {
		t.Fatal("quota fixture failed")
	}
	if _, e = s.putCredential(alice.ID, c); e == nil {
		t.Fatal("owner credential quota bypassed")
	}
}
