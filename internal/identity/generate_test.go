package identity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A key made here is for people who have none: only its public line ever
// leaves, it works like an imported key for connections, and nothing can
// mark an imported key as made here.
func TestGeneratedKeysNeverLeave(t *testing.T) {
	s, _, _, code := custodyFixture(t)
	now := time.Now()
	hash, e := HashPassword(alicePassword)
	if e != nil || s.bootstrap(code, "alice", hash, now) != nil {
		t.Fatal("fixture account failed")
	}
	account, _, recovery := enrollFixture(t, s, "alice", now)
	l, e := NewPersistent("https://127.0.0.1:8443", s)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	defer l.Close()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	c := &custodyClient{t: t, l: l}
	c.login()
	c.session("challenge")
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": recovery[0]}), 204)
	c.session("ready")
	advance(l, &now, freshProof) // making a key needs a ready session, not fresh proof

	w := c.expect("POST", "/api/credentials/generate", inputJSON(map[string]string{"name": "Made here", "username": "deploy"}), 200)
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("generation returned the private key")
	}
	var made struct{ ID, Public string }
	if json.Unmarshal(w.Body.Bytes(), &made) != nil || !validID(made.ID) {
		t.Fatal("generation reply malformed")
	}
	public, comment, options, rest, e := ssh.ParseAuthorizedKey([]byte(made.Public))
	if e != nil || public.Type() != ssh.KeyAlgoED25519 || comment != "" || len(options) != 0 || len(rest) != 0 {
		t.Fatal("generated public line is not a bare ed25519 key")
	}
	stored, e := s.readCredential(account.ID, made.ID)
	if e != nil || !stored.Generated || stored.Kind != "ssh-key" || stored.Username != "deploy" || stored.Public != made.Public {
		t.Fatal("generated key not stored as made here")
	}
	key, e := openSSHKey(stored)
	if e != nil || string(key.PublicKey().Marshal()) != string(public.Marshal()) {
		t.Fatal("stored private key does not match its public line")
	}
	key.Close()
	listed := c.expect("GET", "/api/credentials", "", 200)
	var rows []credentialSummary
	if json.Unmarshal(listed.Body.Bytes(), &rows) != nil || len(rows) != 1 || !rows[0].Generated || rows[0].Public != made.Public || rows[0].Fingerprint != ssh.FingerprintSHA256(public) || strings.Contains(listed.Body.String(), "PRIVATE KEY") {
		t.Fatal("listing does not show the generated key's public half alone")
	}

	// Never revealed, even with fresh proof.
	reveal := "/api/credentials/" + made.ID + "/reveal"
	c.expect("POST", reveal, "{}", 428)
	c.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": recovery[1]}), 204)
	if w := c.expect("POST", reveal, "{}", 403); strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("refused reveal leaked the key")
	}

	// Each one is new; input is exactly a name and a user.
	again := c.expect("POST", "/api/credentials/generate", inputJSON(map[string]string{"name": "Another", "username": "deploy"}), 200)
	if strings.Contains(again.Body.String(), made.Public) {
		t.Fatal("two generations made the same key")
	}
	for _, body := range []string{
		inputJSON(map[string]string{"name": "x", "username": ""}),
		inputJSON(map[string]string{"name": "", "username": "u"}),
		inputJSON(map[string]string{"name": "a\nb", "username": "u"}),
		inputJSON(map[string]string{"name": "x", "username": "u", "secret": "chosen"}),
		inputJSON(map[string]string{"name": "x", "username": "u", "kind": "password"}),
		`{"name":"x","username":"u","generated":true}`,
		`not json`,
	} {
		advance(l, &now, 61*time.Second) // past the per-minute import limit
		c.expect("POST", "/api/credentials/generate", body, 400)
	}
	// An imported key cannot claim to have been made here.
	c.expect("POST", "/api/credentials", `{"name":"x","kind":"password","username":"u","secret":"s","passphrase":"","generated":true}`, 400)
	c.expect("DELETE", "/api/credentials/"+made.ID, "{}", 204)
	c.expect("POST", reveal, "{}", 404)
}
