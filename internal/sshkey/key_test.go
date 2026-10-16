package sshkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSessionKeyHandoffAndClose(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("entropy failed")
	}
	k, err := New(private)
	if err != nil {
		t.Fatal("valid session key refused")
	}
	defer k.Close()
	seed, err := k.Seed()
	if err != nil || !bytes.Equal(seed, private[:32]) {
		t.Fatal("wrong handoff key")
	}
	clear(seed)
	clear(private)
	message := []byte("synthetic SSH authentication")
	sig, err := k.Sign(rand.Reader, message)
	if err != nil || k.PublicKey().Verify(message, sig) != nil {
		t.Fatal("copied key cannot authenticate")
	}
	if fmt.Sprintf("%#v", k) != "[session key redacted]" {
		t.Fatal("key formatting exposed internals")
	}
	k.Close()
	if _, err := k.Seed(); err == nil {
		t.Fatal("closed key exported")
	}
	if _, err := k.Sign(rand.Reader, message); err == nil {
		t.Fatal("closed key signed")
	}
	bad := ed25519.NewKeyFromSeed(make([]byte, 32))
	bad[40] ^= 1
	for _, private := range []ed25519.PrivateKey{nil, make([]byte, 63), bad} {
		if _, err := New(private); err == nil {
			t.Fatal("malformed or inconsistent key accepted")
		}
	}
}
