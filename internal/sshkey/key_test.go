package sshkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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
	material, err := k.Material()
	if err != nil {
		t.Fatal("handoff refused")
	}
	clear(private)
	copied, err := FromMaterial(material)
	if err != nil || !bytes.Equal(copied.PublicKey().Marshal(), k.PublicKey().Marshal()) {
		t.Fatal("handoff changed the key")
	}
	message := []byte("synthetic SSH authentication")
	sig, err := copied.Sign(rand.Reader, message)
	if err != nil || k.PublicKey().Verify(message, sig) != nil {
		t.Fatal("copied key cannot authenticate")
	}
	if fmt.Sprintf("%#v", k) != "[session key redacted]" || strings.Contains(fmt.Sprintf("%v %+v", k, copied), "Ed25519") {
		t.Fatal("key formatting exposed internals")
	}
	k.Close()
	if _, err := k.Material(); err == nil {
		t.Fatal("closed key exported")
	}
	if _, err := k.Sign(rand.Reader, message); err == nil {
		t.Fatal("closed key signed")
	}
	bad := ed25519.NewKeyFromSeed(make([]byte, 32))
	bad[40] ^= 1
	for _, private := range []any{nil, ed25519.PrivateKey(nil), ed25519.PrivateKey(make([]byte, 63)), bad, "not a key", []byte("not a key")} {
		if _, err := New(private); err == nil {
			t.Fatal("malformed or inconsistent key accepted")
		}
	}
	for _, der := range [][]byte{nil, make([]byte, MaxMaterial+1), []byte("not pkcs8")} {
		if _, err := FromMaterial(der); err == nil {
			t.Fatal("malformed handoff accepted")
		}
	}
}

// ECDSA on the three NIST curves and RSA from 2048 to 8192 bits are accepted;
// RSA signs only with SHA-2, never with SHA-1 "ssh-rsa".
func TestSessionKeyTypesStrengthAndAlgorithms(t *testing.T) {
	keys := map[string]any{}
	for name, curve := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()} {
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = private
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys["rsa"] = rsaKey
	for name, private := range keys {
		k, err := New(private)
		if err != nil {
			t.Fatalf("%s key refused", name)
		}
		if slices.Contains(k.Algorithms(), ssh.KeyAlgoRSA) || (name == "rsa") != slices.Equal(k.Algorithms(), []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}) {
			t.Fatalf("%s key offers %v", name, k.Algorithms())
		}
		message := []byte("synthetic " + name)
		for _, algorithm := range k.Algorithms() {
			sig, err := k.SignWithAlgorithm(rand.Reader, message, algorithm)
			if err != nil || sig.Format != algorithm || k.PublicKey().Verify(message, sig) != nil {
				t.Fatalf("%s key cannot sign with %s", name, algorithm)
			}
		}
		if _, err := k.SignWithAlgorithm(rand.Reader, message, ssh.KeyAlgoRSA); err == nil {
			t.Fatalf("%s key signed with SHA-1 ssh-rsa", name)
		}
		material, err := k.Material()
		if err != nil {
			t.Fatalf("%s handoff refused", name)
		}
		if copied, err := FromMaterial(material); err != nil || !bytes.Equal(copied.PublicKey().Marshal(), k.PublicKey().Marshal()) {
			t.Fatalf("%s handoff changed the key", name)
		}
		k.Close()
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	broken, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	broken.D.SetInt64(5)
	for name, private := range map[string]any{"rsa-1024": weak, "p224": p224, "inconsistent-rsa": broken} {
		if _, err := New(private); err == nil {
			t.Fatalf("%s key accepted", name)
		}
	}
	signer, _ := ssh.NewSignerFromKey(weak)
	if Allowed(signer.PublicKey()) || Allowed(nil) {
		t.Fatal("a weak or missing public key is allowed")
	}
	// Moduli at and just past the upper bound; generating real keys this size
	// is too slow for a unit test, and Allowed reads only the public half.
	for bits, want := range map[int]bool{MaxRSABits: true, MaxRSABits + 1: false} {
		modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		public, err := ssh.NewPublicKey(&rsa.PublicKey{N: modulus.Or(modulus, big.NewInt(1)), E: 65537})
		if err != nil || Allowed(public) != want {
			t.Fatalf("a %d-bit RSA modulus allowed=%v", bits, !want)
		}
	}
}

func TestSessionPasswordBoundsAndClose(t *testing.T) {
	p, err := NewPassword("Synthetic şifrə 1!")
	if err != nil {
		t.Fatal("valid password refused")
	}
	value, err := p.Bytes()
	if err != nil || string(value) != "Synthetic şifrə 1!" {
		t.Fatal("password changed")
	}
	if fmt.Sprintf("%v %+v %#v", p, p, p) != "[session password redacted] [session password redacted] [session password redacted]" {
		t.Fatal("password formatting exposed it")
	}
	p.Close()
	if _, err := p.Bytes(); err == nil {
		t.Fatal("closed password exported")
	}
	for _, bad := range []string{"", strings.Repeat("a", MaxPasswordLen+1), "nul\x00inside", string([]byte{0xff})} {
		if _, err := NewPassword(bad); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
	var _ Credential = p
	var _ Credential = (*Key)(nil)
}
