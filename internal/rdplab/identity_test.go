package rdplab

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

func labIdentity(t *testing.T) *Identity {
	t.Helper()
	cert, _ := labCertificate(t, nil)
	identity, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func labCertificate(t *testing.T, change func(*x509.Certificate), supplied ...crypto.Signer) (tls.Certificate, [sha256.Size]byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var signer crypto.Signer = priv
	if len(supplied) != 0 {
		signer = supplied[0]
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-rdp.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"synthetic-rdp.invalid"},
	}
	if change != nil {
		change(cert)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer}, sha256.Sum256(der)
}

func TestRDPIdentityImportNameBoundsAndCopiedCertificate(t *testing.T) {
	cert, pin := labCertificate(t, nil)
	original := bytes.Clone(cert.Certificate[0])
	identity, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// A caller changing its certificate afterwards changes nothing here.
	clear(cert.Certificate[0])
	if identity.pin != pin || !bytes.Equal(identity.der, original) || identity.name != "synthetic-rdp.invalid" {
		t.Fatal("caller mutation changed trust")
	}
	for _, tc := range []struct {
		name string
		der  []byte
	}{{"", original}, {"different.invalid", original}, {"synthetic-rdp.invalid", nil}, {"synthetic-rdp.invalid", []byte("bad certificate")}, {"synthetic-rdp.invalid", make([]byte, 32769)}} {
		if _, err := NewIdentity(tc.name, tc.der); err != ErrConfiguration {
			t.Fatal("invalid certificate/name configuration accepted")
		}
	}
	for _, change := range []func(*x509.Certificate){func(c *x509.Certificate) { c.DNSNames = nil }, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }} {
		bad, _ := labCertificate(t, change)
		if _, err := NewIdentity("synthetic-rdp.invalid", bad.Certificate[0]); err != ErrConfiguration {
			t.Fatal("bad approved identity imported")
		}
	}
}

// Windows' RSA and ECDSA certificates are taken; a weak RSA key is not.
func TestRDPIdentityTakesRSAAndECDSAAndRefusesWeakRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		key    crypto.Signer
		accept bool
	}{{"RSA", rsaKey, true}, {"ECDSA", ecdsaKey, true}, {"weak RSA", weakKey, false}} {
		cert, _ := labCertificate(t, nil, tc.key)
		_, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
		if tc.accept && err != nil || !tc.accept && err != ErrConfiguration {
			t.Errorf("%s: unexpected identity decision: %v", tc.name, err)
		}
	}
}

// A certificate outside its dates, for another purpose, or able to sign
// others is never an RDP server's identity.
func TestRDPExpiredAndWrongPurposeCertificatesRefused(t *testing.T) {
	for name, change := range map[string]func(*x509.Certificate){
		"expired": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-2 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		},
		"future": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = time.Now().Add(2 * time.Hour)
		},
		"client-only":        func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		"no-purpose":         func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"CA":                 func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign },
		"no-signature-usage": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
	} {
		cert, _ := labCertificate(t, change)
		if _, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0]); err != ErrConfiguration {
			t.Errorf("%s: certificate became an identity: %v", name, err)
		}
	}
}

func TestRDPPinCertificateKeyAndCriticalExtensionConstraints(t *testing.T) {
	cert, pin := labCertificate(t, nil)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if verifyLeaf(leaf, pin, now) != nil {
		t.Fatal("valid leaf refused")
	}
	for _, key := range []any{nil, (*rsa.PublicKey)(nil), &rsa.PublicKey{N: big.NewInt(7), E: 65537}, (*ecdsa.PublicKey)(nil), &ecdsa.PublicKey{Curve: elliptic.P224()}, ed25519.PublicKey{1}, "unsupported"} {
		candidate := *leaf
		candidate.PublicKey = key
		if verifyLeaf(&candidate, pin, now) != ErrIdentity {
			t.Fatal("weak/unknown key accepted")
		}
	}
	for _, key := range []any{&rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}, &ecdsa.PublicKey{Curve: elliptic.P256()}} {
		candidate := *leaf
		candidate.PublicKey = key
		if verifyLeaf(&candidate, pin, now) != nil {
			t.Fatal("permitted key policy refused")
		}
	}
	candidate := *leaf
	candidate.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
	if verifyLeaf(&candidate, pin, now) != ErrIdentity {
		t.Fatal("unknown critical extension accepted")
	}
	if verifyLeaf(leaf, pin, leaf.NotAfter) != ErrIdentity {
		t.Fatal("expiration boundary accepted")
	}
	if verifyLeaf(nil, pin, now) != ErrIdentity {
		t.Fatal("missing leaf accepted")
	}
	wrong := pin
	wrong[0] ^= 1
	if verifyLeaf(leaf, wrong, now) != ErrIdentity {
		t.Fatal("another digest accepted")
	}
}

// Catalog loading applies every identity check except the validity period;
// NewIdentity, used for each connection, still requires it.
func TestApprovedIdentityCheckedApartFromItsPeriod(t *testing.T) {
	for name, change := range map[string]func(*x509.Certificate){
		"expired": func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		},
		"future": func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
		},
	} {
		cert, _ := labCertificate(t, change)
		if CheckIdentity("synthetic-rdp.invalid", cert.Certificate[0]) != nil {
			t.Fatalf("%s approved certificate refused at load", name)
		}
		if _, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0]); err != ErrConfiguration {
			t.Fatalf("%s certificate authorized a connection", name)
		}
	}
	valid, _ := labCertificate(t, nil)
	if CheckIdentity("synthetic-rdp.invalid", valid.Certificate[0]) != nil || CheckIdentity("SYNTHETIC-RDP.invalid.", valid.Certificate[0]) != nil {
		t.Fatal("valid approved certificate refused")
	}
	for name, change := range map[string]func(*x509.Certificate){
		"name":    func(c *x509.Certificate) { c.DNSNames = nil },
		"purpose": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		"usage":   func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"ca":      func(c *x509.Certificate) { c.BasicConstraintsValid, c.IsCA = true, true },
		"critical": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		bad, _ := labCertificate(t, func(c *x509.Certificate) {
			change(c)
			c.NotBefore, c.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		})
		if CheckIdentity("synthetic-rdp.invalid", bad.Certificate[0]) != ErrConfiguration {
			t.Fatalf("expired certificate with a wrong %s loaded", name)
		}
	}
	for name, der := range map[string][]byte{"empty": nil, "garbage": []byte("not a certificate"), "huge": make([]byte, 32*1024+1)} {
		if CheckIdentity("synthetic-rdp.invalid", der) != ErrConfiguration {
			t.Fatalf("%s certificate loaded", name)
		}
	}
	if CheckIdentity("", valid.Certificate[0]) != ErrConfiguration || CheckIdentity(strings.Repeat("a", 254), valid.Certificate[0]) != ErrConfiguration {
		t.Fatal("certificate loaded without a valid name")
	}
}
