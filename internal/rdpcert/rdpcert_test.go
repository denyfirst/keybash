package rdpcert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

var (
	hybrid  = [19]byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 1, 0, 2, 0, 8, 0, 2, 0, 0, 0}
	fixture *rsa.PrivateKey
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	if fixture == nil {
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal("fixture key failed")
		}
		fixture = key
	}
	return fixture
}

// windowsShaped is what Windows Server 2025 makes for itself: self-signed, its
// computer name as the common name, no alternative names, and key encipherment
// without digital signature.
func windowsShaped(change func(*x509.Certificate)) *x509.Certificate {
	cert := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "SYNTHETIC-HOST"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(180 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if change != nil {
		change(cert)
	}
	return cert
}

func sign(t *testing.T, template *x509.Certificate, key crypto.Signer) []byte {
	t.Helper()
	der, e := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if e != nil {
		t.Fatal("fixture certificate failed")
	}
	return der
}

func parsed(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal("fixture certificate unreadable")
	}
	return cert
}

// serve answers one read: a confirmation, then TLS with this certificate. It
// records every byte the client sends after the handshake.
func serve(t *testing.T, confirmation []byte, certificate tls.Certificate, config *tls.Config) (net.Conn, <-chan []byte) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal("fixture listener failed")
	}
	after := make(chan []byte, 1)
	go func() {
		defer listener.Close()
		server, e := listener.Accept()
		if e != nil {
			after <- nil
			return
		}
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(5 * time.Second))
		var request [19]byte
		if _, e = io.ReadFull(server, request[:]); e != nil || request[11] != 1 || request[15] != 3 {
			after <- nil
			return
		}
		if _, e = server.Write(confirmation); e != nil || config == nil {
			after <- nil
			return
		}
		config.Certificates = []tls.Certificate{certificate}
		secured := tls.Server(server, config)
		if secured.Handshake() != nil {
			after <- nil
			return
		}
		sent, _ := io.ReadAll(secured)
		after <- sent
	}()
	client, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal("fixture dial failed")
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	return client, after
}

func TestReadTakesWhatTheServerProvesAndSendsNothing(t *testing.T) {
	key := rsaKey(t)
	der := sign(t, windowsShaped(nil), key)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		client, after := serve(t, hybrid[:], tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, &tls.Config{MinVersion: version, MaxVersion: version})
		cert, e := Read(context.Background(), client)
		if e != nil || !bytes.Equal(cert.Raw, der) {
			t.Fatalf("TLS %x: a good server was not read", version)
		}
		_ = client.Close()
		if sent := <-after; len(sent) != 0 {
			t.Fatalf("TLS %x: the read sent %d bytes after the handshake", version, len(sent))
		}
	}
}

func TestReadRefusesAnythingElse(t *testing.T) {
	key := rsaKey(t)
	der := sign(t, windowsShaped(nil), key)
	good := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	other, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal("fixture key failed")
	}
	otherDER := sign(t, windowsShaped(nil), other)
	tlsOnly, plain := hybrid, hybrid
	tlsOnly[15], plain[15] = 1, 0
	failure := hybrid
	failure[11] = 3 // RDP_NEG_FAILURE: this server does not take what was asked
	longer := hybrid
	longer[3] = 200
	for _, tc := range []struct {
		name         string
		confirmation []byte
		certificate  tls.Certificate
		config       *tls.Config
		want         error
	}{
		{"TLS only", tlsOnly[:], good, nil, ErrNegotiation},
		{"plain RDP", plain[:], good, nil, ErrNegotiation},
		{"negotiation failure", failure[:], good, nil, ErrNegotiation},
		{"an untrusted length", longer[:], good, nil, ErrNegotiation},
		{"a cut confirmation", hybrid[:10], good, nil, ErrUnavailable},
		{"a certificate it holds no key for", hybrid[:], tls.Certificate{Certificate: [][]byte{der}, PrivateKey: other}, &tls.Config{}, ErrIdentity},
		{"a key that signs for another certificate", hybrid[:], tls.Certificate{Certificate: [][]byte{otherDER}, PrivateKey: key}, &tls.Config{}, ErrIdentity},
		{"TLS 1.1", hybrid[:], good, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}, ErrIdentity}, // #nosec G402 -- the server a client must refuse.
		{"a suite without forward secrecy", hybrid[:], good, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}}, ErrIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := serve(t, tc.confirmation, tc.certificate, tc.config)
			cert, e := Read(context.Background(), client)
			if cert != nil || !errors.Is(e, tc.want) {
				t.Fatalf("read %v, want %v", e, tc.want)
			}
		})
	}
	if _, e := Read(context.Background(), nil); e == nil {
		t.Fatal("a read with no connection went on")
	}
}

func TestReadStopsWithItsContext(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		var request [19]byte
		_, _ = io.ReadFull(server, request[:])
		_, _ = server.Write(hybrid[:])
		_, _ = io.Copy(io.Discard, server) // the TLS handshake never answers
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, e := Read(ctx, client); !errors.Is(e, ErrIdentity) {
		t.Fatal("a stalled handshake did not end with its context")
	}
}

// The rules for an exact pin take Windows' own certificate and nothing weaker;
// the rules for a name keep asking for that name and a signing key.
func TestCheckTakesWindowsOwnCertificateAndNothingWeaker(t *testing.T) {
	key := rsaKey(t)
	windows := parsed(t, sign(t, windowsShaped(nil), key))
	if Check(windows) != nil {
		t.Fatal("Windows' own certificate was refused")
	}
	if CheckNamed(windows, "synthetic-host") == nil {
		t.Fatal("a certificate naming nothing passed for a name")
	}
	signing := parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) {
		c.KeyUsage, c.DNSNames = x509.KeyUsageDigitalSignature, []string{"desk.invalid"}
	}), key))
	if Check(signing) != nil || CheckNamed(signing, "desk.invalid") != nil {
		t.Fatal("a signing certificate with a name was refused")
	}
	if CheckNamed(signing, "other.invalid") == nil {
		t.Fatal("a certificate passed for another name")
	}
	encipher := parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) { c.DNSNames = []string{"desk.invalid"} }), key))
	if CheckNamed(encipher, "desk.invalid") == nil {
		t.Fatal("the rules for a name dropped digital signature")
	}
	small, e := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- the weak key a check must refuse.
	if e != nil {
		t.Fatal("fixture key failed")
	}
	curve, e := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if e != nil {
		t.Fatal("fixture key failed")
	}
	for name, cert := range map[string]*x509.Certificate{
		"a CA":                parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }), key)),
		"certificate signing": parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }), key)),
		"no key usage":        parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) { c.KeyUsage = 0 }), key)),
		"data only":           parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDataEncipherment }), key)),
		"no server usage":     parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) { c.ExtKeyUsage = nil }), key)),
		"client usage":        parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }), key)),
		"any usage":           parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }), key)),
		"a small RSA key":     parsed(t, sign(t, windowsShaped(nil), small)),
		"a small curve":       parsed(t, sign(t, windowsShaped(nil), curve)),
		"an unknown critical extension": parsed(t, sign(t, windowsShaped(func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
		}), key)),
	} {
		if Check(cert) == nil {
			t.Fatalf("%s passed the exact-pin rules", name)
		}
	}
	long := *windows
	long.Raw = make([]byte, MaxCertificate+1)
	if Check(&long) == nil || Check(nil) == nil || Check(&x509.Certificate{}) == nil || CheckNamed(nil, "desk.invalid") == nil {
		t.Fatal("an oversized or absent certificate passed")
	}
}

func FuzzConfirmation(f *testing.F) {
	f.Add(hybrid[:])
	f.Fuzz(func(t *testing.T, b []byte) {
		var p [19]byte
		copy(p[:], b)
		if AcceptConfirmation(p) && (p[11] != 2 || p[15] != 2 || p[3] != 19) {
			t.Fatal("a confirmation that does not select HYBRID was accepted")
		}
	})
}
