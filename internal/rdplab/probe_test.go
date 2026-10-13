package rdplab

import (
	"bytes"
	"context"
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
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

var hybridConfirmation = [19]byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 1, 0, 2, 0, 8, 0, 2, 0, 0, 0}

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
		BasicConstraintsValid: true,
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

// A private loopback fixture seam never relaxes targetguard's production ban.
// It speaks only the initial X.224 exchange and TLS; there is no CredSSP server.
func tlsFixture(t *testing.T, cert tls.Certificate, version uint16) (func(context.Context) (net.Conn, error), <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			done <- err
			return
		}
		request := make([]byte, 19)
		if _, err := io.ReadFull(raw, request); err != nil {
			done <- err
			return
		}
		// Independent expected wire bytes, including no user/cookie/secret.
		if !bytes.Equal(request, []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}) {
			done <- errors.New("unexpected credential-free request")
			return
		}
		// Fragment the response to exercise stream semantics.
		for _, b := range hybridConfirmation {
			if _, err := raw.Write([]byte{b}); err != nil {
				done <- err
				return
			}
		}
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version}) // #nosec G402 -- old TLS is an explicit refusal fixture only.
		if err := server.Handshake(); err != nil {
			done <- err
			return
		}
		var credential [1]byte
		n, err := server.Read(credential[:])
		if n != 0 {
			done <- errors.New("probe sent application data")
			return
		}
		if err == nil {
			done <- errors.New("probe did not close")
			return
		}
		done <- nil
	}()
	dialer := &net.Dialer{}
	return func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", listener.Addr().String())
	}, done
}

func awaitFixture(t *testing.T, done <-chan error, success bool) {
	t.Helper()
	select {
	case err := <-done:
		if success && err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("fixture did not terminate")
	}
}

func TestRDPHybridTLSProbeVerifiesPinWithoutCredentialsAndCloses(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			cert, pin := labCertificate(t, nil)
			dial, done := tlsFixture(t, cert, version)
			if err := probe(context.Background(), dial, pin); err != nil {
				t.Fatal(err)
			}
			awaitFixture(t, done, true)
		})
	}
}

func TestRDPProbeRSAAndECDSAHandshakeAndWeakRSARefusal(t *testing.T) {
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
		t.Run(tc.name, func(t *testing.T) {
			cert, pin := labCertificate(t, nil, tc.key)
			dial, done := tlsFixture(t, cert, tls.VersionTLS12)
			err := probe(context.Background(), dial, pin)
			if tc.accept && err != nil || !tc.accept && err != ErrIdentity {
				t.Fatalf("unexpected identity decision: %v", err)
			}
			awaitFixture(t, done, tc.accept)
		})
	}
}

func TestRDPChangedExpiredAndWrongPurposeCertificatesRefused(t *testing.T) {
	cases := []struct {
		name     string
		change   func(*x509.Certificate)
		wrongPin bool
	}{
		{name: "changed", wrongPin: true},
		{name: "expired", change: func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-2 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		}},
		{name: "future", change: func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = time.Now().Add(2 * time.Hour)
		}},
		{name: "client-only", change: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{name: "no-purpose", change: func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{name: "CA", change: func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{name: "no-signature-usage", change: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, pin := labCertificate(t, tc.change)
			if tc.wrongPin {
				pin[0] ^= 1
			}
			dial, done := tlsFixture(t, cert, tls.VersionTLS13)
			if err := probe(context.Background(), dial, pin); err != ErrIdentity {
				t.Fatalf("wanted fixed identity error, got %v", err)
			}
			awaitFixture(t, done, false)
		})
	}
	cert, pin := labCertificate(t, nil)
	dial, done := tlsFixture(t, cert, tls.VersionTLS11)
	if err := probe(context.Background(), dial, pin); err != ErrIdentity {
		t.Fatalf("old TLS accepted: %v", err)
	}
	awaitFixture(t, done, false)
}

func TestRDPNegotiationRejectsDowngradeMalformedAndOversized(t *testing.T) {
	for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 13, 14, 15, 16, 17, 18} {
		p := hybridConfirmation
		p[i] ^= 1
		if acceptConfirmation(p) {
			t.Fatalf("changed byte %d accepted", i)
		}
	}
	for _, protocol := range []byte{0, 1, 3, 4, 8, 16, 255} {
		p := hybridConfirmation
		p[15] = protocol
		if acceptConfirmation(p) {
			t.Fatalf("downgrade/mode %d accepted", protocol)
		}
	}
	for _, response := range [][]byte{
		{3, 0, 255, 255}, {3, 0, 0, 11}, {3, 0, 0, 0},
		{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 1, 0, 3, 0, 8, 0, 5, 0, 0, 0},
	} {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			var request [19]byte
			_, _ = io.ReadFull(server, request[:])
			_, _ = server.Write(response)
		}()
		pin := sha256.Sum256([]byte("synthetic"))
		if err := probe(context.Background(), func(context.Context) (net.Conn, error) { return client, nil }, pin); err != ErrNegotiation {
			t.Fatalf("bad confirmation accepted: %v", err)
		}
		<-done
	}
}

func TestRDPInvalidConfigurationCanceledAndFailedDialClose(t *testing.T) {
	pin := sha256.Sum256([]byte("synthetic"))
	calls := 0
	dial := func(context.Context) (net.Conn, error) { calls++; return nil, errors.New("private diagnostic") }
	if probe(context.Background(), dial, [32]byte{}) != ErrConfiguration || calls != 0 {
		t.Fatal("missing pin dialed")
	}
	if Probe(context.Background(), nil, pin) != ErrConfiguration {
		t.Fatal("nil target")
	}
	//lint:ignore SA1012 Nil context is the invalid-input behavior under test.
	if probe(nil, dial, pin) != ErrConfiguration || calls != 0 {
		t.Fatal("nil context dialed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if probe(ctx, dial, pin) != context.Canceled || calls != 0 {
		t.Fatal("canceled request dialed")
	}
	if probe(context.Background(), dial, pin) != ErrUnavailable {
		t.Fatal("diagnostic escaped")
	}
	client, server := net.Pipe()
	defer server.Close()
	if probe(context.Background(), func(context.Context) (net.Conn, error) { return client, errors.New("private") }, pin) != ErrUnavailable {
		t.Fatal("failed dial")
	}
	if _, err := server.Write([]byte{1}); err == nil {
		t.Fatal("failed dial leaked connection")
	}
	// A dial that ignores cancellation cannot hand a live connection back.
	client, server = net.Pipe()
	defer server.Close()
	ctx, cancel = context.WithCancel(context.Background())
	if probe(ctx, func(context.Context) (net.Conn, error) { cancel(); return client, nil }, pin) != context.Canceled {
		t.Fatal("late success escaped cancellation")
	}
	if _, err := server.Write([]byte{1}); err == nil {
		t.Fatal("late success not closed")
	}
}

func TestRDPProbeCancellationUnblocksNegotiationAndTLS(t *testing.T) {
	for _, phase := range []string{"negotiation", "TLS"} {
		t.Run(phase, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			ready := make(chan struct{})
			done := make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				var request [19]byte
				_, _ = io.ReadFull(server, request[:])
				if phase == "TLS" {
					_, _ = server.Write(hybridConfirmation[:])
					var hello [1]byte
					_, _ = server.Read(hello[:])
				}
				close(ready)
			}()
			go func() {
				done <- probe(ctx, func(context.Context) (net.Conn, error) { return client, nil }, sha256.Sum256([]byte("synthetic")))
			}()
			<-ready
			cancel()
			select {
			case err := <-done:
				if err != context.Canceled {
					t.Fatalf("cancellation lost: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation blocked")
			}
		})
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
}

func TestRDPProbeDeadlineClosesStalledConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := probe(ctx, func(context.Context) (net.Conn, error) { return client, nil }, sha256.Sum256([]byte("synthetic"))); err != context.DeadlineExceeded {
		t.Fatalf("deadline lost: %v", err)
	}
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("deadline did not close transport")
	}
	// Deterministically cover transport expiry before the context timer runs.
	past := &labPastDeadline{Context: context.Background()}
	if outcome(past, ErrIdentity) != context.DeadlineExceeded {
		t.Fatal("elapsed transport deadline not classified")
	}
}

type labPastDeadline struct{ context.Context }

func (*labPastDeadline) Deadline() (time.Time, bool) { return time.Now().Add(-time.Second), true }

func FuzzRDPConfirmation(f *testing.F) {
	f.Add(hybridConfirmation[:])
	f.Add([]byte{3, 0, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) != 19 {
			return
		}
		var p [19]byte
		copy(p[:], b)
		if acceptConfirmation(p) && (b[15] != 2 || b[11] != 2 || b[3] != 19) {
			t.Fatal("invalid NLA selection")
		}
	})
}
