// Package rdplab contains a credential-free RDP identity experiment. It is not
// an RDP client, an authentication result, or authorization for a later worker.
package rdplab

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/targetguard"
)

var (
	ErrConfiguration = errors.New("invalid RDP probe configuration")
	ErrNegotiation   = errors.New("RDP NLA negotiation refused")
	ErrIdentity      = errors.New("RDP TLS identity refused")
	ErrUnavailable   = errors.New("RDP probe unavailable")
)

const setupBudget = 5 * time.Second

// Identity is an immutable out-of-band approved leaf certificate and DNS name.
// System roots are not used. Callers cannot mutate the copied DER or trust pool.
type Identity struct {
	name  string
	pin   [sha256.Size]byte
	roots *x509.CertPool
	der   []byte
}

// NewIdentity requires a bounded valid server certificate matching the logical
// DNS identity. Importing the certificate is an independent trust decision,
// never automatic acceptance of a certificate observed over this connection.
func NewIdentity(name string, approvedDER []byte) (*Identity, error) {
	if len(name) == 0 || len(name) > 253 || len(approvedDER) == 0 || len(approvedDER) > 32*1024 {
		return nil, ErrConfiguration
	}
	cert, err := x509.ParseCertificate(append([]byte(nil), approvedDER...))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if err != nil {
		return nil, ErrConfiguration
	}
	pin := sha256.Sum256(cert.Raw)
	if verifyLeaf(cert, pin, time.Now()) != nil || cert.VerifyHostname(name) != nil {
		return nil, ErrConfiguration
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &Identity{name: name, pin: pin, roots: roots, der: cert.Raw}, nil
}

// Probe verifies an independently approved leaf, its SHA-256 digest and name
// after a HYBRID negotiation. It never accepts a password, sends CredSSP data,
// or returns a usable connection. It closes the connection on every outcome.
// This result MUST NOT authorize a subsequent connection: the actual native
// worker must independently enforce its pin on its own TLS handshake.
func Probe(ctx context.Context, target *targetguard.NamedTarget, identity *Identity) error {
	if target == nil || identity == nil || identity.name != target.Hostname() {
		return ErrConfiguration
	}
	return probe(ctx, target.DialContext, identity)
}

func probe(ctx context.Context, dial func(context.Context) (net.Conn, error), identity *Identity) error {
	if ctx == nil || dial == nil || identity == nil || identity.roots == nil || identity.name == "" || identity.pin == [sha256.Size]byte{} {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, setupBudget)
	defer cancel()
	raw, err := dial(ctx)
	if raw != nil {
		defer raw.Close()
	}
	if err != nil || raw == nil {
		return outcome(ctx, ErrUnavailable)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return outcome(ctx, ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// MS-RDPBCGR: TPKT + X.224 CR + NEG_REQ. TLS is advertised as required
	// by the specification's SHOULD, but a TLS-only response is refused.
	request := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
	if n, err := raw.Write(request); err != nil || n != len(request) {
		return outcome(ctx, ErrUnavailable)
	}
	// Fixed-size reads: an untrusted TPKT length cannot drive allocation.
	var response [19]byte
	if _, err := io.ReadFull(raw, response[:4]); err != nil {
		return outcome(ctx, ErrUnavailable)
	}
	if response[0] != 3 || response[1] != 0 || response[2] != 0 || response[3] != 19 {
		return outcome(ctx, ErrNegotiation)
	}
	if _, err := io.ReadFull(raw, response[4:]); err != nil {
		return outcome(ctx, ErrUnavailable)
	}
	if !acceptConfirmation(response) {
		return outcome(ctx, ErrNegotiation)
	}
	// Standard TLS name/certificate verification remains enabled. Only the
	// imported leaf is a trust anchor; the additional exact pin is mandatory.
	// VerifyConnection runs even on resumed handshakes; session caching is off.
	secured := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: identity.name,
		RootCAs:    identity.roots,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrIdentity
			}
			return verifyLeaf(state.PeerCertificates[0], identity.pin, time.Now())
		},
	})
	if err := secured.HandshakeContext(ctx); err != nil {
		return outcome(ctx, ErrIdentity)
	}
	return outcome(ctx, nil)
}

func acceptConfirmation(p [19]byte) bool {
	return p[0] == 3 && p[1] == 0 && p[2] == 0 && p[3] == 19 &&
		p[4] == 14 && p[5] == 0xd0 && p[6] == 0 && p[7] == 0 && p[10] == 0 &&
		p[11] == 2 && p[12]&0xe0 == 0 && p[13] == 8 && p[14] == 0 &&
		p[15] == 2 && p[16] == 0 && p[17] == 0 && p[18] == 0
}

func verifyLeaf(cert *x509.Certificate, pin [sha256.Size]byte, now time.Time) error {
	if cert == nil || len(cert.Raw) == 0 || pin == [sha256.Size]byte{} {
		return ErrIdentity
	}
	digest := sha256.Sum256(cert.Raw)
	if subtle.ConstantTimeCompare(digest[:], pin[:]) != 1 ||
		now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.IsCA || len(cert.UnhandledCriticalExtensions) != 0 ||
		cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ErrIdentity
	}
	serverAuth := false
	for _, usage := range cert.ExtKeyUsage {
		serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth
	}
	if !serverAuth {
		return ErrIdentity
	}
	switch key := cert.PublicKey.(type) {
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return ErrIdentity
		}
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.N.BitLen() < 2048 {
			return ErrIdentity
		}
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.Curve.Params().BitSize < 256 {
			return ErrIdentity
		}
	default:
		return ErrIdentity
	}
	return nil
}

func outcome(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// The connection deadline can fire before the context timer is scheduled.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return fallback
}
