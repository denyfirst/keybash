// Package rdplab contains a credential-free RDP identity experiment. It is not
// an RDP client, an authentication result, or authorization for a later worker.
package rdplab

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/rdpcert"
	"github.com/denyfirst/keybash/internal/targetguard"
)

var (
	ErrConfiguration = errors.New("invalid RDP probe configuration")
	ErrNegotiation   = rdpcert.ErrNegotiation
	ErrIdentity      = rdpcert.ErrIdentity
	ErrUnavailable   = rdpcert.ErrUnavailable
)

const setupBudget = 5 * time.Second

// exactLeaf stands where a DNS name would be for a server at a literal address,
// whose identity is its exact certificate alone. native/identity.c reads the
// same value. "@" is in no DNS name, so a missing, empty or cut file can never
// be read as this: only these exact bytes turn the name check off.
const exactLeaf = "@exact-leaf"

// Identity is an immutable out-of-band approved leaf certificate and DNS name,
// or exactLeaf. System roots are not used. Callers cannot mutate the copied DER
// or trust pool.
type Identity struct {
	name  string
	pin   [sha256.Size]byte
	roots *x509.CertPool
	der   []byte
}

// boundTo reports whether this identity is for that target: a named identity
// for that name, the exact certificate for a literal address.
func (i *Identity) boundTo(target *targetguard.NamedTarget) bool {
	if i == nil || target == nil || i.name == "" {
		return false
	}
	if i.name == exactLeaf {
		return target.Literal()
	}
	return !target.Literal() && i.name == target.Hostname()
}

// NewIdentity requires a bounded valid server certificate matching the logical
// DNS identity. Importing the certificate is an independent trust decision,
// never automatic acceptance of a certificate observed over this connection.
func NewIdentity(name string, approvedDER []byte) (*Identity, error) {
	cert, name, err := approvedLeaf(name, approvedDER)
	if err != nil {
		return nil, err
	}
	pin := sha256.Sum256(cert.Raw)
	if verifyLeaf(cert, pin, time.Now()) != nil {
		return nil, ErrConfiguration
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &Identity{name: name, pin: pin, roots: roots, der: cert.Raw}, nil
}

// NewExactIdentity is NewIdentity for a server at a literal address: an
// administrator compared this exact certificate on the server's console, and
// it is the identity, as a host key is an SSH server's. No name is checked,
// because there is none; every other rule stays, the validity period included.
func NewExactIdentity(approvedDER []byte) (*Identity, error) {
	if len(approvedDER) == 0 || len(approvedDER) > rdpcert.MaxCertificate {
		return nil, ErrConfiguration
	}
	cert, err := x509.ParseCertificate(append([]byte(nil), approvedDER...))
	if err != nil || rdpcert.Check(cert) != nil {
		return nil, ErrConfiguration
	}
	if now := time.Now(); now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, ErrConfiguration
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &Identity{name: exactLeaf, pin: sha256.Sum256(cert.Raw), roots: roots, der: cert.Raw}, nil
}

// CheckIdentity applies every NewIdentity check except the validity period.
// An approved certificate that has expired (Windows renews its own) or is not
// yet valid is still a well-formed operator decision: it loads, and only its
// server stays unavailable, because NewIdentity and every connection check
// the period again.
func CheckIdentity(name string, approvedDER []byte) error {
	_, _, err := approvedLeaf(name, approvedDER)
	return err
}

func approvedLeaf(name string, approvedDER []byte) (*x509.Certificate, string, error) {
	if len(name) == 0 || len(name) > 253 || len(approvedDER) == 0 || len(approvedDER) > rdpcert.MaxCertificate {
		return nil, "", ErrConfiguration
	}
	cert, err := x509.ParseCertificate(append([]byte(nil), approvedDER...))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if err != nil || checkLeaf(cert, sha256.Sum256(cert.Raw)) != nil || cert.VerifyHostname(name) != nil {
		return nil, "", ErrConfiguration
	}
	return cert, name, nil
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
	if err := rdpcert.Negotiate(raw); err != nil {
		return outcome(ctx, err)
	}
	// Standard TLS name/certificate verification remains enabled. Only the
	// imported leaf is a trust anchor; the additional exact pin is mandatory.
	// VerifyConnection runs even on resumed handshakes; session caching is off.
	secured := tls.Client(raw, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   identity.name,
		RootCAs:      identity.roots,
		CipherSuites: rdpcert.Suites(),
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

func verifyLeaf(cert *x509.Certificate, pin [sha256.Size]byte, now time.Time) error {
	if checkLeaf(cert, pin) != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return ErrIdentity
	}
	return nil
}

// checkLeaf is everything verifyLeaf requires except the validity period.
func checkLeaf(cert *x509.Certificate, pin [sha256.Size]byte) error {
	if cert == nil || len(cert.Raw) == 0 || pin == [sha256.Size]byte{} {
		return ErrIdentity
	}
	digest := sha256.Sum256(cert.Raw)
	if subtle.ConstantTimeCompare(digest[:], pin[:]) != 1 || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || rdpcert.CheckServer(cert) != nil {
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
