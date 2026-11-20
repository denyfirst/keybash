// Package rdplab runs browser desktops on Linux: the approved identity of an
// RDP server, the manager and the sandboxed worker that start Keybash's RDP
// proxy (docs/BROWSER-RDP-PROXY.md), and the stream between the gateway and
// that proxy. The proxy, not this package, meets the server's TLS and enforces
// the identity there before any credential leaves it.
package rdplab

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/rdpcert"
	"github.com/denyfirst/keybash/internal/targetguard"
)

var (
	ErrConfiguration = errors.New("RDP server identity refused")
	ErrIdentity      = rdpcert.ErrIdentity
)

// exactLeaf stands where a DNS name would be for a server at a literal address,
// whose identity is its exact certificate alone. The RDP proxy reads the same
// value (rdp-proxy/src/pin.rs). "@" is in no DNS name, so a missing, empty or
// cut file can never be read as this: only these exact bytes turn the name
// check off.
const exactLeaf = "@exact-leaf"

// Identity is an immutable out-of-band approved leaf certificate and DNS name,
// or exactLeaf. System roots are not used. Callers cannot mutate the copied DER.
type Identity struct {
	name string
	pin  [sha256.Size]byte
	der  []byte
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
	return &Identity{name: name, pin: pin, der: cert.Raw}, nil
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
	return &Identity{name: exactLeaf, pin: sha256.Sum256(cert.Raw), der: cert.Raw}, nil
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
