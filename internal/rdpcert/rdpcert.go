// Package rdpcert reads the certificate an RDP server presents, before any
// credential exists, and holds the rules a certificate must meet to be pinned.
// A read is never trust: a caller compares what it read with a pin, or with a
// fingerprint an administrator brought from the server's own console. The
// worker that later holds a credential enforces its pin on its own handshake.
package rdpcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
)

var (
	ErrNegotiation = errors.New("RDP NLA negotiation refused")
	ErrIdentity    = errors.New("RDP TLS identity refused")
	ErrUnavailable = errors.New("RDP probe unavailable")
)

// MaxCertificate bounds a pinned certificate.
const MaxCertificate = 32 * 1024

// Suites are the TLS 1.2 suites a read and the probe accept: ECDHE with an
// AEAD, as the native worker requires. TLS 1.3's own suites are all AEAD.
func Suites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// Negotiate sends the fixed request (MS-RDPBCGR: TPKT + X.224 CR + NEG_REQ) and
// accepts only a confirmation that selects HYBRID. TLS is advertised as the
// specification asks, but a TLS-only answer is refused. Fixed-size reads: an
// untrusted TPKT length cannot drive allocation. This step is not authenticated;
// it proves nothing about the server by itself.
func Negotiate(conn io.ReadWriter) error {
	request := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
	if n, err := conn.Write(request); err != nil || n != len(request) {
		return ErrUnavailable
	}
	var response [19]byte
	if _, err := io.ReadFull(conn, response[:4]); err != nil {
		return ErrUnavailable
	}
	if response[0] != 3 || response[1] != 0 || response[2] != 0 || response[3] != 19 {
		return ErrNegotiation
	}
	if _, err := io.ReadFull(conn, response[4:]); err != nil {
		return ErrUnavailable
	}
	if !AcceptConfirmation(response) {
		return ErrNegotiation
	}
	return nil
}

// AcceptConfirmation is the one confirmation a client accepts: a negotiation
// response selecting HYBRID.
func AcceptConfirmation(p [19]byte) bool {
	return p[0] == 3 && p[1] == 0 && p[2] == 0 && p[3] == 19 &&
		p[4] == 14 && p[5] == 0xd0 && p[6] == 0 && p[7] == 0 && p[10] == 0 &&
		p[11] == 2 && p[12]&0xe0 == 0 && p[13] == 8 && p[14] == 0 &&
		p[15] == 2 && p[16] == 0 && p[17] == 0 && p[18] == 0
}

// Read takes the certificate an RDP server presents on conn: negotiation, then
// a complete TLS handshake, so the server has proved it holds the key of the
// certificate it shows. Nothing is sent after the handshake, and no credential
// exists here. The caller bounds conn's time and amount, and closes it.
func Read(ctx context.Context, conn net.Conn) (*x509.Certificate, error) {
	if ctx == nil || conn == nil {
		return nil, ErrUnavailable
	}
	if err := Negotiate(conn); err != nil {
		return nil, err
	}
	var leaf *x509.Certificate
	secured := tls.Client(conn, &tls.Config{
		MinVersion:             tls.VersionTLS12,
		CipherSuites:           Suites(),
		SessionTicketsDisabled: true,
		// The certificate is the question here, not yet an answer: the caller
		// compares it. Go still checks the handshake signature against it.
		InsecureSkipVerify: true, // #nosec G402 -- nothing is sent over this connection and the result is compared with a pin or an administrator's fingerprint.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrIdentity
			}
			leaf = state.PeerCertificates[0]
			return nil
		},
	})
	if err := secured.HandshakeContext(ctx); err != nil || leaf == nil {
		return nil, ErrIdentity
	}
	return leaf, nil
}

// CheckServer holds for every pinned RDP certificate: not a CA, no critical
// extension nobody here understands, meant for server authentication, and a
// strong key.
func CheckServer(cert *x509.Certificate) error {
	if cert == nil || len(cert.Raw) == 0 || len(cert.Raw) > MaxCertificate || cert.IsCA || len(cert.UnhandledCriticalExtensions) != 0 {
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

// Check is CheckServer for a server at a literal address, whose identity is the
// exact certificate alone, as an SSH server's is its host key: there is no name
// to verify. The key usage is what TLS itself needs, which is what Windows' own
// RDP certificate carries (key encipherment, without digital signature). It is
// checked as native/identity.c checks it.
func Check(cert *x509.Certificate) error {
	if err := CheckServer(cert); err != nil {
		return err
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 || cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) == 0 {
		return ErrIdentity
	}
	return nil
}

// CheckNamed is CheckServer for a server reached by DNS name: the certificate
// also names it in a subject alternative name and may sign.
func CheckNamed(cert *x509.Certificate, name string) error {
	if err := CheckServer(cert); err != nil {
		return err
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || cert.VerifyHostname(name) != nil {
		return ErrIdentity
	}
	return nil
}
