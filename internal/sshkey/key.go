// Package sshkey holds exactly one already-authorized SSH session credential:
// a private key or a password. It is not a vault, agent or general signing
// service.
package sshkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

var ErrKey = errors.New("session key unavailable")

// Bounds on what a session may carry. RSA below 2048 bits is refused as too
// weak; above 8192 only adds signing cost an operator never needs.
const (
	MinRSABits     = 2048
	MaxRSABits     = 8192
	MaxPasswordLen = 4096
	// MaxMaterial bounds a PKCS#8 handoff: an 8192-bit RSA key is under 5 KiB.
	MaxMaterial = 8192
)

// Credential is one session's secret: a *Key or a *Password, nothing else.
type Credential interface {
	fmt.Formatter
	Close()
	sessionCredential()
}

// Key supports the in-process SSH adapter and a single worker handoff.
// Close is best-effort lifetime reduction, not a guaranteed RAM-erasure claim.
type Key struct {
	mu         sync.Mutex
	private    any // ed25519.PrivateKey, *ecdsa.PrivateKey or *rsa.PrivateKey
	signer     ssh.AlgorithmSigner
	public     ssh.PublicKey
	algorithms []string
}

// AlgorithmsFor lists what a key of this type may sign with; SHA-1 "ssh-rsa" is
// never offered. Nil means the type is not accepted.
func AlgorithmsFor(public ssh.PublicKey) []string {
	switch public.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return []string{public.Type()}
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return nil
}

// Allowed reports whether a public key is a type and strength sessions accept.
func Allowed(public ssh.PublicKey) bool {
	if public == nil || AlgorithmsFor(public) == nil {
		return false
	}
	if public.Type() != ssh.KeyAlgoRSA {
		return true
	}
	crypto, ok := public.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	key, ok := crypto.CryptoPublicKey().(*rsa.PublicKey)
	return ok && key.N.BitLen() >= MinRSABits && key.N.BitLen() <= MaxRSABits
}

// New takes a private key, checks its type, strength and consistency, and
// keeps its own copy. Accepted: Ed25519, ECDSA P-256/384/521, RSA 2048–8192.
func New(private any) (*Key, error) {
	var owned any
	switch k := private.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, ErrKey
		}
		derived := ed25519.NewKeyFromSeed(k[:ed25519.SeedSize])
		if !bytes.Equal(derived, k) {
			clear(derived)
			return nil, ErrKey
		}
		owned = derived
	case *ed25519.PrivateKey:
		if k == nil {
			return nil, ErrKey
		}
		return New(*k)
	case *ecdsa.PrivateKey:
		if k == nil || k.Curve == nil {
			return nil, ErrKey
		}
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return nil, ErrKey
		}
		copied, err := copyThroughPKCS8(k)
		if err != nil {
			return nil, ErrKey
		}
		owned = copied
	case *rsa.PrivateKey:
		if k == nil || k.N == nil || k.N.BitLen() < MinRSABits || k.N.BitLen() > MaxRSABits || k.Validate() != nil {
			return nil, ErrKey
		}
		copied, err := copyThroughPKCS8(k)
		if err != nil {
			return nil, ErrKey
		}
		owned = copied
	default:
		return nil, ErrKey
	}
	signer, err := ssh.NewSignerFromKey(owned)
	if err != nil {
		return nil, ErrKey
	}
	algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok || !Allowed(signer.PublicKey()) {
		return nil, ErrKey
	}
	return &Key{private: owned, signer: algorithmSigner, public: signer.PublicKey(), algorithms: AlgorithmsFor(signer.PublicKey())}, nil
}

// copyThroughPKCS8 gives the session its own key value, independent of the
// caller's, by a round trip through the standard encoding.
func copyThroughPKCS8(private any) (any, error) {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return x509.ParsePKCS8PrivateKey(der)
}

func (*Key) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[session key redacted]") }
func (*Key) sessionCredential()         {}
func (k *Key) PublicKey() ssh.PublicKey { return k.public }

// Algorithms lists what this key may sign with, so a client never falls back
// to a weaker default (SHA-1 for RSA).
func (k *Key) Algorithms() []string { return slices.Clone(k.algorithms) }

func (k *Key) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	return k.SignWithAlgorithm(random, data, k.algorithms[0])
}

func (k *Key) SignWithAlgorithm(random io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.signer == nil || !slices.Contains(k.algorithms, algorithm) {
		return nil, ErrKey
	}
	return k.signer.SignWithAlgorithm(random, data, algorithm)
}

// Material returns a fresh PKCS#8 copy for a private, bounded worker startup
// pipe. It must never be logged or put in process arguments, the environment
// or a filesystem.
func (k *Key) Material() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.signer == nil {
		return nil, ErrKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(k.private)
	if err != nil || len(der) > MaxMaterial {
		clear(der)
		return nil, ErrKey
	}
	return der, nil
}

// FromMaterial is the worker's side of Material.
func FromMaterial(der []byte) (*Key, error) {
	if len(der) == 0 || len(der) > MaxMaterial {
		return nil, ErrKey
	}
	private, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, ErrKey
	}
	if key, ok := private.(ed25519.PrivateKey); ok {
		defer clear(key)
	}
	return New(private)
}

func (k *Key) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	Discard(k.private)
	k.private = nil
	k.signer = nil
}

// Discard overwrites a parsed private key's secret values where Go exposes
// them, best effort. Ed25519 bytes are cleared. RSA's big.Int fields are
// zeroed, though the library keeps precomputed copies. An ECDSA key keeps its
// scalar internally, so only dropping the reference helps. Go makes no
// erasure guarantee.
func Discard(private any) {
	switch k := private.(type) {
	case ed25519.PrivateKey:
		clear(k)
	case *ed25519.PrivateKey:
		if k != nil {
			clear(*k)
		}
	case *rsa.PrivateKey:
		if k != nil && k.D != nil {
			k.D.SetInt64(0)
			for _, prime := range k.Primes {
				prime.SetInt64(0)
			}
		}
	}
}

// Password is a remote account's password for one session. The SSH library
// takes it as a Go string, which cannot be cleared; Close drops this copy.
type Password struct {
	mu    sync.Mutex
	value []byte
}

// ValidPassword is the same rule credential import applies: nonempty UTF-8,
// at most 4096 bytes, no NUL.
func ValidPassword(value string) bool {
	return len(value) > 0 && len(value) <= MaxPasswordLen && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func NewPassword(value string) (*Password, error) {
	if !ValidPassword(value) {
		return nil, ErrKey
	}
	return &Password{value: []byte(value)}, nil
}

func (*Password) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[session password redacted]") }
func (*Password) sessionCredential()         {}

// Bytes returns a fresh copy for one handoff.
func (p *Password) Bytes() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.value == nil {
		return nil, ErrKey
	}
	return bytes.Clone(p.value), nil
}

func (p *Password) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.value)
	p.value = nil
}
