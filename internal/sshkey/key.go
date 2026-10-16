// Package sshkey holds exactly one already-authorized Ed25519 session key.
// It is not a vault, agent or general signing service.
package sshkey

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

var ErrKey = errors.New("session key unavailable")

// Key supports the existing in-process SSH adapter and a single worker handoff.
// Close is best-effort lifetime reduction, not a guaranteed RAM-erasure claim.
type Key struct {
	mu      sync.Mutex
	private ed25519.PrivateKey
	signer  ssh.Signer
	public  ssh.PublicKey
}

func New(private ed25519.PrivateKey) (*Key, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, ErrKey
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	if !bytes.Equal(derived, private) {
		clear(derived)
		return nil, ErrKey
	}
	signer, err := ssh.NewSignerFromKey(derived)
	if err != nil {
		clear(derived)
		return nil, ErrKey
	}
	return &Key{private: derived, signer: signer, public: signer.PublicKey()}, nil
}
func (*Key) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[session key redacted]") }
func (k *Key) PublicKey() ssh.PublicKey { return k.public }
func (k *Key) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.signer == nil {
		return nil, ErrKey
	}
	return k.signer.Sign(random, data)
}

// Seed returns a fresh copy for a private, bounded worker startup pipe. It must
// never be logged or put in process arguments/environment or a filesystem.
func (k *Key) Seed() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.signer == nil {
		return nil, ErrKey
	}
	return append([]byte(nil), k.private[:ed25519.SeedSize]...), nil
}
func (k *Key) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	clear(k.private)
	k.private = nil
	k.signer = nil
}
