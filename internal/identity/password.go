// Package identity implements the isolated password-login laboratory. It is not
// yet a persistent account store, MFA service or remote-access authorization API.
package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

var errRefused = errors.New("identity request refused")
var errLimited = errors.New("identity request limited")

// PasswordHash is an opaque, versioned value; it cannot carry caller-selected
// allocation/work parameters. Persistence and migration are a separate gate.
type PasswordHash struct {
	version byte
	salt    [16]byte
	sum     [32]byte
}

func (PasswordHash) Format(w fmt.State, _ rune) { _, _ = w.Write([]byte("[password hash redacted]")) }

func passwordInput(password string) bool {
	return len(password) > 0 && len(password) <= 1024 && utf8.ValidString(password)
}

// HashPassword is for trusted provisioning only, never an unbounded HTTP path.
// Argon2id: 64 MiB, three passes, four lanes, random 128-bit salt, 256-bit output.
// Password bytes are preserved exactly, without trimming or normalization.
func HashPassword(password string) (PasswordHash, error) {
	if !passwordInput(password) || utf8.RuneCountInString(password) < 15 {
		return PasswordHash{}, errRefused
	}
	h := PasswordHash{version: 1}
	if _, err := rand.Read(h.salt[:]); err != nil {
		return PasswordHash{}, errRefused
	}
	key := passwordKey(password, h.salt[:])
	copy(h.sum[:], key)
	clear(key)
	return h, nil
}

func passwordKey(password string, salt []byte) []byte {
	value := []byte(password)
	defer clear(value) // best effort only; Go/Argon2 can retain other copies
	return argon2.IDKey(value, salt, 3, 64*1024, 4, 32)
}

func (h PasswordHash) valid() bool { return h.version == 1 }
func (h PasswordHash) verify(password string) bool {
	if !h.valid() || !passwordInput(password) {
		return false
	}
	key := passwordKey(password, h.salt[:])
	defer clear(key)
	return subtle.ConstantTimeCompare(key, h.sum[:]) == 1
}
