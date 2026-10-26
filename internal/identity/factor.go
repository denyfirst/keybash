package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	bolt "go.etcd.io/bbolt"
)

func validSeed(seed string) bool {
	b, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	return e == nil && len(b) == 20 && base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b) == seed
}
func newSeed() (string, error) {
	var raw [20]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return "", errRefused
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}

type recoveryCodes []string

func (recoveryCodes) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[recovery codes redacted]")
}

// Recovery codes are random 128-bit tokens, never user-selected passwords.
// An independent instance-derived MAC key also separates their verifier from
// password hashing and prevents offline guesses without that key.
func (s *Store) recoveryDigest(owner, code string) [32]byte {
	h := hmac.New(sha256.New, s.recoveryKey[:])
	_, _ = h.Write([]byte("keybash/recovery/v1/" + owner + "/" + code))
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
func (s *Store) newRecovery(owner string) (recoveryCodes, [][32]byte, error) {
	codes := make(recoveryCodes, 10)
	hashes := make([][32]byte, 10)
	for i := range codes {
		var raw [16]byte
		if _, e := rand.Read(raw[:]); e != nil {
			return nil, nil, errRefused
		}
		codes[i] = base64.RawURLEncoding.EncodeToString(raw[:])
		hashes[i] = s.recoveryDigest(owner, codes[i])
	}
	return codes, hashes, nil
}

// The library implements RFC 4226 HMAC OTP; this adapter supplies the three
// bounded RFC 6238 time counters and persists the greatest consumed counter.
func factorCounter(seed, code string, now time.Time, last int64) (int64, bool) {
	if !validSeed(seed) || len(code) != 6 || now.Unix() < 30 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	current := now.Unix() / 30
	matched := int64(-1)
	for _, counter := range []int64{current - 1, current, current + 1} {
		if counter < 0 {
			continue
		}
		valid, e := hotp.ValidateCustom(code, uint64(counter), seed, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e == nil && valid && counter > last {
			matched = max(matched, counter)
		}
	}
	return matched, matched >= 0
}
func factorBudget(a *durableAccount, now time.Time) bool {
	if a.FactorWindow == 0 || now.Unix()-a.FactorWindow >= 60 {
		a.FactorWindow = now.Unix()
		a.FactorCount = 0
	}
	if a.FactorCount >= 5 {
		return false
	}
	a.FactorCount++
	return true
}
func (s *Store) consumeFactor(id string, revision uint64, code string, now time.Time) error {
	accepted := false
	e := s.update(func(tx *bolt.Tx) error {
		a, e := s.readAccount(tx, id)
		if e != nil || a.Revision != revision || a.Seed == "" {
			return errRefused
		}
		if !factorBudget(&a, now) {
			return errRefused
		}
		if counter, ok := factorCounter(a.Seed, code, now, a.LastCounter); ok {
			a.LastCounter = counter
			accepted = true
		} else if len(code) == 22 {
			digest := s.recoveryDigest(id, code)
			for i, h := range a.Recovery {
				if subtle.ConstantTimeCompare(h[:], digest[:]) == 1 {
					a.Recovery = append(a.Recovery[:i], a.Recovery[i+1:]...)
					accepted = true
					break
				}
			}
		}
		// Invalid attempts also commit their durable budget; returning the
		// refusal from inside this transaction would roll that budget back.
		return s.saveAccount(tx, a)
	})
	if e != nil || !accepted {
		return errRefused
	}
	return nil
}
func (s *Store) enroll(id string, revision uint64, seed, code string, now time.Time, replace bool) (recoveryCodes, error) {
	accepted := false
	var codes recoveryCodes
	e := s.update(func(tx *bolt.Tx) error {
		a, e := s.readAccount(tx, id)
		if e != nil || a.Revision != revision || (a.Seed != "") != replace || !validSeed(seed) {
			return errRefused
		}
		if !factorBudget(&a, now) {
			return errRefused
		}
		if counter, ok := factorCounter(seed, code, now, -1); ok {
			var hashes [][32]byte
			codes, hashes, e = s.newRecovery(id)
			if e != nil {
				return e
			}
			a.Seed, a.LastCounter, a.Recovery = seed, counter, hashes
			a.Enrollment, a.EnrollmentEnd = nil, 0 // the one-time setup code is spent
			a.Revision++
			accepted = true
		}
		return s.saveAccount(tx, a)
	})
	if e != nil || !accepted {
		return nil, errRefused
	}
	return codes, nil
}
func (s *Store) replacePassword(id string, revision uint64, next PasswordHash) error {
	return s.update(func(tx *bolt.Tx) error {
		a, e := s.readAccount(tx, id)
		if e != nil || a.Revision != revision || !next.valid() {
			return errRefused
		}
		a.Hash = storedPassword(next)
		a.Revision++
		return s.saveAccount(tx, a)
	})
}
func (s *Store) regenerateRecovery(id string, revision uint64) (recoveryCodes, error) {
	var codes recoveryCodes
	e := s.update(func(tx *bolt.Tx) error {
		a, e := s.readAccount(tx, id)
		if e != nil || a.Revision != revision || a.Seed == "" {
			return errRefused
		}
		codes, a.Recovery, e = s.newRecovery(id)
		if e != nil {
			return e
		}
		a.Revision++
		return s.saveAccount(tx, a)
	})
	if e != nil {
		return nil, errRefused
	}
	return codes, nil
}
