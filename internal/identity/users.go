package identity

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Why an administrator's change was refused, where the page can say more
// than "not allowed".
var (
	errTaken     = errors.New("username taken")
	errMissing   = errors.New("no such account")
	errLastAdmin = errors.New("no administrator would remain")
	errNoPhone   = errors.New("no phone to confirm a new password with")
)

// updateWhy is update that keeps the reason fn refused with; a failed commit
// is errRefused.
func (s *Store) updateWhy(fn func(*bolt.Tx) error) error {
	var why error
	if s.update(func(tx *bolt.Tx) error { why = fn(tx); return why }) != nil {
		if why != nil {
			return why
		}
		return errRefused
	}
	return nil
}

// Three roles. A user reaches servers with their own keys and passwords. An
// administrator also manages accounts. An auditor reaches no server and holds
// no secret: they read what happened. The stored user role is empty, so
// records from before roles read as users.
const (
	roleUser    = ""
	roleAdmin   = "admin"
	roleAuditor = "auditor"
)

func validRole(role string) bool { return role == roleUser || role == roleAdmin || role == roleAuditor }

// roleWord and wordRole translate between the stored role and the word the
// page uses; an unknown word is no role at all.
func roleWord(role string) string {
	if role == roleUser {
		return "user"
	}
	return role
}
func wordRole(word string) (string, bool) {
	switch word {
	case "user":
		return roleUser, true
	case roleAdmin, roleAuditor:
		return word, true
	}
	return "", false
}

// activeAdmin can administer now: an administrator who is not blocked and has
// chosen a password.
func activeAdmin(a durableAccount) bool { return a.Role == roleAdmin && !a.Disabled && !a.Invited }

// accountSummary is what the Users page shows: never a password, factor or code.
type accountSummary struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	State    string `json:"state"` // active, setup, invited, expired or blocked
}

func summarize(a durableAccount, now time.Time) accountSummary {
	state := "active"
	switch {
	case a.Disabled:
		state = "blocked"
	case a.Seed == "" && len(a.Enrollment) != 0 && now.Unix() >= a.EnrollmentEnd:
		state = "expired" // its invite or setup code can no longer be used
	case a.Invited:
		state = "invited"
	case a.Seed == "":
		state = "setup"
	}
	return accountSummary{a.ID, a.Username, roleWord(a.Role), state}
}

func (s *Store) accounts(tx *bolt.Tx) ([]durableAccount, error) {
	var all []durableAccount
	e := tx.Bucket(accountBucket).ForEach(func(k, _ []byte) error {
		a, e := s.readAccount(tx, string(k))
		if e != nil || len(all) >= 256 {
			return errRefused
		}
		all = append(all, a)
		return nil
	})
	return all, e
}

func (s *Store) listAccounts(now time.Time) ([]accountSummary, error) {
	var list []accountSummary
	e := s.view(func(tx *bolt.Tx) error {
		all, e := s.accounts(tx)
		for _, a := range all {
			list = append(list, summarize(a, now))
		}
		return e
	})
	if e != nil {
		return nil, errRefused
	}
	slices.SortFunc(list, func(a, b accountSummary) int { return strings.Compare(a.Username, b.Username) })
	return list, nil
}

// inviteAccount makes an account whose holder chooses its password: hash is
// of a random secret nobody keeps, and the returned code is the invite. Only
// the code and the password the holder then chooses open it. The actor must
// be an active administrator when it commits.
func (s *Store) inviteAccount(actor, name, role string, hash PasswordHash, now time.Time) (string, string, error) {
	var id, code string
	e := s.updateWhy(func(tx *bolt.Tx) error {
		if by, e := s.readAccount(tx, actor); e != nil || !activeAdmin(by) {
			return errRefused
		}
		if tx.Bucket(nameBucket).Get(s.nameIndex(name)) != nil {
			return errTaken
		}
		a, setup, e := s.createAccount(tx, name, hash, now, newAccount{role: role, setup: true, invited: true})
		id, code = a.ID, setup
		return e
	})
	if e != nil {
		return "", "", e
	}
	return id, code, nil
}

// claimInvite sets the password an invited holder chose, once, with the
// invite code. The code stays the account's setup code until the phone is
// enrolled, so a holder who stops before that can sign in and finish later.
func (s *Store) claimInvite(name, code string, hash PasswordHash, now time.Time) error {
	digest, ok := tokenID(code)
	if !ok || !hash.valid() {
		return errRefused
	}
	return s.update(func(tx *bolt.Tx) error {
		if _, e := s.meta(tx); e != nil {
			return e
		}
		id := tx.Bucket(nameBucket).Get(s.nameIndex(name))
		if id == nil {
			return errRefused
		}
		a, e := s.readAccount(tx, string(id))
		if e != nil || a.Username != name || !a.Invited || a.Disabled || now.Unix() >= a.EnrollmentEnd || subtle.ConstantTimeCompare(digest[:], a.Enrollment) != 1 {
			return errRefused
		}
		a.Hash, a.Invited = storedPassword(hash), false
		a.Revision++
		return s.saveAccount(tx, a)
	})
}

// changeAccount applies one administrator's change to another account in one
// transaction. The actor must be an active administrator, may not change
// themselves here (their own password and factor are on the Account page),
// and the result must leave at least one active administrator.
func (s *Store) changeAccount(actor, target string, change func(*durableAccount) error) error {
	return s.updateWhy(func(tx *bolt.Tx) error {
		if actor == target {
			return errRefused
		}
		by, e := s.readAccount(tx, actor)
		if e != nil || !activeAdmin(by) {
			return errRefused
		}
		a, e := s.readAccount(tx, target)
		if e != nil {
			return errMissing
		}
		if e = change(&a); e != nil {
			return e
		}
		a.Revision++
		if s.saveAccount(tx, a) != nil {
			return errRefused
		}
		return s.anAdminRemains(tx)
	})
}

// deleteAccount removes another account with everything it owns: its keys,
// passwords and connections go with it, in the same transaction.
func (s *Store) deleteAccount(actor, target string) error {
	return s.updateWhy(func(tx *bolt.Tx) error {
		if actor == target {
			return errRefused
		}
		by, e := s.readAccount(tx, actor)
		if e != nil || !activeAdmin(by) {
			return errRefused
		}
		a, e := s.readAccount(tx, target)
		if e != nil {
			return errMissing
		}
		if e = s.deleteOwned(tx, a.ID); e != nil {
			return e
		}
		if e = s.dropAccess(tx, a.ID); e != nil {
			return e
		}
		if tx.Bucket(nameBucket).Delete(s.nameIndex(a.Username)) != nil || tx.Bucket(accountBucket).Delete([]byte(a.ID)) != nil {
			return errRefused
		}
		return s.anAdminRemains(tx)
	})
}

// deleteOwned removes every key, password and connection an account owns,
// and how its pages look.
func (s *Store) deleteOwned(tx *bolt.Tx, owner string) error {
	prefix := []byte(owner + "/")
	for _, name := range [][]byte{credentialBucket, connectionBucket, preferenceBucket} {
		b := tx.Bucket(name)
		if b == nil {
			continue
		}
		var keys [][]byte
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			keys = append(keys, slices.Clone(k))
		}
		for _, k := range keys {
			if b.Delete(k) != nil {
				return errRefused
			}
		}
	}
	return nil
}

func (s *Store) anAdminRemains(tx *bolt.Tx) error {
	all, e := s.accounts(tx)
	if e != nil {
		return errRefused
	}
	if !slices.ContainsFunc(all, activeAdmin) {
		return errLastAdmin
	}
	return nil
}

// adoptSoleAdmin names the only account administrator when there is no
// administrator at all: a copy set up before roles existed, whose one account
// is the person who set it up. A copy with several accounts and no
// administrator names one with `keybash account-recover --admin`. A start
// with nothing to adopt rolls back and writes nothing: a failed upgrade checks
// that the database it put back is the same, byte for byte.
func (s *Store) adoptSoleAdmin() error {
	nothing := errors.New("nothing to adopt")
	e := s.updateWhy(func(tx *bolt.Tx) error {
		if _, e := s.meta(tx); e != nil {
			return e
		}
		all, e := s.accounts(tx)
		if e != nil {
			return e
		}
		if len(all) != 1 || all[0].Role == roleAdmin {
			return nothing
		}
		a := all[0]
		a.Role = roleAdmin
		a.Revision++
		return s.saveAccount(tx, a)
	})
	if e == nothing {
		return nil
	}
	return e
}

// resetAccess clears an account's phone and recovery codes and issues a new
// setup code. The password stays, and the account is not made an invite:
// only its holder, with their own password and that code, can enroll again.
// The administrator who receives the code therefore cannot become the
// account and reach its keys, passwords and connections, which stay. A
// holder who also lost their password needs the operator's offline
// account-recover, or deletion and a new invite. An account still waiting
// for its invite stays one, so the new code is its new invite.
func resetAccess(now time.Time) (func(*durableAccount) error, *string) {
	code := new(string)
	return func(a *durableAccount) error {
		var e error
		a.Seed, a.Recovery, a.LastCounter = "", nil, -1
		a.PasswordReset, a.PasswordResetEnd = nil, 0 // it needed the phone just cleared
		*code, e = issueEnrollment(a, now)
		return e
	}, code
}

// passwordReset gives an account a one-time code for choosing a new password,
// for a holder who forgot theirs but keeps their phone. The password, phone
// and recovery codes stay until the code is used, and it works only with the
// holder's own phone code or a recovery code: the administrator who receives
// it still cannot become the account. An account without a phone, invited or
// blocked has nothing to confirm it with.
func passwordReset(now time.Time) (func(*durableAccount) error, *string) {
	code := new(string)
	return func(a *durableAccount) error {
		if a.Seed == "" || a.Invited || a.Disabled {
			return errNoPhone
		}
		raw, e := token()
		if e != nil {
			return errRefused
		}
		digest, _ := tokenID(raw)
		a.PasswordReset, a.PasswordResetEnd, *code = digest[:], now.Add(enrollmentLife).Unix(), raw
		return nil
	}, code
}

// resetPassword sets the password a holder chose with an administrator's
// reset code and their own factor, once. A wrong name or code is refused
// before the factor is looked at, so nobody without the code can spend the
// holder's factor budget; a wrong factor after a right code spends it, as at
// sign-in. The code is spent, and every session ends, when it succeeds.
func (s *Store) resetPassword(name, code, factor string, hash PasswordHash, now time.Time) error {
	digest, ok := tokenID(code)
	if !ok || !hash.valid() {
		return errRefused
	}
	accepted := false
	e := s.update(func(tx *bolt.Tx) error {
		if _, e := s.meta(tx); e != nil {
			return e
		}
		id := tx.Bucket(nameBucket).Get(s.nameIndex(name))
		if id == nil {
			return errRefused
		}
		a, e := s.readAccount(tx, string(id))
		if e != nil || a.Username != name || a.Invited || a.Disabled || a.Seed == "" || len(a.PasswordReset) != 32 ||
			now.Unix() >= a.PasswordResetEnd || subtle.ConstantTimeCompare(digest[:], a.PasswordReset) != 1 || !factorBudget(&a, now) {
			return errRefused
		}
		if accepted = s.spendFactor(&a, factor, now); accepted {
			a.Hash, a.PasswordReset, a.PasswordResetEnd = storedPassword(hash), nil, 0
			a.Revision++
		}
		return s.saveAccount(tx, a)
	})
	if e != nil || !accepted {
		return errRefused
	}
	return nil
}

// startOverAccount sends an account back to an invite when its holder lost
// both password and phone. Its keys, passwords and connections are deleted in
// the same transaction, so the administrator who receives the new invite code
// never reaches what the account held. Its ID, username and role stay; a
// blocked account stays blocked. hash is of a random secret nobody keeps.
func (s *Store) startOverAccount(actor, target string, hash PasswordHash, now time.Time) (string, error) {
	var code string
	e := s.updateWhy(func(tx *bolt.Tx) error {
		if actor == target {
			return errRefused
		}
		by, e := s.readAccount(tx, actor)
		if e != nil || !activeAdmin(by) {
			return errRefused
		}
		a, e := s.readAccount(tx, target)
		if e != nil {
			return errMissing
		}
		if e = s.deleteOwned(tx, a.ID); e != nil {
			return e
		}
		a.Hash, a.Invited, a.Seed, a.Recovery, a.LastCounter = storedPassword(hash), true, "", nil, -1
		a.PasswordReset, a.PasswordResetEnd = nil, 0
		if code, e = issueEnrollment(&a, now); e != nil {
			return errRefused
		}
		a.Revision++
		if s.saveAccount(tx, a) != nil {
			return errRefused
		}
		return s.anAdminRemains(tx)
	})
	if e != nil {
		return "", e
	}
	return code, nil
}
