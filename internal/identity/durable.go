package identity

import (
	"context"
	"time"
)

// Revealing, deleting or importing secrets, changing trust decisions, the
// password or MFA require both factors proved within this window.
const freshProof = 2 * time.Minute

// NewPersistent keeps the existing HTTPS/Origin/session controls, backed by
// encrypted transactional custody. Password-only sessions are setup/challenge
// sessions; only confirmed MFA can reach credential operations.
func NewPersistent(origin string, store *Store, options ...Option) (*Lab, error) {
	if store == nil {
		return nil, errRefused
	}
	if _, e := store.initialized(); e != nil {
		return nil, errRefused
	}
	dummy, e := token()
	if e != nil {
		return nil, e
	}
	hash, e := HashPassword(dummy)
	if e != nil {
		return nil, e
	}
	l, e := NewLab(origin, []Account{{Username: "internal-dummy", Password: hash}}, options...)
	if e != nil {
		return nil, e
	}
	l.mu.Lock()
	clear(l.accounts)
	l.store = store
	l.mu.Unlock()
	return l, nil
}

func (l *Lab) refreshLocked(name string) bool {
	if l.store == nil {
		return l.accounts[name] != nil
	}
	d, e := l.store.lookup(name)
	a := l.accounts[name]
	changed := e != nil || a != nil && (a.id != d.ID || a.revision != d.Revision)
	if changed {
		for id, s := range l.sessions {
			if s.username == name {
				l.forgetLocked(id)
			}
		}
	}
	if e != nil {
		delete(l.accounts, name)
		return false
	}
	if a == nil {
		a = &account{}
		l.accounts[name] = a
	}
	a.id, a.password, a.revision, a.mfa = d.ID, d.password(), d.Revision, d.Seed != ""
	return true
}
func (l *Lab) readyLocked(id [32]byte, fresh bool) *session {
	s := l.liveLocked(id, false)
	if s == nil || l.store == nil || s.stage != "ready" || s.owner != l.accounts[s.username].id || s.revision != l.accounts[s.username].revision || fresh && !l.now().Before(s.reauthUntil) {
		return nil
	}
	return s
}
func (l *Lab) finishFactorLocked(id [32]byte, code string) (string, error) {
	s := l.liveLocked(id, false)
	if s == nil || s.stage != "challenge" || !l.attemptLocked("mfa:"+s.username, factorAttempts) {
		return "", errRefused
	}
	if l.store.consumeFactor(s.owner, s.revision, code, l.now()) != nil {
		return "", errRefused
	}
	name, passwordProof := s.username, s.created
	l.forgetLocked(id)
	raw, e := l.issueLocked(name, "")
	if e != nil {
		return "", e
	}
	newID, _ := tokenID(raw)
	l.sessions[newID].stage = "ready"
	// Sign-in just proved both factors: it counts as fresh proof until the
	// password check (the challenge session's creation) is freshProof old.
	l.sessions[newID].reauthUntil = passwordProof.Add(freshProof)
	return raw, nil
}
func (l *Lab) confirmEnrollmentLocked(id [32]byte, code string) (string, recoveryCodes, error) {
	s := l.liveLocked(id, false)
	if s == nil || s.stage != "enroll" || s.pendingSeed == "" || !s.replacing && !s.setupProved || s.replacing && !l.now().Before(s.reauthUntil) || !l.attemptLocked("mfa:"+s.username, factorAttempts) {
		return "", nil, errRefused
	}
	name := s.username
	// A first enrollment proved the password when its session was created; a
	// replacement carries the fresh window its reauthentication granted.
	proofUntil := s.created.Add(freshProof)
	if s.replacing {
		proofUntil = s.reauthUntil
	}
	codes, e := l.store.enroll(s.owner, s.revision, s.pendingSeed, code, l.now(), s.replacing)
	if e != nil {
		return "", nil, e
	}
	l.refreshLocked(name) // revokes all old generations, including setup cookies
	raw, e := l.issueLocked(name, "")
	if e != nil {
		return "", nil, e
	}
	newID, _ := tokenID(raw)
	l.sessions[newID].stage = "ready"
	l.sessions[newID].reauthUntil = proofUntil
	return raw, codes, nil
}
func (l *Lab) reauthenticate(ctx context.Context, id [32]byte, password, code string) error {
	l.mu.Lock()
	s := l.readyLocked(id, false)
	if s == nil || !l.attemptLocked("reauth:"+s.username, reauthAttempts) {
		l.mu.Unlock()
		return errRefused
	}
	a := l.accounts[s.username]
	hash, revision := a.password, a.revision
	l.mu.Unlock()
	if !l.slot(ctx) {
		return errLimited
	}
	defer func() { <-l.derive }()
	valid := hash.verify(password)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !valid || l.readyLocked(id, false) != s || a.revision != revision || ctx.Err() != nil {
		return errRefused
	}
	if l.store.consumeFactor(s.owner, revision, code, l.now()) != nil {
		return errRefused
	}
	s.reauthUntil = l.now().Add(freshProof)
	return nil
}
