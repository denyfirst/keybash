package identity

import (
	"context"
	"time"
)

// NewPersistent keeps the existing HTTPS/Origin/session controls, backed by
// encrypted transactional custody. Password-only sessions are setup/challenge
// sessions; only confirmed MFA can reach credential operations.
func NewPersistent(origin string, store *Store) (*Lab, error) {
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
	l, e := NewLab(origin, []Account{{Username: "internal-dummy", Password: hash}})
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
	if s == nil || s.stage != "challenge" || !l.attemptLocked("mfa:"+s.username) {
		return "", errRefused
	}
	if l.store.consumeFactor(s.owner, s.revision, code, l.now()) != nil {
		return "", errRefused
	}
	name := s.username
	l.forgetLocked(id)
	raw, e := l.issueLocked(name, "")
	if e != nil {
		return "", e
	}
	newID, _ := tokenID(raw)
	l.sessions[newID].stage = "ready"
	return raw, nil
}
func (l *Lab) confirmEnrollmentLocked(id [32]byte, code string) (string, recoveryCodes, error) {
	s := l.liveLocked(id, false)
	if s == nil || s.stage != "enroll" || s.pendingSeed == "" || s.replacing && !l.now().Before(s.reauthUntil) || !l.attemptLocked("mfa:"+s.username) {
		return "", nil, errRefused
	}
	name := s.username
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
	return raw, codes, nil
}
func (l *Lab) reauthenticate(ctx context.Context, id [32]byte, password, code string) error {
	l.mu.Lock()
	s := l.readyLocked(id, false)
	if s == nil || !l.attemptLocked(s.username) {
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
	s.reauthUntil = l.now().Add(2 * time.Minute)
	return nil
}
