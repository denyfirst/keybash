package identity

import (
	"net/http"
	"strings"
)

const (
	userAttempts   = 20 // administrator changes per administrator and minute
	inviteAttempts = 5  // invite claims per submitted username and minute
)

// randomPassword is the hash of a secret nobody keeps, for an account whose
// holder has not chosen a password. It costs one Argon2id derivation; callers
// hold a derive slot.
func randomPassword() (PasswordHash, error) {
	secret, e := token()
	if e != nil {
		return PasswordHash{}, errRefused
	}
	return HashPassword(secret)
}

// usersHTTP is the Users page's API, for a ready administrator only. Listing
// needs the ready session; every change also needs a factor proved within
// freshProof, like revealing a secret, and ends the changed account's
// sessions. An administrator cannot change their own account here. Returns
// with l.mu released.
func (l *Lab) usersHTTP(w http.ResponseWriter, r *http.Request, id [32]byte, s *session) {
	if l.roleLocked(s) != roleAdmin {
		l.mu.Unlock()
		refuse(w, 403)
		return
	}
	if r.URL.Path == "/api/users" && r.Method == "GET" {
		list, e := l.store.listAccounts(l.now())
		self := s.owner
		l.mu.Unlock()
		if e != nil {
			refuse(w, 503)
			return
		}
		jsonReply(w, struct {
			Self     string           `json:"self"`
			Accounts []accountSummary `json:"accounts"`
		}{self, list})
		return
	}
	// "/api/users" invites; "/api/users/{id}" and "/api/users/{id}/{action}"
	// change one account.
	var target, action string
	if rest := strings.TrimPrefix(r.URL.Path, "/api/users"); rest != "" {
		parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
		if !strings.HasPrefix(rest, "/") || len(parts) > 2 || !validID(parts[0]) {
			l.mu.Unlock()
			refuse(w, 404)
			return
		}
		target = parts[0]
		if len(parts) == 2 {
			action = parts[1]
		}
	} else if r.Method != "POST" {
		l.mu.Unlock()
		refuse(w, 404)
		return
	}
	if l.readyLocked(id, true) != s {
		l.mu.Unlock()
		refuse(w, http.StatusPreconditionRequired)
		return
	}
	if !l.attemptLocked("users:"+s.username, userAttempts) {
		l.mu.Unlock()
		identityError(w, errLimited)
		return
	}
	actor, now := s.owner, l.now()
	s.last = now
	l.mu.Unlock()
	var e error
	var reply any
	switch {
	case target == "":
		fields, ok := readFields(w, r, 1024, "username", "role")
		role, known := wordRole(fields["role"])
		if !ok || !known || !usernameInput(fields["username"]) {
			refuse(w, 400)
			return
		}
		if !l.slot(r.Context()) {
			identityError(w, errLimited)
			return
		}
		hash, he := randomPassword()
		<-l.derive
		if he != nil {
			refuse(w, 503)
			return
		}
		var made, code string
		if made, code, e = l.store.inviteAccount(actor, fields["username"], role, hash, now); e == nil {
			reply = struct {
				ID   string `json:"id"`
				Code string `json:"code"`
			}{made, code}
		}
	case action == "role" && r.Method == "POST":
		fields, ok := readFields(w, r, 1024, "role")
		role, known := wordRole(fields["role"])
		if !ok || !known {
			refuse(w, 400)
			return
		}
		e = l.store.changeAccount(actor, target, func(a *durableAccount) error { a.Role = role; return nil })
	case (action == "block" || action == "unblock") && r.Method == "POST":
		if _, ok := readFields(w, r, 1024); !ok {
			refuse(w, 400)
			return
		}
		blocked := action == "block"
		e = l.store.changeAccount(actor, target, func(a *durableAccount) error { a.Disabled = blocked; return nil })
	case action == "reset" && r.Method == "POST":
		if _, ok := readFields(w, r, 1024); !ok {
			refuse(w, 400)
			return
		}
		if !l.slot(r.Context()) {
			identityError(w, errLimited)
			return
		}
		hash, he := randomPassword()
		<-l.derive
		if he != nil {
			refuse(w, 503)
			return
		}
		change, code := resetAccess(hash, now)
		if e = l.store.changeAccount(actor, target, change); e == nil {
			reply = struct {
				Code string `json:"code"`
			}{*code}
		}
	case action == "" && r.Method == "DELETE":
		if _, ok := readFields(w, r, 1024); !ok {
			refuse(w, 400)
			return
		}
		e = l.store.deleteAccount(actor, target)
	default:
		refuse(w, 404)
		return
	}
	// The changed account's open sessions and terminals end now, not at their
	// next request.
	l.mu.Lock()
	for _, other := range l.sessions {
		if other.owner == target {
			l.refreshLocked(other.username)
			break
		}
	}
	l.mu.Unlock()
	switch {
	case e == errTaken || e == errLastAdmin:
		refuse(w, 409)
	case e == errMissing:
		refuse(w, 404)
	case e != nil:
		refuse(w, 403)
	case reply != nil:
		jsonReply(w, reply)
	default:
		w.WriteHeader(204)
	}
}

// inviteHTTP lets an invited holder choose their password with the invite
// code, then continues as a first sign-in at phone setup. Every attempt costs
// one Argon2id derivation before the code is checked, so a wrong name and a
// wrong code take the same time, and attempts count per source and per name.
func (l *Lab) inviteHTTP(w http.ResponseWriter, r *http.Request) {
	fields, ok := readFields(w, r, 16*1024, "username", "code", "password")
	if !ok || !usernameInput(fields["username"]) || !passwordInput(fields["password"]) {
		refuse(w, 400)
		return
	}
	defer clear(fields)
	if !l.slot(r.Context()) {
		identityError(w, errLimited)
		return
	}
	defer func() { <-l.derive }()
	source := l.source(r)
	l.mu.Lock()
	allowed := !l.closed && (source == "" || l.attemptLocked("source:"+source, sourceAttempts)) && l.attemptLocked("invite:"+fields["username"], inviteAttempts)
	l.mu.Unlock()
	if !allowed {
		identityError(w, errLimited)
		return
	}
	hash, e := HashPassword(fields["password"])
	if e != nil {
		refuse(w, 400)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || r.Context().Err() != nil || l.store.claimInvite(fields["username"], fields["code"], hash, l.now()) != nil {
		refuse(w, 401)
		return
	}
	if !l.refreshLocked(fields["username"]) {
		refuse(w, 503)
		return
	}
	raw, e := l.issueLocked(fields["username"], requestToken(r))
	if e != nil {
		identityError(w, e)
		return
	}
	// The invite is the administrator's setup code, just proved.
	newID, _ := tokenID(raw)
	l.sessions[newID].setupProved = true
	http.SetCookie(w, sessionCookie(raw, int(absoluteLife.Seconds())))
	w.WriteHeader(204)
}
