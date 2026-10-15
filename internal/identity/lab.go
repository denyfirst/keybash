package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const cookieName = "__Host-keybash-session"
const idleLife = 15 * time.Minute
const absoluteLife = 8 * time.Hour

// Account is supplied by trusted local setup. There is no public registration,
// default password or existing-product credential import in the memory lab.
type Account struct {
	Username string
	Password PasswordHash
}
type account struct {
	password PasswordHash
	revision uint64
	disabled bool
	id       string
	mfa      bool
}
type window struct {
	start time.Time
	count int
}

func (w *window) allow(now time.Time, limit int) bool {
	if w.start.IsZero() || now.Sub(w.start) >= time.Minute {
		w.start, w.count = now, 0
	}
	if w.count >= limit {
		return false
	}
	w.count++
	return true
}

type session struct {
	username      string
	created, last time.Time
	ctx           context.Context
	cancel        context.CancelFunc
	owner         string
	revision      uint64
	stage         string
	challengeEnd  time.Time
	pendingSeed   string
	replacing     bool
	reauthUntil   time.Time
}

// Lab is a single-process, loopback HTTPS identity boundary. NewLab is memory-
// only; NewPersistent enables mandatory MFA and encrypted credential custody.
// Sessions remain memory-only. Neither constructor authorizes a native worker.
type Lab struct {
	origin, host string
	mu           sync.Mutex
	accounts     map[string]*account
	dummy        PasswordHash
	sessions     map[[32]byte]*session
	csrfKey      [32]byte
	global       window
	attempts     map[string]int // at most 20 names per global window, known or unknown
	derive       chan struct{}
	now          func() time.Time
	closed       bool
	stop, done   chan struct{}
	store        *Store
	remote       *remoteConfig
}

func usernameInput(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func NewLab(origin string, accounts []Account) (*Lab, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != origin {
		return nil, errRefused
	}
	host, port, err := net.SplitHostPort(u.Host)
	ip, ipErr := netip.ParseAddr(host)
	portNum, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || ipErr != nil || !ip.IsLoopback() || ip.Zone() != "" || portErr != nil || portNum < 1 || strconv.FormatUint(portNum, 10) != port || len(accounts) == 0 || len(accounts) > 256 {
		return nil, errRefused
	}
	l := &Lab{origin: origin, host: u.Host, accounts: make(map[string]*account), sessions: make(map[[32]byte]*session), attempts: make(map[string]int),
		derive: make(chan struct{}, 2), now: time.Now, stop: make(chan struct{}), done: make(chan struct{})}
	for _, a := range accounts {
		if !usernameInput(a.Username) || !a.Password.valid() || l.accounts[a.Username] != nil {
			return nil, errRefused
		}
		l.accounts[a.Username] = &account{password: a.Password, revision: 1}
	}
	l.dummy = accounts[0].Password // same fixed KDF cost for nonexistent accounts
	if _, err := rand.Read(l.csrfKey[:]); err != nil {
		return nil, errRefused
	}
	go l.expirer()
	return l, nil
}

func (l *Lab) expirer() {
	defer close(l.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.mu.Lock()
			if l.store != nil {
				names := make(map[string]bool)
				for _, s := range l.sessions {
					names[s.username] = true
				}
				for name := range names {
					l.refreshLocked(name)
				}
			}
			l.sweepLocked()
			l.mu.Unlock()
		}
	}
}

func (l *Lab) Close() error {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.stop)
		for id := range l.sessions {
			l.forgetLocked(id)
		}
	}
	l.mu.Unlock()
	<-l.done
	return nil
}

func (l *Lab) forgetLocked(id [32]byte) {
	if s := l.sessions[id]; s != nil {
		s.cancel()
		delete(l.sessions, id)
	}
	l.sweepRemotesLocked()
}
func (l *Lab) sweepLocked() {
	now := l.now()
	for id, s := range l.sessions {
		if !now.Before(s.last.Add(idleLife)) || !now.Before(s.created.Add(absoluteLife)) || l.store != nil && s.stage != "ready" && !now.Before(s.challengeEnd) {
			l.forgetLocked(id)
		}
	}
	l.sweepRemotesLocked()
}

func token() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errRefused
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
func tokenID(raw string) ([32]byte, bool) {
	if len(raw) != 43 {
		return [32]byte{}, false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(data) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(raw)), true
}
func (l *Lab) csrf(id [32]byte) string {
	h := hmac.New(sha256.New, l.csrfKey[:])
	_, _ = h.Write(id[:])
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func (l *Lab) attemptLocked(username string) bool {
	if l.global.start.IsZero() || l.now().Sub(l.global.start) >= time.Minute {
		clear(l.attempts)
	}
	if !l.global.allow(l.now(), 20) {
		return false
	}
	// Unknown and registered names share the same policy. Separate unknown-user
	// buckets would expose account existence through different 429 responses.
	if l.attempts[username] >= 5 {
		return false
	}
	l.attempts[username]++
	return true
}
func (l *Lab) slot(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case l.derive <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *Lab) login(ctx context.Context, username, password, previous string) (string, error) {
	l.mu.Lock()
	if l.closed || !l.attemptLocked(username) {
		l.mu.Unlock()
		return "", errLimited
	}
	if l.store != nil {
		l.refreshLocked(username)
	}
	a := l.accounts[username]
	hash, revision := l.dummy, uint64(0)
	if a != nil {
		hash, revision = a.password, a.revision
	}
	oldID, oldValid := tokenID(previous)
	oldSession := l.sessions[oldID]
	l.mu.Unlock()
	if !l.slot(ctx) {
		return "", errLimited
	}
	defer func() { <-l.derive }()
	valid := hash.verify(password)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.store != nil {
		l.refreshLocked(username)
	}
	if !valid || a == nil || a.disabled || a.revision != revision || l.closed || ctx.Err() != nil ||
		oldValid && oldSession != nil && l.sessions[oldID] != oldSession {
		return "", errRefused
	}
	return l.issueLocked(username, previous)
}

func (l *Lab) issueLocked(username, previous string) (string, error) {
	l.sweepLocked()
	a := l.accounts[username]
	if a == nil || a.disabled || l.closed {
		return "", errRefused
	}
	oldID, oldValid := tokenID(previous)
	count := 0
	for _, s := range l.sessions {
		if s.username == username {
			count++
		}
	}
	total := len(l.sessions)
	if oldValid && l.sessions[oldID] != nil {
		total--
		if l.sessions[oldID].username == username {
			count--
		}
	}
	if total >= 128 || count >= 8 {
		return "", errLimited // no silent eviction of another browser's session
	}
	raw, err := token()
	if err != nil {
		return "", errRefused
	}
	id, _ := tokenID(raw)
	if l.sessions[id] != nil {
		return "", errRefused
	}
	if oldValid {
		l.forgetLocked(oldID)
	}
	c, cancel := context.WithCancel(context.Background())
	s := &session{username: username, created: l.now(), last: l.now(), ctx: c, cancel: cancel, owner: a.id, revision: a.revision}
	if l.store != nil {
		s.stage = "enroll"
		if a.mfa {
			s.stage = "challenge"
		}
		s.challengeEnd = l.now().Add(5 * time.Minute)
	}
	l.sessions[id] = s
	return raw, nil
}

func (l *Lab) change(ctx context.Context, id [32]byte, current, replacement string) error {
	if !passwordInput(replacement) || current == replacement {
		return errRefused
	}
	l.mu.Lock()
	s := l.liveLocked(id, false)
	if s == nil || l.store != nil && l.readyLocked(id, true) != s {
		l.mu.Unlock()
		return errRefused
	}
	a := l.accounts[s.username]
	if !l.attemptLocked(s.username) {
		l.mu.Unlock()
		return errLimited
	}
	hash, revision := a.password, a.revision
	l.mu.Unlock()
	if !l.slot(ctx) {
		return errLimited
	}
	defer func() { <-l.derive }()
	if !hash.verify(current) {
		return errRefused
	}
	next, err := HashPassword(replacement)
	if err != nil {
		return errRefused
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.liveLocked(id, false) != s || a.revision != revision || ctx.Err() != nil || l.store != nil && l.readyLocked(id, true) != s {
		return errRefused
	}
	if l.store != nil {
		if l.store.replacePassword(a.id, revision, next) != nil {
			return errRefused
		}
		l.refreshLocked(s.username)
		return nil
	}
	a.password, a.revision = next, a.revision+1
	for key, active := range l.sessions {
		if active.username == s.username {
			l.forgetLocked(key)
		}
	}
	return nil
}

func (l *Lab) liveLocked(id [32]byte, touch bool) *session {
	l.sweepLocked()
	s := l.sessions[id]
	if l.store != nil && s != nil {
		l.refreshLocked(s.username)
		s = l.sessions[id]
	}
	if l.closed || s == nil || l.accounts[s.username].disabled {
		return nil
	}
	if touch {
		s.last = l.now()
	}
	return s
}
