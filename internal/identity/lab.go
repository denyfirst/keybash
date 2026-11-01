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
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/denyfirst/keybash/internal/ingress"
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
	role     string
	invited  bool // no password chosen yet: only the invite opens it
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
	setupProved   bool // bootstrap or operator setup code shown for first enrollment
	reauthUntil   time.Time
	stepFailures  int // wrong step-up codes in this session; see stepUpFailures
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
	attempts     map[string]*window // purpose:account keys; see attemptLocked
	derive       chan struct{}
	now          func() time.Time
	closed       bool
	stop, done   chan struct{}
	store        *Store
	remote       *remoteConfig
	sources      []netip.Prefix // nil: loopback clients only
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

// Option sets how a lab is reached. Without one, it serves loopback clients at
// a loopback origin only.
type Option func(*Lab) error

// FromSources admits clients from these networks only, at a non-loopback
// origin: a numeric global-unicast address or a DNS name the operator's TLS
// certificate covers. Pre-authentication login attempts then also count per
// source. A loopback origin refuses it.
func FromSources(sources []netip.Prefix) Option {
	return func(l *Lab) error {
		if len(sources) == 0 || len(sources) > ingress.MaxSources || l.sources != nil {
			return errRefused
		}
		for _, prefix := range sources {
			if !prefix.IsValid() || prefix.Masked() != prefix || prefix.Bits() == 0 {
				return errRefused
			}
		}
		l.sources = slices.Clone(sources)
		return nil
	}
}

// originHost checks an exact https origin and returns its host:port. A
// loopback origin is numeric. An exposed one is a numeric global-unicast
// address or a canonical DNS name that no URL parser would read as an IPv4
// address, never localhost.
func originHost(origin string, exposed bool) (string, bool) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != origin {
		return "", false
	}
	host, port, err := net.SplitHostPort(u.Host)
	portNum, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || portNum < 1 || strconv.FormatUint(portNum, 10) != port {
		return "", false
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" || ip.String() != host || ip.Is4In6() || ip.IsLoopback() == exposed || exposed && !ip.IsGlobalUnicast() {
			return "", false
		}
		return u.Host, true
	}
	if !exposed || !ingress.Name(host) {
		return "", false
	}
	return u.Host, true
}

func NewLab(origin string, accounts []Account, options ...Option) (*Lab, error) {
	l := &Lab{origin: origin, accounts: make(map[string]*account), sessions: make(map[[32]byte]*session), attempts: make(map[string]*window),
		derive: make(chan struct{}, 2), now: time.Now, stop: make(chan struct{}), done: make(chan struct{})}
	for _, option := range options {
		if option == nil || option(l) != nil {
			return nil, errRefused
		}
	}
	host, ok := originHost(origin, l.sources != nil)
	if !ok || len(accounts) == 0 || len(accounts) > 256 {
		return nil, errRefused
	}
	l.host = host
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
	for key, w := range l.attempts {
		if now.Sub(w.start) >= time.Minute {
			delete(l.attempts, key)
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

// Per-minute attempt budgets. Each key is one purpose for one account; there
// is deliberately no window shared across accounts or purposes, so one caller
// exhausting a key cannot lock every user out of login, MFA or their own open
// sessions. Argon2id CPU stays bounded separately by the two derive slots.
const (
	loginAttempts    = 5  // per submitted username, registered or not (on an exposed lab, per source)
	factorAttempts   = 5  // per account; the store keeps its own durable budget
	reauthAttempts   = 5  // per account, separate from unauthenticated login
	passwordAttempts = 5  // per account
	importAttempts   = 5  // per account
	trustAttempts    = 5  // per account
	remoteAttempts   = 20 // connection opens per account
	setupAttempts    = 5  // the single pre-initialization bootstrap
	// Per submitted username on an exposed lab, across all sources. The name
	// is otherwise counted per source, so one source cannot keep its holder
	// from signing in elsewhere; this ceiling keeps many sources slow too.
	loginNameAttempts = 30
	// Per client source (an IPv4 address or IPv6 /64) on an exposed lab, across
	// every name it tries; loopback labs have one shared source and skip it.
	sourceAttempts = 30
	// Only login and invite claims create attacker-chosen keys, and only after
	// taking a derive slot, so creation is bounded by KDF throughput far below
	// this ceiling.
	maxAttemptKeys = 8192
)

func (l *Lab) attemptLocked(key string, limit int) bool {
	now := l.now()
	w := l.attempts[key]
	if w == nil {
		if len(l.attempts) >= maxAttemptKeys {
			return false // refuse rather than evict another account's counter
		}
		w = &window{}
		l.attempts[key] = w
	}
	return w.allow(now, limit)
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
	return l.loginFrom(ctx, "", username, password, previous)
}

// loginFrom counts the attempt against its source first, when there is one, so
// a refused source creates no per-name state.
func (l *Lab) loginFrom(ctx context.Context, source, username, password, previous string) (string, error) {
	// Take a derive slot before recording the attempt: refused-for-capacity
	// requests then create no per-name state, so attacker-chosen names can
	// only be added at Argon2id speed.
	if !l.slot(ctx) {
		return "", errLimited
	}
	defer func() { <-l.derive }()
	l.mu.Lock()
	// Unknown and registered names share the same policy. Separate unknown-user
	// buckets would expose account existence through different 429 responses.
	// On an exposed lab the source is checked first, so a refused source
	// creates no per-name counter; then the name from this source; then the
	// name across all sources.
	allowed := !l.closed
	if allowed && source != "" {
		allowed = l.attemptLocked("source:"+source, sourceAttempts) &&
			l.attemptLocked("login:"+username+"@"+source, loginAttempts) &&
			l.attemptLocked("login:"+username, loginNameAttempts)
	} else if allowed {
		allowed = l.attemptLocked("login:"+username, loginAttempts)
	}
	if !allowed {
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
	valid := hash.verify(password)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.store != nil {
		l.refreshLocked(username)
	}
	if !valid || a == nil || a.disabled || a.invited || a.revision != revision || l.closed || ctx.Err() != nil ||
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
	if !l.attemptLocked("password:"+s.username, passwordAttempts) {
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
