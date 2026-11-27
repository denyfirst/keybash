package identity

import (
	"slices"
	"strings"
)

// accountInfo is what the gateway keeps of an account between changes, to
// decide who may use it: never its secret. It is rebuilt from the store with
// the servers (reloadServersLocked).
type accountInfo struct {
	server, name, protocol string // the server's ID, name and protocol
	system                 string // the mark its cards show
	files                  string // what the server allows of file transfer, "" when off
	username, kind         string
	people                 map[string]bool
}

// kindFits says whether a server of this protocol takes a secret of this
// kind: SSH a key or a password, a desktop a password.
func kindFits(protocol, kind string) bool {
	return protocol == "ssh" && (kind == "ssh-key" || kind == "password") || protocol == "rdp" && kind == "password"
}

// SSH accepts a key or a password; RDP a password. There is no fallback from
// one to the other: the account's secret is the only one tried.
func compatible(t RemoteTarget, c Credential) bool {
	return c.Username != "" && kindFits(t.Protocol, c.Kind)
}

// mayUseLocked is the server owner reaches through account: a reachable server
// whose account lists owner. Administrators manage every server but connect
// only through accounts that list them.
func (l *Lab) mayUseLocked(owner, account string) (RemoteTarget, bool) {
	info, ok := l.remote.accounts[account]
	if !ok || !info.people[owner] {
		return RemoteTarget{}, false
	}
	t, ok := l.remote.targets[info.server]
	return t, ok
}

// accountLocked is the server and the account, when s's person may connect
// through it now: listed on it, the server usable, and a secret its protocol
// takes. The account is read again from the store, which must list them too.
func (l *Lab) accountLocked(s *session, account string) (RemoteTarget, serverAccount, bool) {
	if !l.serversLocked(s) || !validID(account) {
		return RemoteTarget{}, serverAccount{}, false
	}
	t, ok := l.mayUseLocked(s.owner, account)
	if !ok || !usableTarget(t, l.now()) {
		return RemoteTarget{}, serverAccount{}, false
	}
	a, e := l.store.readServerAccount(t.ID, account)
	if _, listed := slices.BinarySearch(a.People, s.owner); e != nil || !listed || !compatible(t, a.Current) {
		return RemoteTarget{}, serverAccount{}, false
	}
	return t, a, true
}

// Opening an account needs a ready MFA session, not a fresh password and new
// code each time: sign-in already proved both factors, and the one-use
// 30-second lease stays bound to this session and person, the account's
// generation and the server's approval. redeemRemoteLocked checks them all
// again.
func (l *Lab) grantRemoteLocked(id [32]byte, account string) (string, error) {
	s := l.readyLocked(id, false)
	if s == nil || l.remote == nil || !l.serversLocked(s) || !validID(account) {
		return "", errRefused
	}
	if !l.attemptLocked("remote:"+s.username, remoteAttempts) {
		return "", errLimited
	}
	l.sweepRemotesLocked()
	t, a, ok := l.accountLocked(s, account)
	if !ok {
		return "", errRefused
	}
	return l.issueLeaseLocked(s, &remoteLease{session: id, owner: s.owner, account: account, target: t.ID, approval: approvalFingerprint(t), generation: a.Generation})
}

// accessRow is one card on a person's own page: a server they reach, the
// account they sign in as, and nothing of its secret.
type accessRow struct {
	Account  string `json:"account"`
	Server   string `json:"server"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Username string `json:"username"`
	// Trust is what the card says: "verified" (ready), "stopped" (a desktop
	// shows another certificate than its pin, so nothing is sent until an
	// administrator checks it) or "unavailable".
	Trust string `json:"trust"`
	// Unchecked: an administrator pinned this desktop's certificate without
	// comparing it on the server's own screen.
	Unchecked bool `json:"unchecked,omitempty"`
	// Files is what the server allows of file transfer: "download" or
	// "both", and absent when off (ADR 0011).
	Files string `json:"files,omitempty"`
	// System is the mark the server's card shows, chosen by an administrator.
	System string `json:"system,omitempty"`
}

// accessLocked lists them for s's person: every account that lists them.
func (l *Lab) accessLocked(s *session) []accessRow {
	rows := make([]accessRow, 0)
	if !l.serversLocked(s) {
		return rows
	}
	for account, info := range l.remote.accounts {
		if !info.people[s.owner] {
			continue
		}
		trust := "unavailable"
		if t, ok := l.remote.targets[info.server]; ok && usableTarget(t, l.now()) && kindFits(t.Protocol, info.kind) {
			trust = "verified"
			if l.certificateChangedLocked(t) {
				trust = "stopped"
			}
		}
		rows = append(rows, accessRow{Account: account, Server: info.server, Name: info.name, Protocol: info.protocol, Username: info.username, Trust: trust, Unchecked: l.remote.unchecked[info.server], System: info.system, Files: string(l.filesModeLocked(account))})
	}
	slices.SortFunc(rows, func(a, b accessRow) int {
		for _, order := range []int{strings.Compare(a.Name, b.Name), strings.Compare(a.Server, b.Server), strings.Compare(strings.ToLower(a.Username), strings.ToLower(b.Username))} {
			if order != 0 {
				return order
			}
		}
		return strings.Compare(a.Account, b.Account)
	})
	return rows
}
