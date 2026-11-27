package identity

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

// Refused sign-ins are recorded in groups (ADR 0012): the first refusal for
// an account (or for names that are no account), from one address, at one
// step, is written at once; the rest of its ten minutes become one entry with
// their count when the ten minutes end. Someone who cannot sign in can then
// write at most two entries per address and account every ten minutes, and
// cannot push the record's history out.
const (
	refusalWindow  = 10 * time.Minute
	maxRefusalKeys = 4096
)

type refusalKey struct{ owner, source, step string }

type refusalCount struct {
	since time.Time
	count int // refusals since the first, not yet written
}

// refusedLocked counts one refused sign-in. owner is the account's ID, or
// empty for a name that is no account: that name is never written.
func (l *Lab) refusedLocked(owner, source, step string) {
	if l.store == nil {
		return
	}
	key := refusalKey{owner, source, step}
	if c := l.refusals[key]; c != nil {
		c.count++
		return
	}
	// Past the bound, new groups fold into one with no address or account,
	// so memory stays bounded and nothing goes uncounted.
	if len(l.refusals) >= maxRefusalKeys {
		key = refusalKey{step: step}
		if c := l.refusals[key]; c != nil {
			c.count++
			return
		}
	}
	now := l.now()
	l.refusals[key] = &refusalCount{since: now}
	_ = l.store.record(now, refusalEntry(key, 1, now))
}

func refusalEntry(key refusalKey, count int, now time.Time) activityEntry {
	return activityEntry{Time: now.Unix(), Kind: "sign-in-refused", Actor: key.owner, Source: key.source,
		Detail: map[string]string{"count": strconv.Itoa(count), "step": key.step}}
}

// flushRefusalsLocked writes every group whose ten minutes are over, or every
// group at all when the gateway stops.
func (l *Lab) flushRefusalsLocked(all bool) {
	if l.store == nil {
		return
	}
	now := l.now()
	for key, c := range l.refusals {
		if !all && now.Sub(c.since) < refusalWindow {
			continue
		}
		if c.count > 0 {
			_ = l.store.record(now, refusalEntry(key, c.count, now))
		}
		delete(l.refusals, key)
	}
}

// endedLocked records that a sign-in ended, and why: only a full sign-in,
// since one that never passed its second factor was never in.
func (l *Lab) endedLocked(s *session, cause error) {
	if l.store == nil || s == nil || s.stage != "ready" {
		return
	}
	why := "signed-out"
	switch cause {
	case terminalweb.ReasonIdle:
		why = "idle"
	case terminalweb.ReasonExpired:
		why = "expired"
	case nil:
		return // the gateway is stopping
	}
	e := l.noteLocked(s, "signed-out")
	e.Detail = map[string]string{"why": why}
	_ = l.store.record(l.now(), e)
}

// serverNoteLocked starts an entry about a server, and one of its accounts
// when account is given; IDs that are not IDs are left out.
func (l *Lab) serverNoteLocked(s *session, kind, server, account string) activityEntry {
	e := l.noteLocked(s, kind)
	if validID(server) {
		e.Server = server
		if validID(account) {
			e.Account = account
		}
	}
	return e
}

// personNoteLocked starts an entry about another person.
func (l *Lab) personNoteLocked(s *session, kind, person string) activityEntry {
	e := l.noteLocked(s, kind)
	if validID(person) {
		e.Person = person
	}
	return e
}

// keyUsedNote records that a key made here opened its first session: the
// server took it, so its line is on the server.
func (l *Lab) keyUsedNote(owner, server, account string) activityEntry {
	return activityEntry{Time: l.now().Unix(), Kind: "account-key-used", Actor: owner, Server: server, Account: account}
}

// sessionRecord is a session's start, kept to write its end.
type sessionRecord struct {
	entry activityEntry
	at    time.Time
}

// sessionStarted records a terminal, desktop or Files session before anything
// opens. A session whose entry cannot be written does not start.
func (l *Lab) sessionStarted(lease *remoteLease, session string) (sessionRecord, bool) {
	l.mu.Lock()
	source := ""
	if s := l.sessions[lease.session]; s != nil {
		source = s.source
	}
	now := l.now()
	l.mu.Unlock()
	e := activityEntry{Time: now.Unix(), Kind: "session-started", Actor: lease.owner, Server: lease.target, Account: lease.account, Source: source,
		Detail: map[string]string{"session": session}}
	if lease.files != "" {
		e.Detail["mode"] = string(lease.files)
	}
	if l.store == nil || l.store.record(now, e) != nil {
		return sessionRecord{}, false
	}
	return sessionRecord{entry: e, at: now}, true
}

// sessionEnded records how long a session lasted and why it ended: why when
// the caller knows it, else the cause its context ended with, else "closed"
// (the page or the remote side closed it).
func (l *Lab) sessionEnded(ctx context.Context, started sessionRecord, why string) {
	if l.store == nil || started.entry.Kind == "" {
		return
	}
	if why == "" {
		var cause terminalweb.Reason
		why = "closed"
		if errors.As(context.Cause(ctx), &cause) && cause != "" {
			why = string(cause)
		}
	}
	now := l.now()
	e := started.entry
	e.Time, e.Kind = now.Unix(), "session-ended"
	e.Detail = map[string]string{"session": started.entry.Detail["session"], "seconds": strconv.FormatInt(max(0, int64(now.Sub(started.at).Seconds())), 10), "why": why}
	_ = l.store.record(now, e)
}

var fileKinds = map[terminalweb.FileOp]string{
	terminalweb.OpGet: "file-downloaded", terminalweb.OpPut: "file-uploaded", terminalweb.OpReplace: "file-replaced",
	terminalweb.OpMkdir: "folder-made", terminalweb.OpRename: "renamed", terminalweb.OpRemove: "file-deleted", terminalweb.OpRmdir: "folder-deleted",
}

// fileRecorded records one Files operation's outcome, in its session's name.
func (l *Lab) fileRecorded(started sessionRecord, r terminalweb.FileRequest, failure terminalweb.FileFailure, size uint64) error {
	kind, known := fileKinds[r.Op]
	if !known || l.store == nil {
		return nil
	}
	now := l.now()
	e := started.entry
	e.Time, e.Kind = now.Unix(), kind
	outcome := "done"
	if failure != "" {
		outcome = string(failure)
	}
	e.Detail = map[string]string{"path": r.Path, "outcome": outcome}
	if r.Op == terminalweb.OpRename {
		e.Detail["to"] = r.To
	}
	if failure == "" && (r.Op == terminalweb.OpGet || r.Op == terminalweb.OpPut || r.Op == terminalweb.OpReplace) {
		e.Detail["size"] = strconv.FormatUint(size, 10)
	}
	return l.store.record(now, e)
}
