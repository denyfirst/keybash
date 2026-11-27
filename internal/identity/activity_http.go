package identity

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// activityGroups are what the Activity page filters by: plain groups of the
// record's kinds.
var activityGroups = map[string][]string{
	"sign-ins": {"first-admin", "signed-in", "sign-in-refused", "confirmed", "confirm-refused", "signed-out", "invite-taken", "reset-taken"},
	"accounts": {"phone-set", "phone-replaced", "password-changed", "recovery-renewed"},
	"people":   {"person-invited", "role-changed", "person-blocked", "person-unblocked", "phone-reset", "password-reset", "person-restarted", "person-deleted"},
	"servers": {"server-added", "server-renamed", "server-picture", "server-files", "server-identity", "server-removed",
		"account-added", "account-person-added", "account-person-removed", "account-password", "account-key-made", "account-key-dropped", "account-key-switched", "account-key-used", "account-removed"},
	"sessions": {"session-started", "session-ended"},
	"files":    {"file-downloaded", "file-uploaded", "file-replaced", "folder-made", "renamed", "file-deleted", "folder-deleted"},
	"console":  {"console-account-added", "console-account-recovered", "console-setup-code", "restored", "record-trimmed"},
}

// The whole chain is checked when Keybash starts and, when the Activity page
// asks, at most this often: walking it reads every block.
const activityRecheck = 10 * time.Minute

type activityName struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type activityPage struct {
	Entries []activityEntry `json:"entries"`
	More    string          `json:"more"` // the number to ask before for older entries; "" when none
	Broken  bool            `json:"broken"`
	At      string          `json:"at,omitempty"` // where the chain stopped following, when broken
	People  []activityName  `json:"people"`
	Servers []activityName  `json:"servers"`
}

// checkedActivityLocked is the chain's state, walked again when the last
// walk is older than activityRecheck.
func (l *Lab) checkedActivityLocked() activityCheck {
	if l.activityChecked.IsZero() || l.now().Sub(l.activityChecked) >= activityRecheck {
		var check activityCheck
		if l.store.view(func(tx *bolt.Tx) error { check = l.store.checkActivity(tx); return nil }) != nil {
			check = activityCheck{Broken: true}
		}
		l.activity, l.activityChecked = check, l.now()
	}
	return l.activity
}

// activityHTTP answers POST /api/activity: a page of the record, newest
// first, for administrators and auditors. Nobody can change the record here
// or anywhere else in the API. Returns with l.mu released.
func (l *Lab) activityHTTP(w http.ResponseWriter, r *http.Request, s *session) {
	if role := l.roleLocked(s); role != roleAdmin && role != roleAuditor || r.Method != "POST" || l.store == nil {
		l.mu.Unlock()
		refuse(w, 403)
		return
	}
	if !l.attemptLocked("activity:"+s.username, 120) {
		l.mu.Unlock()
		identityError(w, errLimited)
		return
	}
	check := l.checkedActivityLocked()
	l.mu.Unlock()
	fields, ok := readFields(w, r, 1024, "before", "person", "server", "what", "from", "to")
	if !ok {
		refuse(w, 400)
		return
	}
	var filter activityFilter
	number := func(name string) (uint64, bool) {
		if fields[name] == "" {
			return 0, true
		}
		n, e := strconv.ParseUint(fields[name], 10, 63)
		return n, e == nil && n > 0
	}
	before, okBefore := number("before")
	from, okFrom := number("from")
	to, okTo := number("to")
	filter.From, filter.To = int64(from), int64(to) // #nosec G115 -- parsed within 63 bits
	if !okBefore || !okFrom || !okTo || fields["person"] != "" && !validID(fields["person"]) || fields["server"] != "" && !validID(fields["server"]) {
		refuse(w, 400)
		return
	}
	filter.Person, filter.Server = fields["person"], fields["server"]
	if what := fields["what"]; what != "" {
		kinds, known := activityGroups[what]
		if !known {
			refuse(w, 400)
			return
		}
		filter.Kinds = map[string]bool{}
		for _, kind := range kinds {
			filter.Kinds[kind] = true
		}
	}
	entries, more, e := l.store.readActivity(before, 50, filter)
	if e != nil {
		refuse(w, 503)
		return
	}
	page := activityPage{Entries: entries, Broken: check.Broken, People: []activityName{}, Servers: []activityName{}}
	if page.Entries == nil {
		page.Entries = []activityEntry{}
	}
	if more != 0 {
		page.More = strconv.FormatUint(more, 10)
	}
	if check.Broken && check.At != 0 {
		page.At = strconv.FormatUint(check.At, 10)
	}
	// The filters list everyone and every server there is now.
	if accounts, e := l.store.listAccounts(l.now()); e == nil {
		for _, a := range accounts {
			page.People = append(page.People, activityName{a.ID, a.Username})
		}
	}
	if servers, e := l.store.listServers(); e == nil {
		for _, server := range servers {
			if !server.Removed {
				page.Servers = append(page.Servers, activityName{server.ID, server.Name})
			}
		}
	}
	byName := func(a, b activityName) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) }
	slices.SortFunc(page.People, byName)
	slices.SortFunc(page.Servers, byName)
	jsonReply(w, page)
}
