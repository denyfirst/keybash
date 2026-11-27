package identity

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
)

// The activity record (ADR 0012): who did what, where and when. Entries go
// into sealed blocks of the activity namespace, each entry chained to the one
// before it by an HMAC keyed for this alone. The head of the chain lives in
// the store's authenticated metadata. An entry is written in the same
// transaction as the change it records.
var activityBucket = []byte("activity-v1")

const (
	// activityBlockBytes bounds one block's entries before sealing; a block
	// of entries stays well under the 96 KiB a sealed record may hold.
	activityBlockBytes = 32 * 1024
	// activityKeep is how long entries stay.
	activityKeep = 366 * 24 * time.Hour
	// activityEntryBytes bounds one entry; a path is the longest part.
	activityEntryBytes = 6 * 1024
)

// activityMaxBlocks keeps the record at most 32 MiB of entries, about 90,000,
// so that sealed (about a third larger) it still fits a backup beside
// everything else. Only tests lower it.
var activityMaxBlocks uint64 = 1024

// activityEntry is one line of the record. Every word in Kind and Detail is
// one of a fixed set (activityKinds); names are copied in when the entry is
// written, so a later rename or removal keeps its meaning.
type activityEntry struct {
	Seq         uint64            `json:"seq"`
	Time        int64             `json:"time"`
	Kind        string            `json:"kind"`
	Actor       string            `json:"actor,omitempty"`
	ActorName   string            `json:"actor_name,omitempty"`
	Source      string            `json:"source,omitempty"`
	Person      string            `json:"person,omitempty"`
	PersonName  string            `json:"person_name,omitempty"`
	Server      string            `json:"server,omitempty"`
	ServerName  string            `json:"server_name,omitempty"`
	Account     string            `json:"account,omitempty"`
	AccountName string            `json:"account_name,omitempty"`
	Detail      map[string]string `json:"detail,omitempty"`
	MAC         []byte            `json:"mac,omitempty"`
}

// activityKinds is every kind of entry and the details it may carry.
var activityKinds = map[string][]string{
	// Signing in, and a person's own account.
	"first-admin":      nil,
	"signed-in":        {"factor"},
	"sign-in-refused":  {"count", "step"},
	"confirmed":        {"factor"},
	"confirm-refused":  nil,
	"signed-out":       {"why"},
	"invite-taken":     nil,
	"reset-taken":      nil,
	"phone-set":        nil,
	"phone-replaced":   nil,
	"password-changed": nil,
	"recovery-renewed": nil,
	// People.
	"person-invited":   {"role"},
	"role-changed":     {"role"},
	"person-blocked":   nil,
	"person-unblocked": nil,
	"phone-reset":      nil,
	"password-reset":   nil,
	"person-restarted": nil,
	"person-deleted":   nil,
	// Servers and their accounts.
	"server-added":           {"protocol", "fingerprint", "address", "unchecked"},
	"server-renamed":         {"to"},
	"server-picture":         {"system"},
	"server-files":           {"files"},
	"server-identity":        {"fingerprint"},
	"server-removed":         nil,
	"account-added":          {"kind"},
	"account-person-added":   nil,
	"account-person-removed": nil,
	"account-password":       nil,
	"account-key-made":       nil,
	"account-key-dropped":    nil,
	"account-key-switched":   nil,
	"account-key-used":       nil,
	"account-removed":        nil,
	// Sessions and files.
	"session-started": {"session", "mode"},
	"session-ended":   {"session", "seconds", "why"},
	"file-downloaded": {"path", "size", "outcome"},
	"file-uploaded":   {"path", "size", "outcome"},
	"file-replaced":   {"path", "size", "outcome"},
	"folder-made":     {"path", "outcome"},
	"renamed":         {"path", "to", "outcome"},
	"file-deleted":    {"path", "outcome"},
	"folder-deleted":  {"path", "outcome"},
	// The server's console, and the record itself.
	"console-account-added":     nil,
	"console-account-recovered": {"what"},
	"console-setup-code":        nil,
	"restored":                  nil,
	"record-trimmed":            {"count", "until"},
}

// valid checks an entry's shape before it is chained: a known kind, only its
// own details, IDs and sizes in bounds, and text that is text.
func (e activityEntry) valid() bool {
	allowed, known := activityKinds[e.Kind]
	if !known || e.Time <= 0 || len(e.Detail) > len(allowed) {
		return false
	}
	for _, id := range []string{e.Actor, e.Person, e.Server, e.Account} {
		if id != "" && !validID(id) {
			return false
		}
	}
	for _, text := range []string{e.ActorName, e.PersonName, e.ServerName, e.AccountName} {
		if len(text) > 160 || !utf8.ValidString(text) {
			return false
		}
	}
	if len(e.Source) > 64 || !utf8.ValidString(e.Source) {
		return false
	}
	for key, value := range e.Detail {
		limit := 256
		if key == "path" || key == "to" {
			limit = 4096
		}
		if !contains(allowed, key) || value == "" || len(value) > limit || !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// activityBlock is one sealed block: consecutive entries from First.
type activityBlock struct {
	First   uint64          `json:"first"`
	Entries []activityEntry `json:"entries"`
}

func blockID(n uint64) string  { return fmt.Sprintf("%032x", n) }
func blockKey(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

// chain is the HMAC that ties an entry to everything before it.
func (s *Store) chain(previous []byte, e activityEntry) []byte {
	e.MAC = nil
	data, _ := json.Marshal(e)
	h := hmac.New(sha256.New, s.activityKey[:])
	_, _ = h.Write(previous)
	_, _ = h.Write(binary.BigEndian.AppendUint64(nil, e.Seq))
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func (s *Store) readBlock(b *bolt.Bucket, n uint64) (activityBlock, uint64, error) {
	var block activityBlock
	plain, revision, e := s.unseal("activity", s.instance, blockID(n), b.Get(blockKey(n)))
	if e != nil {
		return block, 0, errRefused
	}
	defer clear(plain)
	if decodeRecord(plain, &block, activityBlockBytes+activityEntryBytes) != nil || len(block.Entries) == 0 {
		return activityBlock{}, 0, errRefused
	}
	return block, revision, nil
}

func (s *Store) writeBlock(tx *bolt.Tx, b *bolt.Bucket, n, revision uint64, block activityBlock) error {
	plain, e := json.Marshal(block)
	if e != nil {
		return errRefused
	}
	sealed, e := s.seal(tx, "activity", s.instance, blockID(n), revision, plain)
	clear(plain)
	if e != nil {
		return e
	}
	return b.Put(blockKey(n), sealed)
}

// appendActivity chains entries onto the record inside tx. Each entry's names
// are filled from its IDs where they are still known; then old blocks leave
// if the record is over its size or age, with an entry that says so.
func (s *Store) appendActivity(tx *bolt.Tx, now time.Time, entries ...activityEntry) error {
	if len(entries) == 0 {
		return nil
	}
	b, e := tx.CreateBucketIfNotExists(activityBucket)
	if e != nil {
		return errRefused
	}
	if e = s.trimActivity(tx, b, now); e != nil {
		return e
	}
	for _, entry := range entries {
		if e = s.chainEntry(tx, b, s.named(tx, entry, now)); e != nil {
			return e
		}
	}
	return nil
}

// named copies in the names an entry's IDs have now, and its time.
func (s *Store) named(tx *bolt.Tx, e activityEntry, now time.Time) activityEntry {
	if e.Time == 0 {
		e.Time = now.Unix()
	}
	if e.Actor != "" && e.ActorName == "" {
		if a, err := s.readAccount(tx, e.Actor); err == nil {
			e.ActorName = a.Username
		}
	}
	if e.Person != "" && e.PersonName == "" {
		if a, err := s.readAccount(tx, e.Person); err == nil {
			e.PersonName = a.Username
		}
	}
	if e.Server != "" && e.ServerName == "" && tx.Bucket(serverBucket) != nil {
		if w, err := s.server(tx, e.Server); err == nil {
			e.ServerName = w.Name
		}
	}
	if e.Server != "" && e.Account != "" && e.AccountName == "" && tx.Bucket(serverAccountBucket) != nil {
		if a, _, err := s.serverAccount(tx, e.Server, e.Account); err == nil {
			e.AccountName = a.Current.Username
		}
	}
	return e
}

func (s *Store) chainEntry(tx *bolt.Tx, b *bolt.Bucket, entry activityEntry) error {
	m, e := s.meta(tx)
	if e != nil {
		return e
	}
	entry.Seq = m.ActivityNext
	if entry.Seq == 0 {
		entry.Seq = 1
	}
	entry.MAC = nil
	if !entry.valid() {
		return errRefused
	}
	entry.MAC = s.chain(m.ActivityMAC, entry)
	size, e := json.Marshal(entry)
	if e != nil || len(size) > activityEntryBytes {
		return errRefused
	}
	// The newest block takes the entry while it has room; otherwise a new
	// block starts. A newest block that does not read is left as it is and a
	// new one starts after it: the check then shows the break, and Keybash
	// stays usable instead of refusing every change, sign-ins included.
	n, revision, block := uint64(1), uint64(1), activityBlock{First: entry.Seq}
	if last, _ := b.Cursor().Last(); last != nil {
		n = binary.BigEndian.Uint64(last)
		current, r, err := s.readBlock(b, n)
		if used, _ := json.Marshal(current); err == nil && len(used)+len(size)+1 <= activityBlockBytes {
			block, revision = current, r+1
		} else {
			n++
		}
	}
	block.Entries = append(block.Entries, entry)
	if e = s.writeBlock(tx, b, n, revision, block); e != nil {
		return e
	}
	// Sealing counted a seal in the metadata; the head moves on that copy.
	if m, e = s.meta(tx); e != nil {
		return e
	}
	if m.ActivityFirst == 0 {
		m.ActivityFirst = entry.Seq
	}
	m.ActivityNext, m.ActivityMAC = entry.Seq+1, entry.MAC
	return s.putMeta(tx, m)
}

// trimActivity removes the oldest whole blocks while the record is over its
// size or holds entries older than it keeps, and records what left.
func (s *Store) trimActivity(tx *bolt.Tx, b *bolt.Bucket, now time.Time) error {
	removed, until := 0, int64(0)
	for {
		first, _ := b.Cursor().First()
		if first == nil {
			break
		}
		last, _ := b.Cursor().Last()
		// Blocks are numbered one after another, so the first and last say how many.
		blocks := binary.BigEndian.Uint64(last) - binary.BigEndian.Uint64(first) + 1
		block, _, e := s.readBlock(b, binary.BigEndian.Uint64(first))
		if e != nil {
			// An oldest block that does not read stays while the record has
			// room, and leaves when it is over its size, so the record never
			// grows past it; the check shows the break either way.
			if blocks <= activityMaxBlocks || bytes.Equal(first, last) {
				break
			}
			if e = b.Delete(first); e != nil {
				return errRefused
			}
			continue
		}
		newest := block.Entries[len(block.Entries)-1]
		if blocks <= activityMaxBlocks && now.Sub(time.Unix(newest.Time, 0)) <= activityKeep {
			break
		}
		// The last block always stays: it holds the head.
		if bytes.Equal(first, last) {
			break
		}
		m, e := s.meta(tx)
		if e != nil {
			return e
		}
		m.ActivityFirst, m.ActivityAnchor = newest.Seq+1, newest.MAC
		if e = s.putMeta(tx, m); e != nil {
			return e
		}
		if e = b.Delete(first); e != nil {
			return errRefused
		}
		removed += len(block.Entries)
		until = newest.Time
	}
	if removed == 0 {
		return nil
	}
	return s.chainEntry(tx, b, activityEntry{Time: now.Unix(), Kind: "record-trimmed", Detail: map[string]string{"count": strconv.Itoa(removed), "until": strconv.FormatInt(until, 10)}})
}

// record writes entries in their own transaction: for what changes nothing
// else in the store (a sign-out, a session's start and end, a file moved).
func (s *Store) record(now time.Time, entries ...activityEntry) error {
	return s.update(func(tx *bolt.Tx) error { return s.appendActivity(tx, now, entries...) })
}

// activityCheck is the result of walking the whole chain.
type activityCheck struct {
	Entries uint64
	Broken  bool
	At      uint64 // the first entry that does not follow, when broken
}

// checkActivity walks the record from where it starts to its head: every
// entry must follow the one before it, every block its predecessor, and the
// last entry must be the head the metadata names.
func (s *Store) checkActivity(tx *bolt.Tx) activityCheck {
	m, e := s.meta(tx)
	if e != nil {
		return activityCheck{Broken: true}
	}
	b := tx.Bucket(activityBucket)
	if b == nil {
		return activityCheck{Broken: m.ActivityNext != 0}
	}
	next, previous := m.ActivityFirst, m.ActivityAnchor
	var count uint64
	c := b.Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		if len(k) != 8 {
			return activityCheck{Entries: count, Broken: true, At: next}
		}
		block, _, err := s.readBlock(b, binary.BigEndian.Uint64(k))
		if err != nil || block.First != next {
			return activityCheck{Entries: count, Broken: true, At: next}
		}
		for _, entry := range block.Entries {
			if entry.Seq != next || !entry.valid() || subtle.ConstantTimeCompare(entry.MAC, s.chain(previous, entry)) != 1 {
				return activityCheck{Entries: count, Broken: true, At: next}
			}
			previous, next = entry.MAC, next+1
			count++
		}
	}
	if (count > 0 || m.ActivityNext != 0) && (next != m.ActivityNext || !hmac.Equal(previous, m.ActivityMAC)) {
		return activityCheck{Entries: count, Broken: true, At: next}
	}
	return activityCheck{Entries: count}
}

// activityFilter narrows a page of the record.
type activityFilter struct {
	Person, Server string
	Kinds          map[string]bool
	From, To       int64 // unix seconds, inclusive; zero for open
}

func (f activityFilter) matches(e activityEntry) bool {
	if f.Person != "" && e.Actor != f.Person && e.Person != f.Person {
		return false
	}
	if f.Server != "" && e.Server != f.Server {
		return false
	}
	if len(f.Kinds) > 0 && !f.Kinds[e.Kind] {
		return false
	}
	return (f.From == 0 || e.Time >= f.From) && (f.To == 0 || e.Time <= f.To)
}

// readActivity returns up to limit entries, newest first, numbered below
// before (zero for the newest), that match the filter, and the number to ask
// before for the next page (zero when there is none).
func (s *Store) readActivity(before uint64, limit int, filter activityFilter) ([]activityEntry, uint64, error) {
	var out []activityEntry
	var more uint64
	e := s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket(activityBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.Last(); k != nil; k, _ = c.Prev() {
			// A block that does not read is passed over: the rest of the
			// record still reads, and the check shows the break.
			block, _, err := s.readBlock(b, binary.BigEndian.Uint64(k))
			if err != nil {
				continue
			}
			for i := len(block.Entries) - 1; i >= 0; i-- {
				entry := block.Entries[i]
				if before != 0 && entry.Seq >= before || !filter.matches(entry) {
					continue
				}
				if len(out) == limit {
					more = out[len(out)-1].Seq
					return nil
				}
				entry.MAC = nil
				out = append(out, entry)
			}
		}
		return nil
	})
	return out, more, e
}

// updateRecorded runs a change and its entries in one transaction: the names
// are taken before the change, so a removal keeps them, the entries are
// chained after it, and both commit or neither does. updateWhyRecorded keeps
// the reason the change refused with.
func (s *Store) updateRecorded(notes []activityEntry, fn func(*bolt.Tx) error) error {
	return s.update(s.recorded(notes, fn))
}

func (s *Store) updateWhyRecorded(notes []activityEntry, fn func(*bolt.Tx) error) error {
	return s.updateWhy(s.recorded(notes, fn))
}

func (s *Store) recorded(notes []activityEntry, fn func(*bolt.Tx) error) func(*bolt.Tx) error {
	if len(notes) == 0 {
		return fn
	}
	now := time.Now()
	if notes[0].Time > 0 {
		now = time.Unix(notes[0].Time, 0)
	}
	return func(tx *bolt.Tx) error {
		for i := range notes {
			notes[i] = s.named(tx, notes[i], now)
		}
		if e := fn(tx); e != nil {
			return e
		}
		return s.appendActivity(tx, now, notes...)
	}
}
