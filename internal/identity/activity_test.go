package identity

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func activityStore(t *testing.T) (*Store, string) {
	t.Helper()
	store, _, _ := bootstrapped(t)
	alice := mustLookup(t, store, "alice")
	return store, alice.ID
}

func entries(t *testing.T, s *Store, filter activityFilter) []activityEntry {
	t.Helper()
	var all []activityEntry
	for before := uint64(0); ; {
		page, more, e := s.readActivity(before, 50, filter)
		if e != nil {
			t.Fatal("the record did not read")
		}
		all = append(all, page...)
		if more == 0 {
			return all
		}
		before = more
	}
}

func check(t *testing.T, s *Store) activityCheck {
	t.Helper()
	var c activityCheck
	if s.view(func(tx *bolt.Tx) error { c = s.checkActivity(tx); return nil }) != nil {
		t.Fatal("the store did not read")
	}
	return c
}

// Entries chain one to the next across blocks, read back newest first in
// pages, and filter by person, server and kind.
func TestActivityChainsAcrossBlocksAndReadsBack(t *testing.T) {
	s, alice := activityStore(t)
	now := time.Now()
	server := strings.Repeat("a", 32)
	for i := range 300 {
		e := activityEntry{Kind: "signed-in", Actor: alice, Source: "10.0.0." + strconv.Itoa(i%250), Detail: map[string]string{"factor": "phone"}}
		if i%3 == 0 {
			e = activityEntry{Kind: "server-renamed", Actor: alice, Server: server, ServerName: "Build " + strconv.Itoa(i), Detail: map[string]string{"to": "New " + strconv.Itoa(i)}}
		}
		if s.record(now, e) != nil {
			t.Fatalf("entry %d was refused", i)
		}
	}
	var blocks int
	_ = s.view(func(tx *bolt.Tx) error { blocks = tx.Bucket(activityBucket).Stats().KeyN; return nil })
	if blocks < 2 {
		t.Fatalf("300 entries made %d block(s)", blocks)
	}
	if c := check(t, s); c.Broken || c.Entries != 300 {
		t.Fatalf("check = %+v", c)
	}
	all := entries(t, s, activityFilter{})
	if len(all) != 300 || all[0].Seq != 300 || all[299].Seq != 1 {
		t.Fatalf("read %d entries, first %d, last %d", len(all), all[0].Seq, all[len(all)-1].Seq)
	}
	if all[0].ActorName != "alice" || all[0].MAC != nil {
		t.Fatalf("an entry reads as %+v", all[0])
	}
	if renamed := entries(t, s, activityFilter{Server: server}); len(renamed) != 100 {
		t.Fatalf("the server filter found %d", len(renamed))
	}
	if signed := entries(t, s, activityFilter{Kinds: map[string]bool{"signed-in": true}}); len(signed) != 200 {
		t.Fatalf("the kind filter found %d", len(signed))
	}
	if none := entries(t, s, activityFilter{Person: strings.Repeat("b", 32)}); len(none) != 0 {
		t.Fatalf("another person's filter found %d", len(none))
	}
}

// What the record does not know is refused, and leaves the record as it was.
func TestActivityRefusesWhatItDoesNotKnow(t *testing.T) {
	s, alice := activityStore(t)
	now := time.Now()
	if s.record(now, activityEntry{Kind: "signed-in", Actor: alice, Detail: map[string]string{"factor": "phone"}}) != nil {
		t.Fatal("a valid entry was refused")
	}
	for name, e := range map[string]activityEntry{
		"unknown kind":   {Kind: "anything", Actor: alice},
		"foreign detail": {Kind: "signed-in", Actor: alice, Detail: map[string]string{"password": "x"}},
		"empty detail":   {Kind: "signed-in", Actor: alice, Detail: map[string]string{"factor": ""}},
		"long detail":    {Kind: "signed-in", Actor: alice, Detail: map[string]string{"factor": strings.Repeat("x", 257)}},
		"long path":      {Kind: "file-deleted", Actor: alice, Detail: map[string]string{"path": "/" + strings.Repeat("x", 4096)}},
		"bad ID":         {Kind: "server-removed", Actor: alice, Server: "../../etc"},
		"not text":       {Kind: "server-removed", Actor: alice, ServerName: "\xff"},
		"long source":    {Kind: "signed-in", Actor: alice, Source: strings.Repeat("1", 65)},
	} {
		if s.record(now, e) == nil {
			t.Errorf("%s was written", name)
		}
	}
	if c := check(t, s); c.Broken || c.Entries != 1 {
		t.Fatalf("after refusals: %+v", c)
	}
}

// Any change to the file's record outside Keybash shows as a break: a block
// removed from the middle or the end, a block moved, an older copy of a
// block put back.
func TestActivityShowsWhereItWasChanged(t *testing.T) {
	type tamper func(t *testing.T, b *bolt.Bucket, old []byte)
	for name, change := range map[string]tamper{
		"middle block removed": func(t *testing.T, b *bolt.Bucket, _ []byte) { _ = b.Delete(blockKey(2)) },
		"last block removed": func(t *testing.T, b *bolt.Bucket, _ []byte) {
			last, _ := b.Cursor().Last()
			_ = b.Delete(last)
		},
		"block moved": func(t *testing.T, b *bolt.Bucket, _ []byte) {
			data := append([]byte(nil), b.Get(blockKey(1))...)
			_ = b.Put(blockKey(2), data)
		},
		"older copy put back": func(t *testing.T, b *bolt.Bucket, old []byte) {
			last, _ := b.Cursor().Last()
			_ = b.Put(last, old)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, alice := activityStore(t)
			now := time.Now()
			var old []byte
			for i := range 400 {
				if s.record(now, activityEntry{Kind: "signed-in", Actor: alice, Detail: map[string]string{"factor": "phone"}}) != nil {
					t.Fatal("entry refused")
				}
				if i == 398 {
					_ = s.view(func(tx *bolt.Tx) error {
						_, v := tx.Bucket(activityBucket).Cursor().Last()
						old = append([]byte(nil), v...)
						return nil
					})
				}
			}
			if c := check(t, s); c.Broken {
				t.Fatal("broken before the change")
			}
			if s.db.Update(func(tx *bolt.Tx) error { change(t, tx.Bucket(activityBucket), old); return nil }) != nil {
				t.Fatal("the change failed")
			}
			if c := check(t, s); !c.Broken {
				t.Fatalf("%s went unnoticed: %+v", name, c)
			}
		})
	}
	// Even resealed with the store's own sealing key, a rewritten entry breaks
	// the chain: its HMAC is keyed apart.
	t.Run("entry rewritten and resealed", func(t *testing.T) {
		s, alice := activityStore(t)
		now := time.Now()
		for range 10 {
			if s.record(now, activityEntry{Kind: "signed-in", Actor: alice, Detail: map[string]string{"factor": "phone"}}) != nil {
				t.Fatal("entry refused")
			}
		}
		if s.update(func(tx *bolt.Tx) error {
			b := tx.Bucket(activityBucket)
			block, revision, e := s.readBlock(b, 1)
			if e != nil {
				return e
			}
			block.Entries[3].Detail = map[string]string{"factor": "recovery"}
			return s.writeBlock(tx, b, 1, revision+1, block)
		}) != nil {
			t.Fatal("the rewrite failed")
		}
		if c := check(t, s); !c.Broken || c.At != 4 {
			t.Fatalf("a rewritten entry went unnoticed: %+v", c)
		}
	})
}

// Old entries leave by age and by size, whole blocks at a time, with an
// entry that says how many and up to when; the chain still holds.
func TestActivityTrimsByAgeAndSize(t *testing.T) {
	s, alice := activityStore(t)
	long := time.Now().Add(-400 * 24 * time.Hour)
	for range 200 {
		if s.record(long, activityEntry{Time: long.Unix(), Kind: "signed-in", Actor: alice, Detail: map[string]string{"factor": "phone"}}) != nil {
			t.Fatal("entry refused")
		}
	}
	now := time.Now()
	if s.record(now, activityEntry{Kind: "signed-out", Actor: alice, Detail: map[string]string{"why": "signed-out"}}) != nil {
		t.Fatal("entry refused")
	}
	trimmed := entries(t, s, activityFilter{Kinds: map[string]bool{"record-trimmed": true}})
	if len(trimmed) != 1 || trimmed[0].Detail["count"] == "" || trimmed[0].Detail["until"] != strconv.FormatInt(long.Unix(), 10) {
		t.Fatalf("trimmed = %+v", trimmed)
	}
	if c := check(t, s); c.Broken {
		t.Fatalf("the chain broke when old entries left: %+v", c)
	}

	saved := activityMaxBlocks
	activityMaxBlocks = 2
	defer func() { activityMaxBlocks = saved }()
	for range 600 {
		if s.record(now, activityEntry{Kind: "signed-in", Actor: alice, Detail: map[string]string{"factor": "phone"}}) != nil {
			t.Fatal("entry refused")
		}
	}
	var blocks int
	_ = s.view(func(tx *bolt.Tx) error { blocks = tx.Bucket(activityBucket).Stats().KeyN; return nil })
	if blocks > 3 {
		t.Fatalf("the record holds %d blocks over its limit", blocks)
	}
	if c := check(t, s); c.Broken {
		t.Fatalf("the chain broke when the record was full: %+v", c)
	}
	var first uint64
	_ = s.view(func(tx *bolt.Tx) error {
		k, _ := tx.Bucket(activityBucket).Cursor().First()
		first = binary.BigEndian.Uint64(k)
		return nil
	})
	if first < 2 {
		t.Fatal("no old block left the full record")
	}
}

// An entry that cannot be written takes its change with it.
func TestActivityAndItsChangeGoTogether(t *testing.T) {
	s, alice := activityStore(t)
	now := time.Now()
	before, _ := s.lookup("alice")
	e := s.update(func(tx *bolt.Tx) error {
		a, err := s.readAccount(tx, alice)
		if err != nil {
			return err
		}
		a.Revision++
		if err = s.saveAccount(tx, a); err != nil {
			return err
		}
		return s.appendActivity(tx, now, activityEntry{Kind: "unknown", Actor: alice})
	})
	after, _ := s.lookup("alice")
	if e == nil || after.Revision != before.Revision {
		t.Fatal("a change kept going without its entry")
	}
	if c := check(t, s); c.Entries != 0 {
		t.Fatalf("a refused entry is in the record: %+v", c)
	}
}

// A backup carries the record sealed; a restore keeps it whole, adds that it
// was restored, and the chain still holds.
func TestActivityTravelsInBackups(t *testing.T) {
	s, key, _ := bootstrapped(t)
	alice := mustLookup(t, s, "alice")
	now := time.Now()
	for i := range 120 {
		if s.record(now, activityEntry{Kind: "file-downloaded", Actor: alice.ID, Detail: map[string]string{"path": "/srv/secret-canary-" + strconv.Itoa(i), "outcome": "done"}}) != nil {
			t.Fatal("entry refused")
		}
	}
	data := backupOf(t, s, now)
	if strings.Contains(string(data), "secret-canary") {
		t.Fatal("the backup carries the record in plaintext")
	}
	restored, _, summary, e := restoreStore(emptyDataDir(t), key, data, now)
	if e != nil {
		t.Fatal("a backup with a record was not restored")
	}
	defer restored.Close()
	if summary.ActivityEntries != 120 || summary.ActivityBroken {
		t.Fatalf("the backup's summary: %+v", summary)
	}
	all := entries(t, restored, activityFilter{})
	if len(all) != 121 || all[0].Kind != "restored" || all[120].Detail["path"] != "/srv/secret-canary-0" {
		t.Fatalf("after the restore the record holds %d entries, newest %q", len(all), all[0].Kind)
	}
	if c := check(t, restored); c.Broken {
		t.Fatalf("the restored chain broke: %+v", c)
	}
}
