package identity

import (
	"bytes"
	"regexp"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// An account's chosen look arrives with every page, in its root tag, from a
// few fixed words. It is kept with the account on the server, never in the
// browser, and only a ready session of that account, with its request proof,
// can change it.
func TestLookIsKeptWithTheAccountAndArrivesWithThePage(t *testing.T) {
	l, store, c, _, _ := remoteFixture(t, "https://127.0.0.1:8443")
	rootTag := regexp.MustCompile(`<html[^>]*>`)
	root := func(client *custodyClient, path string) string {
		t.Helper()
		page := client.expect("GET", path, "", 200).Body.String()
		found := rootTag.FindAllString(page, -1)
		if len(found) != 1 {
			t.Fatalf("%s has %d root tags", path, len(found))
		}
		return found[0]
	}
	if got := root(c, "/"); got != `<html lang="en">` {
		t.Fatalf("a new account's pages arrived with a chosen look: %s", got)
	}
	choose := func(theme, menu string, status int) {
		t.Helper()
		c.expect("POST", "/api/preferences", inputJSON(map[string]string{"theme": theme, "menu": menu}), status)
	}
	choose("dark", "collapsed", 204)
	for _, path := range []string{"/", "/keys", "/account", "/installation", "/users", "/servers"} {
		if got := root(c, path); got != `<html lang="en" data-theme="dark" data-menu="collapsed">` {
			t.Fatalf("%s arrived as %s", path, got)
		}
	}
	// Anything but the exact words, both together, changes nothing.
	for _, body := range []string{
		`{"theme":"light"}`, `{"menu":"open"}`, `{"theme":"Light","menu":"open"}`, `{"theme":"","menu":"open"}`, `{"theme":"auto","menu":"open"}`,
		`{"theme":"dark\" onload=\"x","menu":"open"}`, `{"theme":"light","menu":"hidden"}`, `{"theme":"light","menu":""}`,
		`{"theme":"light","menu":"open","owner":"x"}`, `{"theme":1,"menu":"open"}`, `{"theme":null,"menu":"open"}`,
		`{"theme":"light","menu":"open","theme":"dark"}`, `{"theme":"light","menu":"open"} {}`, `[]`, ``,
	} {
		c.expect("POST", "/api/preferences", body, 400)
	}
	if got := root(c, "/keys"); got != `<html lang="en" data-theme="dark" data-menu="collapsed">` {
		t.Fatalf("a refused choice changed the look: %s", got)
	}
	// Only a ready session of this account, with its proof, chooses.
	proof := c.csrf
	c.csrf = "wrong"
	choose("light", "open", 403)
	c.csrf = proof
	(&custodyClient{t: t, l: l}).expect("POST", "/api/preferences", inputJSON(map[string]string{"theme": "light", "menu": "open"}), 401)
	if _, e := store.CreateAccount("bob", alicePassword); e != nil {
		t.Fatal("second account failed")
	}
	enrollFixture(t, store, "bob", time.Now())
	bob := &custodyClient{t: t, l: l}
	bob.expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": alicePassword}), 204)
	bob.session("challenge")
	bob.expect("POST", "/api/preferences", inputJSON(map[string]string{"theme": "light", "menu": "open"}), 403)
	// Another account's pages keep their own look.
	if got := root(bob, "/"); got != `<html lang="en">` {
		t.Fatalf("another account's page arrived as %s", got)
	}
	if got := root(c, "/"); got != `<html lang="en" data-theme="dark" data-menu="collapsed">` {
		t.Fatalf("someone else's choice changed this account's look: %s", got)
	}
	// And back: light, then the system's again.
	choose("light", "open", 204)
	if got := root(c, "/"); got != `<html lang="en" data-theme="light">` {
		t.Fatalf("light arrived as %s", got)
	}
	choose("system", "open", 204)
	if got := root(c, "/"); got != `<html lang="en">` {
		t.Fatalf("following the system arrived as %s", got)
	}
}

// The look is a sealed record under the account's own name: it reads for that
// account only, refuses to be written over when it cannot be read, travels
// in a backup, and goes when the account goes.
func TestLookRecordIsSealedOwnedAndGoesWithTheAccount(t *testing.T) {
	s, key, _ := bootstrapped(t)
	now := time.Now()
	alice, _, _ := enrollFixture(t, s, "alice", now)
	if _, e := s.CreateAccount("bob", bobPassword); e != nil {
		t.Fatal("fixture second account refused")
	}
	bob, _ := s.lookup("bob")
	for _, bad := range []preferences{{Theme: "Dark"}, {Theme: "system"}, {Menu: "open"}, {Theme: `dark" x="`}} {
		if s.setPreferences(alice.ID, bad) == nil {
			t.Fatalf("%+v was saved", bad)
		}
	}
	if s.setPreferences(stringsRepeat("f", 32), preferences{Theme: "dark"}) == nil || s.setPreferences("alice", preferences{Theme: "dark"}) == nil {
		t.Fatal("a look was saved for no account")
	}
	if s.setPreferences(alice.ID, preferences{Theme: "dark", Menu: "collapsed"}) != nil || s.setPreferences(bob.ID, preferences{Theme: "light"}) != nil {
		t.Fatal("valid looks refused")
	}
	if got := s.preferencesOf(alice.ID); got != (preferences{Theme: "dark", Menu: "collapsed"}) {
		t.Fatalf("alice reads %+v", got)
	}
	var raw []byte
	_ = s.view(func(tx *bolt.Tx) error {
		raw = bytes.Clone(tx.Bucket(preferenceBucket).Get(credentialKey(alice.ID, alice.ID)))
		return nil
	})
	if len(raw) == 0 || bytes.Contains(raw, []byte("dark")) || bytes.Contains(raw, []byte("collapsed")) {
		t.Fatal("the look is not sealed")
	}
	put := func(k []byte, v []byte) {
		t.Helper()
		if s.update(func(tx *bolt.Tx) error {
			if v == nil {
				return tx.Bucket(preferenceBucket).Delete(k)
			}
			return tx.Bucket(preferenceBucket).Put(k, v)
		}) != nil {
			t.Fatal("fixture write failed")
		}
	}
	// Alice's record under Bob's name does not read, is not written over,
	// and stops a backup; under her name with his ID it stops one too.
	var bobs []byte
	_ = s.view(func(tx *bolt.Tx) error {
		bobs = bytes.Clone(tx.Bucket(preferenceBucket).Get(credentialKey(bob.ID, bob.ID)))
		return nil
	})
	put(credentialKey(bob.ID, bob.ID), raw)
	if got := s.preferencesOf(bob.ID); got != (preferences{}) {
		t.Fatalf("a moved record read as %+v", got)
	}
	if s.setPreferences(bob.ID, preferences{Theme: "dark"}) == nil {
		t.Fatal("an unreadable record was written over")
	}
	if _, e := s.Backup(&bytes.Buffer{}, now); e == nil {
		t.Fatal("a store with a moved look backed up")
	}
	put(credentialKey(bob.ID, bob.ID), bobs)
	put(credentialKey(alice.ID, alice.ID), nil)
	put(credentialKey(alice.ID, bob.ID), raw)
	if _, e := s.Backup(&bytes.Buffer{}, now); e == nil {
		t.Fatal("a store with a look under another account's ID backed up")
	}
	put(credentialKey(alice.ID, bob.ID), nil)
	put(credentialKey(alice.ID, alice.ID), raw)
	// A backup carries both looks; a restore brings them back.
	data := backupOf(t, s, now)
	restored, _, _, e := restoreStore(emptyDataDir(t), key, data, now)
	if e != nil {
		t.Fatal("a backup with looks was not restored")
	}
	if restored.preferencesOf(alice.ID) != (preferences{Theme: "dark", Menu: "collapsed"}) || restored.preferencesOf(bob.ID) != (preferences{Theme: "light"}) {
		t.Fatal("the looks did not survive restore")
	}
	_ = restored.Close()
	// Deleting Bob takes his look with him.
	if s.deleteAccount(alice.ID, bob.ID) != nil {
		t.Fatal("fixture account deletion refused")
	}
	_ = s.view(func(tx *bolt.Tx) error {
		raw = tx.Bucket(preferenceBucket).Get(credentialKey(bob.ID, bob.ID))
		return nil
	})
	if raw != nil {
		t.Fatal("a deleted account's look stayed")
	}
	if _, e := s.Backup(&bytes.Buffer{}, now); e != nil {
		t.Fatal("the store after deletion did not back up")
	}
}

func stringsRepeat(s string, n int) string { return string(bytes.Repeat([]byte(s), n)) }
