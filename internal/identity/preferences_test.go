package identity

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// An account's chosen look arrives with every page, in its root tag, from a
// few fixed words. It is kept with the account on the server; the browser
// gets only a copy of the scheme for the sign-in page
// (TestChosenLookReachesEveryPage). Only a ready session of that account, with
// its request proof, can change it.
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
	for _, path := range []string{"/", "/account", "/installation", "/users", "/servers", "/servers/" + strings.Repeat("c", 32)} {
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
	if got := root(c, "/account"); got != `<html lang="en" data-theme="dark" data-menu="collapsed">` {
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

// The sign-in page is drawn before anyone signs in, so it cannot ask the
// account. It takes the scheme from the browser's copy of the choice: one
// cookie holding one of two words, written by this server with the
// workspace's pages and with every change. Session pages and the closed page
// take the account's choice itself.
func TestChosenLookReachesEveryPage(t *testing.T) {
	l, _, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	rootTag := regexp.MustCompile(`<html[^>]*>`)
	root := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		found := rootTag.FindAllString(w.Body.String(), -1)
		if len(found) != 1 {
			t.Fatalf("the page has %d root tags", len(found))
		}
		return found[0]
	}
	copies := func(w *httptest.ResponseRecorder) []*http.Cookie {
		var found []*http.Cookie
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name == lookCookie {
				found = append(found, cookie)
			}
		}
		return found
	}
	// A request as a browser sends it, with the session's cookie when there
	// is one and the raw Cookie header it holds besides.
	get := func(path, held string, session bool, status int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", l.origin+path, nil)
		r.RemoteAddr, r.TLS = "127.0.0.1:9876", &tls.ConnectionState{Version: tls.VersionTLS13}
		if held != "" {
			r.Header.Add("Cookie", held)
		}
		if session {
			r.AddCookie(c.cookie)
		}
		w := httptest.NewRecorder()
		l.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("GET %s with %q: got %d want %d", path, held, w.Code, status)
		}
		return w
	}
	choose := func(theme string) *http.Cookie {
		t.Helper()
		found := copies(c.expect("POST", "/api/preferences", inputJSON(map[string]string{"theme": theme, "menu": "open"}), 204))
		if len(found) != 1 || !found[0].Secure || !found[0].HttpOnly || found[0].SameSite != http.SameSiteStrictMode || found[0].Path != "/" {
			t.Fatalf("choosing %s wrote %+v", theme, found)
		}
		return found[0]
	}
	// Following the system writes nothing, and the sign-in page has no scheme.
	if found := copies(get("/", "", true, 200)); len(found) != 0 {
		t.Fatalf("following the system wrote %+v", found)
	}
	if got := root(get("/login", "", false, 200)); got != `<html lang="en">` {
		t.Fatalf("the sign-in page arrived as %s", got)
	}
	// A choice writes its copy at once, and the sign-in page takes it.
	dark := choose("dark")
	if dark.Value != "dark" || dark.MaxAge <= 0 {
		t.Fatalf("dark wrote %+v", dark)
	}
	if got := root(get("/login", "keybash-look=dark", false, 200)); got != `<html lang="en" data-theme="dark">` {
		t.Fatalf("the sign-in page arrived as %s", got)
	}
	// A workspace page writes the copy when the browser's differs, and only then.
	for held, want := range map[string]int{"": 1, "keybash-look=light": 1, "keybash-look=Dark": 1, "keybash-look=dark": 0} {
		found := copies(get("/servers", held, true, 200))
		if len(found) != want || want == 1 && found[0].Value != "dark" {
			t.Fatalf("a workspace page with %q wrote %+v", held, found)
		}
	}
	// Only one of the two words, from exactly one cookie, reaches the page.
	for _, held := range []string{
		"keybash-look=Dark", "keybash-look=system", "keybash-look=", `keybash-look=dark" onload="x`, "keybash-look=dark%22", "keybash-look=dark; keybash-look=dark",
		"keybash-look=dark; keybash-look=light", "keybash-looks=dark", "Keybash-Look=dark",
	} {
		if got := root(get("/login", held, false, 200)); got != `<html lang="en">` {
			t.Fatalf("the sign-in page with %q arrived as %s", held, got)
		}
	}
	// Each side holds on its own: the reader takes only the two words, and
	// the writer writes nothing else, on exactly one root tag.
	page := []byte("<!doctype html>\n" + workspaceRoot + "<head>")
	for _, word := range []string{"Dark", "system", "auto", "light%20", `dark" onload="x`, "x"} {
		r := httptest.NewRequest("GET", l.origin+"/login", nil)
		r.Header.Set("Cookie", lookCookie+"="+word)
		if got := requestLook(r); got != "" {
			t.Fatalf("the copy %q was read as %q", word, got)
		}
		if got, ok := withLook(page, word); !ok || !bytes.Equal(got, page) {
			t.Fatalf("%q was written on the page: %s", word, got)
		}
	}
	for _, bad := range []string{"<html>", workspaceRoot + workspaceRoot, `<html lang="en" data-theme="dark">`} {
		if _, ok := withLook([]byte(bad), "dark"); ok {
			t.Fatalf("a page with the root tags %q was drawn", bad)
		}
	}
	// Session pages and the closed page follow the account, whatever the
	// browser holds.
	choose("light")
	for path, status := range map[string]int{"/remote/rdp/" + record: 200, "/remote/ssh/" + record: 404, "/remote/rdp/" + strings.Repeat("d", 32): 404} {
		if got := root(get(path, "keybash-look=dark", true, status)); got != `<html lang="en" data-theme="light">` {
			t.Fatalf("%s arrived as %s", path, got)
		}
	}
	// Following the system again takes the copy away.
	if system := choose("system"); system.Value != "" || system.MaxAge >= 0 {
		t.Fatalf("following the system wrote %+v", system)
	}
	if got := root(get("/remote/rdp/"+record, "keybash-look=dark", true, 200)); got != `<html lang="en">` {
		t.Fatalf("a session page arrived as %s", got)
	}
}

// How an account's desktops open on a scaled screen is kept with the account
// too, chosen as one fixed word, and reaches only its desktop pages' body tag.
// Choosing it keeps the look, and choosing the look keeps it.
func TestDesktopPictureIsKeptWithTheAccountAndArrivesWithTheDesktop(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	body := regexp.MustCompile(`<body[^>]*>`)
	desktop := func(client *custodyClient) string {
		t.Helper()
		found := body.FindAllString(client.expect("GET", "/remote/rdp/"+record, "", 200).Body.String(), -1)
		if len(found) != 1 {
			t.Fatalf("the desktop page has %d body tags", len(found))
		}
		return found[0]
	}
	picture := func(word string, status int) {
		t.Helper()
		c.expect("POST", "/api/preferences/picture", inputJSON(map[string]string{"picture": word}), status)
	}
	if got := desktop(c); strings.Contains(got, "data-picture") {
		t.Fatalf("a new account's desktop arrived with a picture: %s", got)
	}
	c.expect("POST", "/api/preferences", inputJSON(map[string]string{"theme": "dark", "menu": "collapsed"}), 204)
	picture("sharp", 204)
	if got := desktop(c); strings.Count(got, `data-picture="sharp"`) != 1 {
		t.Fatalf("sharp arrived as %s", got)
	}
	if got := store.preferencesOf(mustLookup(t, store, "alice").ID); got != (preferences{Theme: "dark", Menu: "collapsed", Picture: "sharp"}) {
		t.Fatalf("choosing the picture changed the look: %+v", got)
	}
	c.expect("POST", "/api/preferences", inputJSON(map[string]string{"theme": "light", "menu": "open"}), 204)
	if got := desktop(c); strings.Count(got, `data-picture="sharp"`) != 1 {
		t.Fatalf("choosing the look lost the picture: %s", got)
	}
	// Anything but one exact word changes nothing.
	for _, bad := range []string{
		`{"picture":"Sharp"}`, `{"picture":""}`, `{"picture":"none"}`, `{"picture":"sharp\" onload=\"x"}`, `{"picture":1}`, `{"picture":null}`,
		`{"picture":"smooth","theme":"dark"}`, `{"picture":"smooth","picture":"sharp"}`, `{"picture":"smooth"} {}`, `{}`, `[]`, ``,
	} {
		c.expect("POST", "/api/preferences/picture", bad, 400)
	}
	if got := desktop(c); strings.Count(got, `data-picture="sharp"`) != 1 {
		t.Fatalf("a refused word changed the picture: %s", got)
	}
	// Only a ready session of this account, with its proof, chooses.
	proof := c.csrf
	c.csrf = "wrong"
	picture("smooth", 403)
	c.csrf = proof
	(&custodyClient{t: t, l: l}).expect("POST", "/api/preferences/picture", inputJSON(map[string]string{"picture": "smooth"}), 401)
	picture("smooth", 204)
	if got := desktop(c); strings.Count(got, `data-picture="smooth"`) != 1 || strings.Contains(got, "sharp") {
		t.Fatalf("smooth arrived as %s", got)
	}
	// Auto leaves the choice to the page again.
	picture("auto", 204)
	if got := desktop(c); strings.Contains(got, "data-picture") {
		t.Fatalf("auto arrived as %s", got)
	}
	if got := store.preferencesOf(mustLookup(t, store, "alice").ID); got != (preferences{Theme: "light"}) {
		t.Fatalf("auto left %+v", got)
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
	for _, bad := range []preferences{{Theme: "Dark"}, {Theme: "system"}, {Menu: "open"}, {Theme: `dark" x="`}, {Picture: "Sharp"}, {Picture: "auto"}, {Picture: `sharp" x="`}} {
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
		raw = bytes.Clone(tx.Bucket(preferenceBucket).Get(lookKey(alice.ID, alice.ID)))
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
		bobs = bytes.Clone(tx.Bucket(preferenceBucket).Get(lookKey(bob.ID, bob.ID)))
		return nil
	})
	put(lookKey(bob.ID, bob.ID), raw)
	if got := s.preferencesOf(bob.ID); got != (preferences{}) {
		t.Fatalf("a moved record read as %+v", got)
	}
	if s.setPreferences(bob.ID, preferences{Theme: "dark"}) == nil {
		t.Fatal("an unreadable record was written over")
	}
	if _, e := s.Backup(&bytes.Buffer{}, now); e == nil {
		t.Fatal("a store with a moved look backed up")
	}
	put(lookKey(bob.ID, bob.ID), bobs)
	put(lookKey(alice.ID, alice.ID), nil)
	put(lookKey(alice.ID, bob.ID), raw)
	if _, e := s.Backup(&bytes.Buffer{}, now); e == nil {
		t.Fatal("a store with a look under another account's ID backed up")
	}
	put(lookKey(alice.ID, bob.ID), nil)
	put(lookKey(alice.ID, alice.ID), raw)
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
		raw = tx.Bucket(preferenceBucket).Get(lookKey(bob.ID, bob.ID))
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

// lookKey is where a look is kept: under its owner, and an ID that must be
// the owner's own.
func lookKey(owner, id string) []byte { return []byte(owner + "/" + id) }
