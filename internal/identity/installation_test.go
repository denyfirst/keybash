package identity

import (
	"encoding/json"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"
)

// The Installation page's facts need a ready session and say only the build
// and what this copy serves: no path, address, key, account or setting.
func TestInstallationFactsNeedAReadySession(t *testing.T) {
	_, store, c, _, _ := remoteFixture(t, "https://127.0.0.1:8443")
	w := c.expect("GET", "/api/installation", "", 200)
	var view map[string]any
	if json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatal("installation facts are not JSON")
	}
	keys := make([]string, 0, len(view))
	for key := range view {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if strings.Join(keys, " ") != "built modified rdp revision servers ssh" {
		t.Fatalf("installation facts carry %v", keys)
	}
	c.l.mu.Lock()
	ssh, rdp := c.l.remote.ssh != nil, c.l.remote.rdp != nil
	c.l.mu.Unlock()
	if view["ssh"] != ssh || view["rdp"] != rdp || !ssh && !rdp || view["servers"] != float64(1) {
		t.Fatalf("installation facts misdescribe the fixture: %v", view)
	}
	for _, leak := range []string{"/etc/", "/var/", "127.0.0.1", "alice", "BEGIN", "keybash-gateway"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("installation facts name %q", leak)
		}
	}
	c.expect("POST", "/api/installation", "{}", 404)
	// Without a session, and with one before the second factor, nothing.
	(&custodyClient{t: t, l: c.l}).expect("GET", "/api/installation", "", 401)
	(&custodyClient{t: t, l: c.l}).expect("GET", "/installation", "", 303)
	if _, e := store.CreateAccount("bob", alicePassword); e != nil {
		t.Fatal("second account failed")
	}
	enrollFixture(t, store, "bob", time.Now())
	bob := &custodyClient{t: t, l: c.l}
	bob.expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": alicePassword}), 204)
	bob.session("challenge")
	bob.expect("GET", "/api/installation", "", 403)
	// The page itself is the workspace document, which shows the part named.
	page := c.expect("GET", "/installation", "", 200)
	if !strings.Contains(page.Body.String(), `data-page="installation"`) || !strings.Contains(page.Body.String(), `id="installation-panel"`) {
		t.Fatal("the workspace has no Installation page")
	}
}

// The build is reported only as Go recorded it: a full lowercase commit, its
// time in UTC, and whether the tree had local changes. Anything else is none.
func TestBuildStampReportsOnlyAFullCommit(t *testing.T) {
	commit := strings.Repeat("0123456789", 4)
	info := func(settings ...debug.BuildSetting) *debug.BuildInfo { return &debug.BuildInfo{Settings: settings} }
	for _, c := range []struct {
		name            string
		info            *debug.BuildInfo
		ok              bool
		revision, built string
		modified        bool
	}{
		{"no build info", nil, false, "", "", false},
		{"no commit", info(debug.BuildSetting{Key: "vcs.time", Value: "2026-10-30T12:46:54Z"}), true, "", "", false},
		{"full", info(debug.BuildSetting{Key: "vcs.revision", Value: commit}, debug.BuildSetting{Key: "vcs.time", Value: "2026-10-30T14:46:54+02:00"}, debug.BuildSetting{Key: "vcs.modified", Value: "true"}), true, commit, "2026-10-30T12:46:54Z", true},
		{"short commit", info(debug.BuildSetting{Key: "vcs.revision", Value: commit[:12]}, debug.BuildSetting{Key: "vcs.modified", Value: "true"}), true, "", "", false},
		{"uppercase", info(debug.BuildSetting{Key: "vcs.revision", Value: strings.ToUpper(strings.Repeat("ab", 20))}), true, "", "", false},
		{"markup", info(debug.BuildSetting{Key: "vcs.revision", Value: commit[:39] + "<"}), true, "", "", false},
		{"bad time", info(debug.BuildSetting{Key: "vcs.revision", Value: commit}, debug.BuildSetting{Key: "vcs.time", Value: "yesterday"}), true, commit, "", false},
	} {
		revision, built, modified := buildStamp(c.info, c.ok)
		if revision != c.revision || built != c.built || modified != c.modified {
			t.Errorf("%s: got %q %q %v", c.name, revision, built, modified)
		}
	}
}
