package identity

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Every workspace page arrives in the layout of the session's stage, so moving
// between pages never shows the second-factor layout for a moment, and a
// session before its second factor never arrives in the ready layout.
func TestWorkspaceArrivesInTheSessionStage(t *testing.T) {
	_, store, c, _, _ := remoteFixture(t, "https://127.0.0.1:8443")
	named := regexp.MustCompile(`data-stage="([^"]*)"`)
	stageOf := func(client *custodyClient, path string) string {
		t.Helper()
		page := client.expect("GET", path, "", 200).Body.String()
		found := named.FindAllStringSubmatch(page, -1)
		if len(found) != 1 || !strings.Contains(page, strings.TrimSuffix(workspaceBody, ">")+` data-stage="`+found[0][1]+`">`) {
			t.Fatalf("%s names a stage %d times, or outside the body tag", path, len(found))
		}
		return found[0][1]
	}
	for _, path := range []string{"/", "/keys", "/account", "/installation"} {
		if stage := stageOf(c, path); stage != "ready" {
			t.Fatalf("%s arrived as %q for a ready session", path, stage)
		}
	}
	if _, e := store.CreateAccount("bob", alicePassword); e != nil {
		t.Fatal("second account failed")
	}
	enrollFixture(t, store, "bob", time.Now())
	bob := &custodyClient{t: t, l: c.l}
	bob.expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": alicePassword}), 204)
	if stage := stageOf(bob, "/keys"); stage != "challenge" {
		t.Fatalf("a session awaiting its code arrived as %q", stage)
	}
	bob.session("challenge")
	if _, e := store.CreateAccount("carol", alicePassword); e != nil {
		t.Fatal("third account failed")
	}
	carol := &custodyClient{t: t, l: c.l}
	carol.expect("POST", "/api/session", inputJSON(map[string]string{"username": "carol", "password": alicePassword}), 204)
	if stage := stageOf(carol, "/"); stage != "enroll" {
		t.Fatalf("a session without a phone arrived as %q", stage)
	}
	carol.session("enroll")
	(&custodyClient{t: t, l: c.l}).expect("GET", "/keys", "", 303)
	// Only the three stages are ever written into the page.
	for _, stage := range []string{"", "admin", "Ready", `ready" hidden="`, "ready "} {
		w := httptest.NewRecorder()
		serveWorkspace(w, stage)
		if w.Code != 500 || strings.Contains(w.Body.String(), "data-stage") {
			t.Fatalf("stage %q was written into the page (%d)", stage, w.Code)
		}
	}
}
