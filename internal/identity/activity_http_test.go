package identity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	bolt "go.etcd.io/bbolt"
)

// readActivityPage reads the record through the page's own request.
func readActivityPage(t *testing.T, c *custodyClient, what string) activityPage {
	t.Helper()
	var page activityPage
	body := inputJSON(map[string]string{"before": "", "person": "", "server": "", "what": what, "from": "", "to": ""})
	if json.Unmarshal(c.expect("POST", "/api/activity", body, 200).Body.Bytes(), &page) != nil {
		t.Fatal("the activity page did not read")
	}
	return page
}

func kindsOf(page activityPage) []string {
	var kinds []string
	for _, e := range page.Entries {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

func findKind(page activityPage, kind string) (activityEntry, bool) {
	for _, e := range page.Entries {
		if e.Kind == kind {
			return e, true
		}
	}
	return activityEntry{}, false
}

// Every change made on the pages, sign-ins and their refusals, and a Files
// session with its operations land in the record, in plain fixed words, with
// who did them; a name that is no account is never written.
func TestActivityRecordsWhoDidWhat(t *testing.T) {
	f := filesFixture(t)
	dave, _ := f.person("dave", roleAuditor)
	f.setFiles("both")
	f.alice.expect("POST", "/api/servers/"+f.server+"/name", inputJSON(map[string]string{"name": "Build box"}), 204)
	f.alice.expect("POST", "/api/servers/"+f.server+"/system", inputJSON(map[string]string{"system": "ubuntu"}), 204)
	var invited struct{ ID string }
	if json.Unmarshal(f.alice.expect("POST", "/api/users", inputJSON(map[string]string{"username": "carol", "role": "user"}), 200).Body.Bytes(), &invited) != nil {
		t.Fatal("invite failed")
	}
	f.alice.expect("POST", "/api/users/"+invited.ID+"/block", "{}", 204)
	f.alice.expect("POST", "/api/users/"+invited.ID+"/unblock", "{}", 204)

	stranger := &custodyClient{t: t, l: f.l}
	for range 3 {
		stranger.call("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": "not bob's password"}))
	}
	stranger.call("POST", "/api/session", inputJSON(map[string]string{"username": "typed-secret-in-name", "password": "x"}))
	// The right password and a wrong code: refused at the second step.
	wrongCode := &custodyClient{t: t, l: f.l}
	wrongCode.expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": bobPassword}), 204)
	wrongCode.session("challenge")
	wrongCode.call("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": "000000"}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := f.socket(ctx, "/api/remote/files-socket", f.lease("/api/remote/files", 200))
	if _, _, e := conn.Read(ctx); e != nil {
		t.Fatal("no ready")
	}
	_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"mkdir","id":1,"path":"/srv/deploy/reports"}`))
	if _, data, e := conn.Read(ctx); e != nil || !strings.Contains(string(data), `"done"`) {
		t.Fatalf("mkdir = %q, %v", data, e)
	}
	_ = conn.Close(websocket.StatusNormalClosure, "")
	var page activityPage
	for deadline := time.Now().Add(5 * time.Second); ; {
		page = readActivityPage(t, f.alice, "")
		if _, ended := findKind(page, "session-ended"); ended || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, kind := range []string{"server-added", "signed-in", "server-files", "server-renamed", "server-picture", "person-invited", "person-blocked", "person-unblocked", "sign-in-refused", "session-started", "folder-made", "session-ended"} {
		if _, ok := findKind(page, kind); !ok {
			t.Errorf("no %s entry in %v", kind, kindsOf(page))
		}
	}
	renamed, _ := findKind(page, "server-renamed")
	if renamed.ActorName != "alice" || renamed.ServerName != "Build" || renamed.Detail["to"] != "Build box" {
		t.Errorf("the rename reads %+v", renamed)
	}
	made, _ := findKind(page, "folder-made")
	if made.ActorName != "bob" || made.AccountName != "deploy" || made.Detail["path"] != "/srv/deploy/reports" || made.Detail["outcome"] != "done" {
		t.Errorf("the folder reads %+v", made)
	}
	ended, _ := findKind(page, "session-ended")
	if ended.Detail["session"] != "files" || ended.Detail["why"] != "closed" || ended.Detail["seconds"] == "" {
		t.Errorf("the session's end reads %+v", ended)
	}
	refusedFor, unknown, wrongCodes, bobIn := 0, 0, 0, 0
	for _, e := range page.Entries {
		switch {
		case e.Kind == "signed-in" && e.ActorName == "bob":
			bobIn++
		case e.Kind != "sign-in-refused":
		case e.Detail["step"] == "code" && e.ActorName == "bob":
			wrongCodes++
		case e.ActorName == "bob":
			refusedFor++
		case e.Actor == "":
			unknown++
		}
	}
	if refusedFor != 1 || unknown != 1 {
		t.Errorf("refused sign-ins were not grouped: %d for bob, %d for no account", refusedFor, unknown)
	}
	if wrongCodes != 1 || bobIn != 1 {
		t.Errorf("a wrong code reads as %d refusal(s) and bob signed in %d time(s)", wrongCodes, bobIn)
	}
	raw := f.alice.expect("POST", "/api/activity", inputJSON(map[string]string{"before": "", "person": "", "server": "", "what": "", "from": "", "to": ""}), 200).Body.String()
	if strings.Contains(raw, "typed-secret-in-name") || strings.Contains(raw, "not bob's password") {
		t.Fatal("a typed name or password reached the record")
	}

	// Filters narrow the page.
	if files := readActivityPage(t, f.alice, "files"); len(files.Entries) != 1 || files.Entries[0].Kind != "folder-made" {
		t.Errorf("the files filter shows %v", kindsOf(files))
	}
	// Administrators and auditors read it; a user does not, and nobody
	// changes it.
	readActivityPage(t, dave, "")
	f.bob.expect("POST", "/api/activity", inputJSON(map[string]string{"before": "", "person": "", "server": "", "what": "", "from": "", "to": ""}), 403)
	for _, method := range []string{"GET", "DELETE", "PUT"} {
		if w := f.alice.call(method, "/api/activity", "{}"); w.Code == 200 || w.Code == 204 {
			t.Errorf("%s answered %d", method, w.Code)
		}
	}
	for _, body := range []string{
		inputJSON(map[string]string{"before": "", "person": "", "server": "", "what": "everything", "from": "", "to": ""}),
		inputJSON(map[string]string{"before": "x", "person": "", "server": "", "what": "", "from": "", "to": ""}),
		inputJSON(map[string]string{"before": "", "person": "../x", "server": "", "what": "", "from": "", "to": ""}),
		`{"before":""}`,
	} {
		f.alice.expect("POST", "/api/activity", body, 400)
	}
	if c := check(t, f.store); c.Broken {
		t.Fatal("the record's chain broke")
	}
}

// A session whose entry cannot be written does not start, and says why.
func TestActivitySessionsAreRecordedFirst(t *testing.T) {
	f := filesFixture(t)
	f.setFiles("both")
	// An address no entry can hold makes the session's entry refuse.
	f.l.mu.Lock()
	for _, s := range f.l.sessions {
		if s.username == "bob" {
			s.source = strings.Repeat("9", 100)
		}
	}
	f.l.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := f.socket(ctx, "/api/remote/files-socket", f.lease("/api/remote/files", 200))
	if _, data, e := conn.Read(ctx); e != nil || string(data) != `{"type":"ended","reason":"unrecorded"}` {
		t.Fatalf("an unrecorded session answered %q, %v", data, e)
	}
	if f.worker.files.Load() != 0 {
		t.Fatal("a session that was not recorded opened its worker")
	}
}

// A block that no longer reads does not stop Keybash: the next entry starts a
// new block, changes go on, and the check shows the break.
func TestActivityGoesOnPastADamagedBlock(t *testing.T) {
	f := filesFixture(t)
	if f.store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(activityBucket)
		last, _ := b.Cursor().Last()
		return b.Put(last, []byte(`{"Version":1}`))
	}) != nil {
		t.Fatal("damage failed")
	}
	f.setFiles("download")
	if f.card().Files != "download" {
		t.Fatal("a change stopped after a damaged block")
	}
	if c := check(t, f.store); !c.Broken {
		t.Fatal("a damaged block went unnoticed")
	}
	if page := readActivityPage(t, f.alice, ""); !page.Broken {
		t.Fatal("the page does not say the record broke")
	}
}
