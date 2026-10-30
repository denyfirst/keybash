package identity

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/web"
)

// The names the server accepts are exactly the marks the page can draw.
func TestSystemNamesMatchTheMarks(t *testing.T) {
	module, e := web.Assets.ReadFile("systems.mjs")
	if e != nil {
		t.Fatal("systems.mjs is not embedded")
	}
	drawn := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^  ([a-z]+): \{`).FindAllStringSubmatch(string(module), -1) {
		drawn[m[1]] = true
	}
	if len(drawn) != len(systemNames) {
		t.Fatalf("page draws %d marks, server accepts %d names", len(drawn), len(systemNames))
	}
	for name := range systemNames {
		if !drawn[name] {
			t.Fatalf("server accepts %q, which the page cannot draw", name)
		}
	}
	// Path data only: no markup, script or URL can come in with a mark.
	for _, banned := range []string{"<", ">", "javascript:", "http", "url(", "import ", "fetch"} {
		if strings.Contains(strings.SplitN(string(module), "export const systems", 2)[1], banned) {
			t.Fatalf("systems.mjs data contains %q", banned)
		}
	}
}

// A card's system is a label its owner picks: it changes no target,
// credential or trust decision, and only the owner can set it.
func TestConnectionSystemIsALabelOnly(t *testing.T) {
	_, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	read := func() connectionView {
		t.Helper()
		var rows []connectionView
		if json.Unmarshal(c.expect("GET", "/api/connections", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 {
			t.Fatal("connection list malformed")
		}
		return rows[0]
	}
	before := read()
	if before.System != "" || before.Trust != "verified" {
		t.Fatal("fixture connection is not a verified connection without a system")
	}
	path := "/api/connections/" + record + "/system"
	c.expect("POST", path, inputJSON(map[string]string{"system": "ubuntu"}), 204)
	after := read()
	if after.System != "ubuntu" || after.Trust != "verified" || after.Target != before.Target || after.Credential != before.Credential || after.Fingerprint != before.Fingerprint || after.Name != before.Name {
		t.Fatal("setting the system changed more than the label")
	}
	if after.Revision == before.Revision {
		t.Fatal("the record was not resealed at a new revision")
	}
	for _, body := range []string{
		inputJSON(map[string]string{"system": "windows95"}),
		inputJSON(map[string]string{"system": "Ubuntu"}),
		inputJSON(map[string]string{"system": ""}),
		inputJSON(map[string]string{"system": "ubuntu", "target": strings.Repeat("a", 32)}),
		`{"system":1}`, `not json`,
	} {
		c.expect("POST", path, body, 400)
	}
	c.expect("POST", "/api/connections/"+strings.Repeat("a", 32)+"/system", inputJSON(map[string]string{"system": "debian"}), 404)
	c.expect("POST", "/api/connections/not-an-id/system", inputJSON(map[string]string{"system": "debian"}), 400)
	if read().System != "ubuntu" {
		t.Fatal("a refused request changed the system")
	}
	// Another account cannot label someone else's connection.
	if _, e := store.CreateAccount("bob", alicePassword); e != nil {
		t.Fatal("second account failed")
	}
	_, _, codes := enrollFixture(t, store, "bob", time.Now())
	bob := &custodyClient{t: t, l: c.l}
	bob.expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": alicePassword}), 204)
	bob.session("challenge")
	bob.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	bob.session("ready")
	bob.expect("POST", path, inputJSON(map[string]string{"system": "debian"}), 404)
	if read().System != "ubuntu" {
		t.Fatal("another account changed the system")
	}
}
