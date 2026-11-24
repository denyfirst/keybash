package identity

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/web"
	"golang.org/x/crypto/ssh"
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

// A server's mark is a label an administrator picks for its cards: it changes
// no target, identity or access, and nobody else sets it.
func TestServerSystemIsALabelOnly(t *testing.T) {
	f, scans := serversFixture(t)
	server, key := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	bob, b := f.person("bob", roleUser)
	dave, _ := f.person("dave", roleAuditor)
	account := accountFixture(t, f.l, server, "deploy", "", b.ID)
	card := func() accessRow {
		t.Helper()
		var rows []accessRow
		if json.Unmarshal(bob.expect("GET", "/api/access", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 {
			t.Fatal("access list malformed")
		}
		return rows[0]
	}
	before := card()
	stored, _ := f.store.listServers()
	if before.System != "" || before.Trust != "verified" {
		t.Fatal("fixture card is not a ready card without a mark")
	}
	path := "/api/servers/" + server + "/system"
	f.alice.expect("POST", path, inputJSON(map[string]string{"system": "ubuntu"}), 204)
	after := card()
	if after.System != "ubuntu" || after.Trust != "verified" || after.Account != account || after.Username != "deploy" {
		t.Fatal("setting the mark changed more than the label")
	}
	row, _ := serverRow(listServersView(t, f.alice), server)
	if row.System != "ubuntu" || row.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatalf("the server's row: %+v", row)
	}
	if list, _ := f.store.listServers(); list[0].Revision == stored[0].Revision && list[1].Revision == stored[1].Revision {
		t.Fatal("the record was not resealed at a new revision")
	}
	for _, body := range []string{
		inputJSON(map[string]string{"system": "windows95"}),
		inputJSON(map[string]string{"system": "Ubuntu"}),
		inputJSON(map[string]string{"system": "ubuntu", "name": "x"}),
		`{"system":1}`, `not json`,
	} {
		f.alice.expect("POST", path, body, 400)
	}
	f.alice.expect("POST", "/api/servers/"+strings.Repeat("e", 32)+"/system", inputJSON(map[string]string{"system": "debian"}), 404)
	for _, c := range []*custodyClient{bob, dave} {
		c.expect("POST", path, inputJSON(map[string]string{"system": "debian"}), 403)
	}
	if card().System != "ubuntu" {
		t.Fatal("a refused request changed the mark")
	}
	// Taking the mark away is allowed.
	f.alice.expect("POST", path, inputJSON(map[string]string{"system": ""}), 204)
	if card().System != "" {
		t.Fatal("the mark was not taken away")
	}
	_ = time.Second
}
