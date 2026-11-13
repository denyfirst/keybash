package freshness

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

func TestPinsFromTheRepository(t *testing.T) {
	pins, err := Pins(os.DirFS("../.."))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]Pin{}
	for _, p := range pins {
		if _, err := plainVersion(p.Version); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		found[p.Name] = p
	}
	for _, name := range []string{"Go", "golang.org/x/crypto", "golang.org/x/sys", "go.etcd.io/bbolt",
		"FreeRDP", "guacamole-server", "Node.js", "pnpm", "staticcheck", "gosec", "govulncheck",
		"actionlint", "playwright", "@xterm/xterm", "@xterm/addon-webgl"} {
		if _, ok := found[name]; !ok {
			t.Errorf("the check no longer watches %s", name)
		}
	}
	if got := found["staticcheck"].Key; got != "honnef.co/go/tools" {
		t.Errorf("staticcheck is looked up as %q, want its module", got)
	}
}

func repo() fstest.MapFS {
	return fstest.MapFS{
		"go.mod": {Data: []byte("module example\n\ngo 1.27.4\n\nrequire (\n\tgolang.org/x/crypto v0.59.0\n\tgolang.org/x/text v0.44.0 // indirect\n)\n")},
		"scripts/build-native-runtime.sh": {Data: []byte("https://github.com/FreeRDP/FreeRDP/releases/download/3.33.1/freerdp-3.33.1.tar.gz\n" +
			"https://archive.apache.org/dist/guacamole/1.6.0/source/guacamole-server-1.6.0.tar.gz\n" +
			"https://downloads.apache.org/guacamole/1.6.0/source/guacamole-server-1.6.0.tar.gz\n")},
		".github/workflows/ci.yml": {Data: []byte("https://nodejs.org/dist/v26.13.1/node-v26.13.1-linux-x64.tar.xz\n" +
			"https://registry.npmjs.org/@pnpm/exe.linux-x64/-/exe.linux-x64-12.18.0.tgz\n" +
			"          # `go install tool@version` reads the tool's go.mod\n" +
			"          go install honnef.co/go/tools/cmd/staticcheck@v0.8.2\n")},
		"web/package.json": {Data: []byte(`{"devDependencies": {"playwright": "1.65.0"}}`)},
	}
}

func TestPinsRefuseAFileWhoseFormatChanged(t *testing.T) {
	pins, err := Pins(repo())
	if err != nil || len(pins) != 8 {
		t.Fatalf("pins %+v, %v", pins, err)
	}
	for _, p := range pins {
		if p.Name == "golang.org/x/text" {
			t.Fatal("an indirect requirement is watched")
		}
	}
	for name, change := range map[string]func(fstest.MapFS){
		"Node.js URL gone": func(f fstest.MapFS) {
			f[".github/workflows/ci.yml"].Data = bytes.Replace(f[".github/workflows/ci.yml"].Data, []byte("nodejs.org"), []byte("example.org"), 1)
		},
		"two guacamole versions": func(f fstest.MapFS) {
			f["scripts/build-native-runtime.sh"].Data = bytes.Replace(f["scripts/build-native-runtime.sh"].Data, []byte("guacamole/1.6.0/source"), []byte("guacamole/1.6.1/source"), 1)
		},
		"pre-release pin": func(f fstest.MapFS) {
			f["go.mod"].Data = bytes.Replace(f["go.mod"].Data, []byte("v0.59.0"), []byte("v0.60.0-rc.1"), 1)
		},
		"range in package.json": func(f fstest.MapFS) {
			f["web/package.json"].Data = []byte(`{"devDependencies": {"playwright": "^1.65.0"}}`)
		},
		"no go line": func(f fstest.MapFS) {
			f["go.mod"].Data = bytes.Replace(f["go.mod"].Data, []byte("go 1.27.4"), nil, 1)
		},
	} {
		f := repo()
		change(f)
		if _, err := Pins(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOlderComparesNumbersNotText(t *testing.T) {
	for _, c := range []struct {
		a, b  string
		older bool
	}{
		{"1.9", "1.10", true}, {"1.10", "1.9", false}, {"1.27.4", "1.27.4", false},
		{"3.33", "3.33.1", true}, {"3.33.1", "3.33", false}, {"3.33.0", "3.33", false},
		{"0.8.2", "0.59.0", true}, {"24.22.3", "26.13.1", true}, {"2.30.0", "2.28.0", false},
	} {
		if got := Older(c.a, c.b); got != c.older {
			t.Errorf("Older(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestPlainVersionRefusesEverythingElse(t *testing.T) {
	for _, ok := range []string{"go1.27.4", "v0.59.0", "3.33.1", "1.6", "v26.13.1"} {
		if _, err := plainVersion(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "1", "v", "1.2.3-rc.1", "1.2.3+build", "1.2.3.4.5", "1.2.3\n| x |",
		"1.2.3](https://example.com)", "<script>", "1. 2", "１.２", "1234567.1"} {
		if _, err := plainVersion(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEscapeModuleUsesTheProxyCaseEncoding(t *testing.T) {
	if got := escapeModule("github.com/BurntSushi/toml"); got != "github.com/!burnt!sushi/toml" {
		t.Fatal(got)
	}
}

// fakeUpstream answers like the real endpoints and records which requests
// carried the GitHub token.
func fakeUpstream(t *testing.T, answers map[string]string) (Upstream, map[string]string) {
	t.Helper()
	var mu sync.Mutex
	tokens := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokens[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		body, ok := answers[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return Upstream{Client: srv.Client(), GoDL: srv.URL + "/dl", Proxy: srv.URL + "/proxy",
		GitHub: srv.URL + "/gh", Node: srv.URL + "/node/index.json", NPM: srv.URL + "/npm", Token: "t"}, tokens
}

func TestCheckAgainstAFakeUpstream(t *testing.T) {
	u, tokens := fakeUpstream(t, map[string]string{
		"/dl": `[{"version":"go1.28rc1","stable":false},{"version":"go1.26.12","stable":true},{"version":"go1.27.5","stable":true}]`,
		"/proxy/github.com/!burnt!sushi/toml/@latest": `{"Version":"v1.6.0"}`,
		"/gh/repos/FreeRDP/FreeRDP/releases":          `[{"tag_name":"3.34.0","prerelease":true},{"tag_name":"2.11.9"},{"tag_name":"3.33.1"}]`,
		"/gh/repos/apache/guacamole-server/tags":      `[{"name":"1.7.0-RC1"},{"name":"1.5.5"},{"name":"1.6.0"}]`,
		"/node/index.json":                            `[{"version":"v27.1.0","lts":false},{"version":"v24.22.3","lts":"Krypton"},{"version":"v26.13.2","lts":"Lithium"}]`,
		"/npm/@xterm%2Fxterm/latest":                  `{"version":"6.0.0"}`,
	})
	pins := []Pin{
		{Name: "Go", Version: "1.27.4", Source: GoToolchain},
		{Name: "toml", Version: "1.6.0", Source: GoModule, Key: "github.com/BurntSushi/toml"},
		{Name: "FreeRDP", Version: "3.33.1", Source: GitHubRelease, Key: "FreeRDP/FreeRDP"},
		{Name: "guacamole-server", Version: "1.5.5", Source: GitHubTag, Key: "apache/guacamole-server"},
		{Name: "Node.js", Version: "26.13.1", Source: NodeLTS},
		{Name: "@xterm/xterm", Version: "6.0.0", Source: NPM, Key: "@xterm/xterm"},
	}
	want := map[string]struct {
		newest string
		behind bool
	}{
		"Go": {"1.27.5", true}, "toml": {"1.6.0", false}, "FreeRDP": {"3.33.1", false},
		"guacamole-server": {"1.6.0", true}, "Node.js": {"26.13.2", true}, "@xterm/xterm": {"6.0.0", false},
	}
	for _, r := range Check(context.Background(), u, pins) {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Name, r.Err)
		}
		if w := want[r.Name]; r.Newest != w.newest || r.Behind() != w.behind {
			t.Errorf("%s: newest %s behind %v, want %s %v", r.Name, r.Newest, r.Behind(), w.newest, w.behind)
		}
	}
	for p, token := range tokens {
		if github := strings.HasPrefix(p, "/gh/"); github != (token == "Bearer t") {
			t.Errorf("%s: Authorization %q", p, token)
		}
	}
}

func TestUpstreamAnswersAreOnlyPlainVersions(t *testing.T) {
	hostile := []string{`"1.2.3](https://example.com)"`, `"1.2.3\n| injected |"`, `"<img src=x>"`, `""`, `null`, `42`}
	for _, answer := range hostile {
		u, _ := fakeUpstream(t, map[string]string{"/npm/pnpm/latest": `{"version":` + answer + `}`})
		results := Check(context.Background(), u, []Pin{{Name: "pnpm", File: "x", Version: "12.18.0", Source: NPM, Key: "pnpm"}})
		if results[0].Err == nil {
			t.Errorf("%s accepted as %q", answer, results[0].Newest)
		}
		var report strings.Builder
		if err := Report(&report, results); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(report.String(), "example.com") || strings.Contains(report.String(), "injected") ||
			strings.Contains(report.String(), "<img") || !strings.Contains(report.String(), "lookup failed") {
			t.Errorf("%s reached the report:\n%s", answer, report.String())
		}
	}
}

func TestUpstreamRefusesErrorsAndOversizedAnswers(t *testing.T) {
	// Each answer below is valid JSON with a plain version, so only the
	// status or size rule can refuse it. The oversized one is a complete
	// object padded with spaces: cut at the limit, it would still parse.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/npm/big/latest":
			_, _ = w.Write([]byte(`{"version":"1.2.3"}` + strings.Repeat(" ", maxAnswer)))
		case "/npm/fits/latest":
			_, _ = w.Write([]byte(`{"version":"1.2.3"}` + strings.Repeat(" ", maxAnswer-len(`{"version":"1.2.3"}`))))
		case "/npm/error/latest":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"version":"1.2.3"}`))
		case "/npm/moved/latest":
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			_, _ = w.Write([]byte(`{"version":"1.2.3"}`))
		}
	}))
	t.Cleanup(srv.Close)
	u := Upstream{Client: srv.Client(), NPM: srv.URL + "/npm"}
	for _, key := range []string{"big", "error", "moved"} {
		if v, err := u.Newest(context.Background(), Pin{Source: NPM, Key: key}); err == nil {
			t.Errorf("%s: accepted %q", key, v)
		}
	}
	if v, err := u.Newest(context.Background(), Pin{Source: NPM, Key: "fits"}); err != nil || v != "1.2.3" {
		t.Errorf("an answer of exactly the limit: %q, %v", v, err)
	}
}

func TestReportMarksOnlyBehindPins(t *testing.T) {
	var out strings.Builder
	err := Report(&out, []Result{
		{Pin: Pin{Name: "a", File: "f", Version: "1.2.3"}, Newest: "1.2.3"},
		{Pin: Pin{Name: "b", File: "f", Version: "1.2.3"}, Newest: "1.3.0"},
		{Pin: Pin{Name: "c", File: "f", Version: "1.2.3"}, Newest: "1.2.0"},
		{Pin: Pin{Name: "d", File: "f", Version: "1.2.3"}, Err: context.DeadlineExceeded},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"| a | `f` | 1.2.3 | 1.2.3 | current |",
		"| b | `f` | 1.2.3 | 1.3.0 | **behind** |",
		"| c | `f` | 1.2.3 | 1.2.0 | newer than upstream |",
		"| d | `f` | 1.2.3 | ? | lookup failed |",
	} {
		if !strings.Contains(out.String(), line+"\n") {
			t.Errorf("missing %q in\n%s", line, out.String())
		}
	}
	if strings.Contains(out.String(), "deadline") {
		t.Error("error text reached the report")
	}
}
