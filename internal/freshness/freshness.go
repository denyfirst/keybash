// Package freshness compares the versions Keybash pins with the newest
// upstream releases, so a maintainer learns when a pin falls behind.
//
// Pins are read from the repository's own files; the newest releases come
// from fixed upstream endpoints. Only plain dotted version numbers are
// accepted from either side, and anything else fails the check instead of
// reaching the report, which a scheduled job may post as an issue. Nothing
// fetched is executed or stored.
package freshness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Source says where the newest release of a pin is looked up.
type Source string

const (
	GoToolchain   Source = "go.dev"
	GoModule      Source = "Go module proxy"
	GitHubRelease Source = "GitHub releases"
	GitHubTag     Source = "GitHub tags"
	NodeLTS       Source = "Node.js LTS"
	NPM           Source = "npm registry"
)

// Pin is one version the repository fixes.
type Pin struct {
	Name    string // shown in the report
	File    string // the repository file that pins it
	Version string // plain dotted numbers, without a "v" or "go" prefix
	Source  Source
	Key     string // module path, owner/repo or package name, per Source
}

var versionPattern = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,6}){1,3}$`)

// plainVersion strips a "go" or "v" prefix and refuses anything that is not
// two to four dotted numbers: pre-releases, build tags, Markdown, newlines.
func plainVersion(raw string) (string, error) {
	v := strings.TrimPrefix(strings.TrimPrefix(raw, "go"), "v")
	if !versionPattern.MatchString(v) {
		if len(raw) > 40 {
			raw = raw[:40]
		}
		return "", fmt.Errorf("not a plain version: %q", raw)
	}
	return v, nil
}

// Older reports whether plain version a is older than plain version b.
// Numbers are compared, not text, and a missing part counts as zero.
func Older(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(as), len(bs)) {
		if x, y := versionPart(as, i), versionPart(bs, i); x != y {
			return x < y
		}
	}
	return false
}

func versionPart(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n, _ := strconv.Atoi(parts[i]) // plainVersion allows digits only
	return n
}

// The files whose pins are watched. A workflow without a matching line is
// fine; every other expected pin must be found.
const (
	goModFile      = "go.mod"
	nativeFile     = "scripts/build-native-runtime.sh"
	ciWorkflow     = ".github/workflows/ci.yml"
	freshWorkflow  = ".github/workflows/freshness.yml"
	webPackageFile = "web/package.json"
)

var (
	goLine      = regexp.MustCompile(`(?m)^go (\S+)$`)
	requireLine = regexp.MustCompile(`(?m)^\t(\S+) (v\S+)$`)
	freeRDPURL  = regexp.MustCompile(`releases/download/([^/\s]+)/freerdp-`)
	guacamole   = regexp.MustCompile(`/guacamole/([^/\s]+)/source/guacamole-server-`)
	nodeURL     = regexp.MustCompile(`nodejs\.org/dist/v([^/\s]+)/`)
	pnpmURL     = regexp.MustCompile(`(?:/pnpm|exe\.linux-x64)-([^/\s]+)\.tgz`)
	goInstall   = regexp.MustCompile(`go install (\S+)@(v\S+)`)
)

// Pins reads every pinned version from the repository at root. A pin that
// disappears, or appears with two different versions, is an error, so the
// check cannot silently stop watching it.
func Pins(root fs.FS) ([]Pin, error) {
	var pins []Pin
	read := func(name string) (string, error) {
		b, err := fs.ReadFile(root, name)
		return string(b), err
	}
	agreed := func(file, text string, pattern *regexp.Regexp, name string, source Source, key string) error {
		matches := pattern.FindAllStringSubmatch(text, -1)
		if len(matches) == 0 {
			return fmt.Errorf("%s: no %s pin found; update the freshness check with the file", file, name)
		}
		for _, m := range matches[1:] {
			if m[1] != matches[0][1] {
				return fmt.Errorf("%s: %s is pinned twice with different versions", file, name)
			}
		}
		v, err := plainVersion(matches[0][1])
		if err != nil {
			return fmt.Errorf("%s: %s: %w", file, name, err)
		}
		pins = append(pins, Pin{Name: name, File: file, Version: v, Source: source, Key: key})
		return nil
	}

	mod, err := read(goModFile)
	if err != nil {
		return nil, err
	}
	if err := agreed(goModFile, mod, goLine, "Go", GoToolchain, "go"); err != nil {
		return nil, err
	}
	requires := requireLine.FindAllStringSubmatch(mod, -1)
	if len(requires) == 0 {
		return nil, fmt.Errorf("%s: no direct requirement found", goModFile)
	}
	for _, m := range requires {
		v, err := plainVersion(m[2])
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", goModFile, m[1], err)
		}
		pins = append(pins, Pin{Name: m[1], File: goModFile, Version: v, Source: GoModule, Key: m[1]})
	}

	native, err := read(nativeFile)
	if err != nil {
		return nil, err
	}
	if err := agreed(nativeFile, native, freeRDPURL, "FreeRDP", GitHubRelease, "FreeRDP/FreeRDP"); err != nil {
		return nil, err
	}
	if err := agreed(nativeFile, native, guacamole, "guacamole-server", GitHubTag, "apache/guacamole-server"); err != nil {
		return nil, err
	}

	ci, err := read(ciWorkflow)
	if err != nil {
		return nil, err
	}
	if err := agreed(ciWorkflow, ci, nodeURL, "Node.js", NodeLTS, "node"); err != nil {
		return nil, err
	}
	if err := agreed(ciWorkflow, ci, pnpmURL, "pnpm", NPM, "pnpm"); err != nil {
		return nil, err
	}
	for _, file := range []string{ciWorkflow, freshWorkflow} {
		text, err := read(file)
		if errors.Is(err, fs.ErrNotExist) && file != ciWorkflow {
			continue
		} else if err != nil {
			return nil, err
		}
		for _, m := range goInstall.FindAllStringSubmatch(text, -1) {
			module := m[1]
			if i := strings.Index(module, "/cmd/"); i >= 0 {
				module = module[:i]
			}
			v, err := plainVersion(m[2])
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", file, m[1], err)
			}
			pins = append(pins, Pin{Name: path.Base(m[1]), File: file, Version: v, Source: GoModule, Key: module})
		}
	}

	web, err := read(webPackageFile)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(web), &pkg); err != nil {
		return nil, fmt.Errorf("%s: %w", webPackageFile, err)
	}
	var names []string
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name := range deps {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		raw, ok := pkg.DevDependencies[name]
		if !ok {
			raw = pkg.Dependencies[name]
		}
		v, err := plainVersion(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %s must be an exact version: %w", webPackageFile, name, err)
		}
		pins = append(pins, Pin{Name: name, File: webPackageFile, Version: v, Source: NPM, Key: name})
	}
	return pins, nil
}

// Upstream holds the endpoints the check asks. DefaultUpstream gives the real
// ones; tests point them at a local server.
type Upstream struct {
	Client *http.Client
	GoDL   string // Go's list of current releases
	Proxy  string // Go module proxy
	GitHub string // GitHub REST API
	Node   string // Node.js release index
	NPM    string // npm registry
	Token  string // optional GitHub token; sent to the GitHub API only
}

func DefaultUpstream(token string) Upstream {
	return Upstream{
		Client: &http.Client{Timeout: 30 * time.Second},
		GoDL:   "https://go.dev/dl/?mode=json",
		Proxy:  "https://proxy.golang.org",
		GitHub: "https://api.github.com",
		Node:   "https://nodejs.org/dist/index.json",
		NPM:    "https://registry.npmjs.org",
		Token:  token,
	}
}

// maxAnswer bounds every upstream answer; the Node.js index is the largest.
const maxAnswer = 8 << 20

func (u Upstream) getJSON(ctx context.Context, address string, github bool, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if github {
		req.Header.Set("Accept", "application/vnd.github+json")
		if u.Token != "" {
			req.Header.Set("Authorization", "Bearer "+u.Token)
		}
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", req.URL.Host, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return err
	}
	if len(body) > maxAnswer {
		return fmt.Errorf("%s answered more than %d bytes", req.URL.Host, maxAnswer)
	}
	return json.Unmarshal(body, into)
}

// escapeModule applies the module proxy's case encoding: an upper-case
// letter becomes "!" and its lower-case form.
func escapeModule(module string) string {
	var b strings.Builder
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// highest returns the newest plain version among candidates, skipping any
// that are not plain versions (release candidates, odd tags).
func highest(candidates []string) (string, error) {
	newest := ""
	for _, c := range candidates {
		v, err := plainVersion(c)
		if err != nil {
			continue
		}
		if newest == "" || Older(newest, v) {
			newest = v
		}
	}
	if newest == "" {
		return "", errors.New("no plain version among the answers")
	}
	return newest, nil
}

// Newest asks the pin's upstream for its newest release.
func (u Upstream) Newest(ctx context.Context, pin Pin) (string, error) {
	switch pin.Source {
	case GoToolchain:
		var releases []struct {
			Version string `json:"version"`
			Stable  bool   `json:"stable"`
		}
		if err := u.getJSON(ctx, u.GoDL, false, &releases); err != nil {
			return "", err
		}
		var stable []string
		for _, r := range releases {
			if r.Stable {
				stable = append(stable, r.Version)
			}
		}
		return highest(stable)
	case GoModule:
		var info struct {
			Version string `json:"Version"`
		}
		if err := u.getJSON(ctx, u.Proxy+"/"+escapeModule(pin.Key)+"/@latest", false, &info); err != nil {
			return "", err
		}
		return plainVersion(info.Version)
	case GitHubRelease:
		var releases []struct {
			Tag        string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}
		if err := u.getJSON(ctx, u.GitHub+"/repos/"+pin.Key+"/releases?per_page=50", true, &releases); err != nil {
			return "", err
		}
		var tags []string
		for _, r := range releases {
			if !r.Draft && !r.Prerelease {
				tags = append(tags, r.Tag)
			}
		}
		return highest(tags)
	case GitHubTag:
		var tags []struct {
			Name string `json:"name"`
		}
		if err := u.getJSON(ctx, u.GitHub+"/repos/"+pin.Key+"/tags?per_page=100", true, &tags); err != nil {
			return "", err
		}
		names := make([]string, 0, len(tags))
		for _, t := range tags {
			names = append(names, t.Name)
		}
		return highest(names)
	case NodeLTS:
		var releases []struct {
			Version string `json:"version"`
			LTS     any    `json:"lts"`
		}
		if err := u.getJSON(ctx, u.Node, false, &releases); err != nil {
			return "", err
		}
		var lts []string
		for _, r := range releases {
			if name, ok := r.LTS.(string); ok && name != "" {
				lts = append(lts, r.Version)
			}
		}
		return highest(lts)
	case NPM:
		var latest struct {
			Version string `json:"version"`
		}
		if err := u.getJSON(ctx, u.NPM+"/"+url.PathEscape(pin.Key)+"/latest", false, &latest); err != nil {
			return "", err
		}
		return plainVersion(latest.Version)
	}
	return "", fmt.Errorf("unknown source %q", pin.Source)
}

// Result is one pin with its newest upstream release, or why that is unknown.
type Result struct {
	Pin
	Newest string
	Err    error
}

// Behind reports whether a newer upstream release exists.
func (r Result) Behind() bool { return r.Err == nil && Older(r.Version, r.Newest) }

// Check looks up every pin in turn.
func Check(ctx context.Context, u Upstream, pins []Pin) []Result {
	results := make([]Result, 0, len(pins))
	for _, pin := range pins {
		newest, err := u.Newest(ctx, pin)
		results = append(results, Result{Pin: pin, Newest: newest, Err: err})
	}
	return results
}

// Report writes the results as a Markdown table. Every cell is fixed text,
// a repository name or a checked plain version, and lookup errors are
// summarised without their text, so the table is safe to post as an issue.
func Report(w io.Writer, results []Result) error {
	var b strings.Builder
	b.WriteString("| Pin | File | Pinned | Newest | State |\n|---|---|---|---|---|\n")
	for _, r := range results {
		newest, state := r.Newest, "current"
		switch {
		case r.Err != nil:
			newest, state = "?", "lookup failed"
		case r.Behind():
			state = "**behind**"
		case Older(r.Newest, r.Version):
			state = "newer than upstream"
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n", r.Name, r.File, r.Version, newest, state)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
