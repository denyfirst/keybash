package web

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// fontSHA256 is the typeface Porch chose and pinned: Schibsted Grotesk, the
// variable Latin subset from @fontsource-variable/schibsted-grotesk 5.3.0. A
// font is a program a browser parses, so a different file is a decision
// somebody writes down here, never a side effect.
const fontSHA256 = "4c8b93f431d462c696e12b9d6a033feb3394d36e66e781357c496b95d8a75e05"

var sheets = []string{"keybash.css", "auth.css", "custody.css", "style.css", "desktop.css"}

func sheet(t *testing.T, name string) string {
	t.Helper()
	data, err := Assets.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

func TestTheTypefaceIsTheOneChosenAndCarriesItsLicence(t *testing.T) {
	body, err := Assets.ReadFile(strings.TrimPrefix(FontPath, "/"))
	if err != nil {
		t.Fatalf("reading the typeface: %v", err)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != fontSHA256 {
		t.Errorf("the typeface is not the file that was chosen: sha256 %x", sum)
	}
	licence, err := os.ReadFile("../docs/third-party/schibsted-grotesk-LICENSE.txt")
	if err != nil {
		t.Fatalf("the typeface's licence is missing: %v", err)
	}
	for _, want := range []string{"SIL OPEN FONT LICENSE Version 1.1", "Copyright 2023 The Schibsted-Grotesk Project Authors"} {
		if !strings.Contains(string(licence), want) {
			t.Errorf("the typeface's licence does not say %q", want)
		}
	}
	// One face, from this server; no stylesheet loads anything else.
	shared := sheet(t, "keybash.css")
	if n := strings.Count(shared, "@font-face"); n != 1 {
		t.Errorf("keybash.css declares %d faces, not one", n)
	}
	for _, name := range sheets {
		urls := regexp.MustCompile(`url\(([^)]*)\)`).FindAllStringSubmatch(sheet(t, name), -1)
		for _, u := range urls {
			if name != "keybash.css" || u[1] != `"`+FontPath+`"` {
				t.Errorf("%s loads %s; only keybash.css may load the typeface, from this server", name, u[1])
			}
		}
		if strings.Contains(sheet(t, name), "@import") {
			t.Errorf("%s imports another stylesheet", name)
		}
	}
}

// Every page that is drawn loads the shared sheet and the typeface preload,
// so no page falls back to whatever the system draws.
func TestEveryPageLoadsTheSharedDesign(t *testing.T) {
	for _, page := range []string{"index.html", "desktop.html", "auth-login.html", "auth-workspace.html", "custody-login.html", "custody-workspace.html"} {
		html := sheet(t, page)
		if !strings.Contains(html, `href="/keybash.css"`) || !strings.Contains(html, `href="`+FontPath+`" as="font"`) {
			t.Errorf("%s does not load the shared design", page)
		}
		if strings.Contains(html, "style=") || strings.Contains(html, "<style") {
			t.Errorf("%s carries inline styles", page)
		}
	}
}

// The ratio text needs at the sizes these pages use. Nothing is set at a size
// where the large-text allowance would apply.
const readableContrast = 4.5

var (
	tokenPattern      = regexp.MustCompile(`--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;`)
	textColourPattern = regexp.MustCompile(`(?m)(?:^|[;{\s])color:\s*var\(--([a-z-]+)\)`)
)

func relativeLuminance(hex string) float64 {
	channel := func(offset int) float64 {
		v, _ := strconv.ParseInt(hex[offset:offset+2], 16, 32)
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	hex = strings.TrimPrefix(hex, "#")
	return 0.2126*channel(0) + 0.7152*channel(2) + 0.0722*channel(4)
}

func contrast(a, b string) float64 {
	la, lb := relativeLuminance(a), relativeLuminance(b)
	return (math.Max(la, lb) + 0.05) / (math.Min(la, lb) + 0.05)
}

// schemes returns each scheme's tokens: the dark one is the light one with the
// dark block's overrides applied, as a browser resolves it.
func schemes(t *testing.T) map[string]map[string]string {
	t.Helper()
	shared := sheet(t, "keybash.css")
	block := func(from string) string {
		start := strings.Index(shared, from)
		if start < 0 {
			t.Fatalf("keybash.css has no %q block", from)
		}
		rest := shared[start:]
		end := strings.Index(rest, "\n}")
		if end < 0 {
			t.Fatalf("the %q block is not closed", from)
		}
		return rest[:end]
	}
	parse := func(text string) map[string]string {
		found := map[string]string{}
		for _, m := range tokenPattern.FindAllStringSubmatch(text, -1) {
			found[m[1]] = strings.ToLower(m[2])
		}
		return found
	}
	light := parse(block(":root {"))
	if len(light) < 12 {
		t.Fatalf("only %d colour tokens were found", len(light))
	}
	dark := map[string]string{}
	for k, v := range light {
		dark[k] = v
	}
	for k, v := range parse(block("@media screen and (prefers-color-scheme: dark)")) {
		dark[k] = v
	}
	return map[string]map[string]string{"light": light, "dark": dark}
}

func TestEveryColourTextIsSetInIsLegible(t *testing.T) {
	tables := schemes(t)
	used := map[string]bool{}
	for _, name := range sheets {
		for _, m := range textColourPattern.FindAllStringSubmatch(sheet(t, name), -1) {
			used[m[1]] = true
		}
	}
	if len(used) < 8 {
		t.Fatalf("only %d text colours were found, which is too few to be right", len(used))
	}
	for _, scheme := range []string{"light", "dark"} {
		tokens := tables[scheme]
		for token := range used {
			value, ok := tokens[token]
			if !ok {
				t.Errorf("%s: text is set in --%s, which is not defined", scheme, token)
				continue
			}
			// The one inversion: a busy button prints the paper on soft ink.
			if token == "paper" {
				if got := contrast(value, tokens["ink-soft"]); got < readableContrast {
					t.Errorf("%s: --paper on --ink-soft is %.2f:1", scheme, got)
				}
				continue
			}
			on := []string{"paper", "paper-sunk", "card"}
			// The session panel is dark in both schemes; its text is checked on it.
			if strings.HasPrefix(token, "term-") {
				on = []string{"term-bg", "term-bar"}
			}
			for _, surface := range on {
				if got := contrast(value, tokens[surface]); got < readableContrast {
					t.Errorf("%s: --%s (%s) on --%s (%s) is %.2f:1, below %.1f:1", scheme, token, value, surface, tokens[surface], got, readableContrast)
				}
			}
		}
		// Button labels are white on the accent, resting and hovered.
		for _, face := range []string{"accent", "accent-hover"} {
			if got := contrast("#ffffff", tokens[face]); got < readableContrast {
				t.Errorf("%s: white on --%s is %.2f:1", scheme, face, got)
			}
		}
	}
}

// The rule colour draws lines and is never text; it is below the threshold on
// purpose, so a word set in it would be unreadable.
func TestTheRuleColourIsNeverUsedForText(t *testing.T) {
	for _, name := range sheets {
		for _, m := range textColourPattern.FindAllStringSubmatch(sheet(t, name), -1) {
			if m[1] == "rule" || m[1] == "edge" || m[1] == "term-rule" {
				t.Errorf("%s sets text in --%s, a line colour", name, m[1])
			}
		}
	}
	for scheme, tokens := range schemes(t) {
		if got := contrast(tokens["rule"], tokens["paper"]); got >= readableContrast {
			t.Errorf("%s: --rule is %.2f:1 against paper; if it is dark enough for text, drop this exception", scheme, got)
		}
	}
}

// Keybash's colour is not a verdict's: verified, unverified and changed are
// said in green, amber and red, and no control may look like one of them.
func TestTheToolColourIsNeverAVerdictColour(t *testing.T) {
	for scheme, tokens := range schemes(t) {
		for _, control := range []string{"tool", "link", "accent", "accent-hover"} {
			for _, verdict := range []string{"strong", "weak", "insecure", "brand"} {
				if tokens[control] == tokens[verdict] {
					t.Errorf("%s: --%s is the same colour as --%s", scheme, control, verdict)
				}
			}
		}
	}
}

// Nothing rests faded: a state is said in words and colour, not opacity.
func TestNoRestingStateIsFadedOut(t *testing.T) {
	// 0, 0.4, .4 and 40% alike; only 1 or 100% is a resting state.
	faded := regexp.MustCompile(`opacity:\s*(0?\.\d+|0|\d{1,2}(?:\.\d+)?%)\s*[;}!]`)
	for _, name := range sheets {
		for _, m := range faded.FindAllStringSubmatch(sheet(t, name), -1) {
			t.Errorf("%s fades a resting state to opacity %s", name, m[1])
		}
	}
}

func TestTheContrastArithmeticIsRight(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want float64
	}{{"#000000", "#ffffff", 21}, {"#ffffff", "#ffffff", 1}, {"#777777", "#ffffff", 4.48}, {"#767676", "#ffffff", 4.54}} {
		if got := contrast(c.a, c.b); math.Abs(got-c.want) > 0.01 {
			t.Errorf("contrast(%s, %s) = %.2f, want %.2f", c.a, c.b, got, c.want)
		}
	}
}
