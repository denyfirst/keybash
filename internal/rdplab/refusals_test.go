package rdplab

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

// proxyEndOf has the proxy end a stream with one Ended frame of payload and
// returns what the gateway made of it.
func proxyEndOf(t *testing.T, payload []byte) (terminalweb.Reason, terminalweb.Refusal, bool) {
	t.Helper()
	s, worker := proxyPair(t)
	go func() { _ = writeProxyFrame(worker, proxyEnded, payload) }()
	if _, err := s.ReadMessage(); err == nil {
		t.Fatalf("%v: an end was read as a message", payload)
	}
	refusal, refused := s.Refusal()
	return s.Reason(), refusal, refused
}

// A refusal is the end code 5, the side and what, each named with the
// proxy's own words; an end that is not a refusal names none.
func TestProxyStreamNamesTheProxysRefusal(t *testing.T) {
	for _, c := range []struct {
		payload []byte
		want    terminalweb.Refusal
	}{
		{[]byte{5, 2, 31}, terminalweb.Refusal{Side: "windows", What: "clipboard format list"}},
		{[]byte{5, 1, 1}, terminalweb.Refusal{Side: "browser", What: "PDU framing"}},
		{[]byte{5, 1, 58}, terminalweb.Refusal{Side: "browser", What: "handshake too slow"}},
		{[]byte{5, 2, 55}, terminalweb.Refusal{Side: "windows", What: "certificate or TLS"}},
		{[]byte{5, 3, 62}, terminalweb.Refusal{Side: "keybash", What: "proxy internal"}},
	} {
		reason, refusal, refused := proxyEndOf(t, c.payload)
		if reason != terminalweb.ReasonRefused || !refused || refusal != c.want {
			t.Errorf("%v: %q %+v %v, want %+v", c.payload, reason, refusal, refused, c.want)
		}
	}
	for code, want := range map[byte]terminalweb.Reason{1: terminalweb.ReasonCredentials, 3: terminalweb.ReasonUnreachable, 6: terminalweb.ReasonRemoteEnded} {
		reason, refusal, refused := proxyEndOf(t, []byte{code})
		if reason != want || refused || refusal != (terminalweb.Refusal{}) {
			t.Errorf("end %d: %q %+v %v", code, reason, refusal, refused)
		}
	}
}

// An end the gateway cannot read is the proxy's own fault: refused, named
// as a proxy frame, whatever it held. That includes a refusal without its
// codes, one with a byte too many, the retired certificate code 4, a
// non-refusal with codes, and an end as long as a frame may be.
func TestProxyStreamRefusesAnEndItCannotRead(t *testing.T) {
	long := append([]byte{5, 2, 31}, make([]byte, proxyMaxPayload-3)...)
	for name, payload := range map[string][]byte{
		"empty":                     {},
		"a refusal with no codes":   {5},
		"a refusal with one code":   {5, 2},
		"a refusal with four bytes": {5, 2, 31, 0},
		"the retired code 4":        {4},
		"an unknown end":            {200},
		"an end with codes":         {6, 2, 31},
		"an end of 64 KiB":          long,
	} {
		reason, refusal, refused := proxyEndOf(t, payload)
		if reason != terminalweb.ReasonRefused || !refused || refusal != proxyFrameRefused {
			t.Errorf("%s: %q %+v %v", name, reason, refusal, refused)
		}
	}
	// A frame the proxy never sends, or a malformed one, is the same.
	for name, frame := range map[string][]byte{
		"setup back":     {proxySetup, 0, 0, 0, 0},
		"empty desktop":  {proxyDesktop, 0, 0, 0, 0},
		"malformed type": {7, 0, 0, 0, 0},
		"cut short":      {proxyEnded, 3, 0, 0, 0, 5},
	} {
		s, worker := proxyPair(t)
		go func() { _, _ = worker.Write(frame); _ = worker.Close() }()
		_, _ = s.ReadMessage()
		if refusal, refused := s.Refusal(); !refused || refusal != proxyFrameRefused {
			t.Errorf("%s: %+v %v", name, refusal, refused)
		}
	}
}

// A code outside the lists is "unknown"; no byte the proxy sends becomes
// text, so an Ended frame holding a clipboard's text, a password or an
// address yields only fixed words.
func TestProxyStreamNamesUnknownCodesUnknownAndNeverEchoes(t *testing.T) {
	for _, c := range []struct {
		payload    []byte
		side, what string
	}{
		{[]byte{5, 0, 31}, "unknown", "clipboard format list"},
		{[]byte{5, 4, 31}, "unknown", "clipboard format list"},
		{[]byte{5, 2, 0}, "windows", "unknown"},
		{[]byte{5, 2, 63}, "windows", "unknown"},
		{[]byte{5, 255, 255}, "unknown", "unknown"},
	} {
		_, refusal, refused := proxyEndOf(t, c.payload)
		if !refused || refusal.Side != c.side || refusal.What != c.what {
			t.Errorf("%v: %+v", c.payload, refusal)
		}
	}
	for _, secret := range []string{"Synthetic clipboard text", "Synthetic remote password", "10.34.0.8", "5\x02\x1f"} {
		_, refusal, _ := proxyEndOf(t, []byte(secret))
		if line := refusal.Line(); strings.Contains(line, secret) || refusal != proxyFrameRefused {
			t.Errorf("%q came through as %+v: %q", secret, refusal, line)
		}
	}
}

// Every word is one the journal line takes as it is, and no two codes share
// a word.
func TestProxyRefusalWordsAreJournalWords(t *testing.T) {
	seen := map[string]bool{}
	for code, word := range proxyRefusals {
		r := terminalweb.Refusal{Side: "windows", What: word}
		if code == 0 || seen[word] || !strings.Contains(r.Line(), `"`+word+`"`) {
			t.Errorf("%d %q", code, word)
		}
		seen[word] = true
	}
	for _, side := range proxySides {
		if !strings.Contains((terminalweb.Refusal{Side: side, What: "x"}).Line(), "side="+side+" ") {
			t.Errorf("side %q", side)
		}
	}
}

// The words are the proxy's own, code for code: this reads
// rdp-proxy/src/refusal.rs and compares both lists both ways.
func TestProxyRefusalWordsMatchTheProxy(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "rdp-proxy", "src", "refusal.rs"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	refusal := regexp.MustCompile(`^    [A-Z]\w* = (\d+) => "([^"\\]+)",$`)
	side := regexp.MustCompile(`^    ([A-Z]\w*) = (\d+),$`)
	refusals, sides := map[byte]string{}, map[byte]string{}
	inSide := false
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		line := lines.Text()
		switch {
		case line == "pub enum Side {":
			inSide = true
		case inSide && line == "}":
			inSide = false
		case inSide && side.MatchString(line):
			m := side.FindStringSubmatch(line)
			sides[code(t, m[2])] = strings.ToLower(m[1])
		case refusal.MatchString(line):
			m := refusal.FindStringSubmatch(line)
			if _, twice := refusals[code(t, m[1])]; twice {
				t.Fatalf("code %s twice", m[1])
			}
			refusals[code(t, m[1])] = m[2]
		}
	}
	if lines.Err() != nil || len(refusals) == 0 || len(sides) == 0 {
		t.Fatalf("read %d refusals and %d sides: %v", len(refusals), len(sides), lines.Err())
	}
	for name, lists := range map[string][2]map[byte]string{"refusals": {refusals, proxyRefusals}, "sides": {sides, proxySides}} {
		proxy, gateway := lists[0], lists[1]
		for c, word := range proxy {
			if gateway[c] != word {
				t.Errorf("%s: the proxy's %d is %q, the gateway's %q", name, c, word, gateway[c])
			}
		}
		for c, word := range gateway {
			if proxy[c] != word {
				t.Errorf("%s: the gateway's %d is %q, the proxy's %q", name, c, word, proxy[c])
			}
		}
	}
}

func code(t *testing.T, s string) byte {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		t.Fatal(err)
	}
	return byte(n)
}
