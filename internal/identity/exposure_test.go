package identity

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestOriginsAreExactForLoopbackAndExposedLabs(t *testing.T) {
	// {as a loopback origin, as an exposed origin}
	for origin, want := range map[string][2]bool{
		"https://127.0.0.1:8443":               {true, false},
		"https://[::1]:8443":                   {true, false},
		"https://192.168.1.10:8443":            {false, true},
		"https://[fd00:1::10]:8443":            {false, true},
		"https://keybash.lan:8443":             {false, true},
		"https://keybash:8443":                 {false, true},
		"https://xn--bcher-kva.lan:8443":       {false, true},
		"https://Keybash.lan:8443":             {false, false},
		"https://localhost:8443":               {false, false},
		"https://vault.localhost:8443":         {false, false},
		"https://10.1:8443":                    {false, false},
		"https://1.2.3.4.5:8443":               {false, false},
		"https://keybash.lan.:8443":            {false, false},
		"https://-keybash.lan:8443":            {false, false},
		"https://keybash_lan:8443":             {false, false},
		"https://keybash.lan":                  {false, false},
		"https://keybash.lan:0":                {false, false},
		"https://keybash.lan:08443":            {false, false},
		"http://keybash.lan:8443":              {false, false},
		"https://keybash.lan:8443/":            {false, false},
		"https://user@keybash.lan:8443":        {false, false},
		"https://169.254.1.1:8443":             {false, false},
		"https://0.0.0.0:8443":                 {false, false},
		"https://224.0.0.1:8443":               {false, false},
		"https://[::ffff:192.168.1.10]:8443":   {false, false},
		"https://[fe80::1%25eth0]:8443":        {false, false},
		"https://[FD00:1::10]:8443":            {false, false},
		"https://192.168.001.010:8443":         {false, false},
		"https://keybash.lan:8443?next=/vault": {false, false},
	} {
		for i, exposed := range []bool{false, true} {
			if _, ok := originHost(origin, exposed); ok != want[i] {
				t.Fatalf("%s exposed=%v accepted=%v", origin, exposed, ok)
			}
		}
	}
}

func TestExposedLabAdmitsOnlyListedNetworks(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	for name, build := range map[string]func() (*Lab, error){
		"loopback-exposed": func() (*Lab, error) { return NewLab("https://127.0.0.1:8443", accounts(t), FromSources(lan)) },
		"named-unexposed":  func() (*Lab, error) { return NewLab("https://keybash.lan:8443", accounts(t)) },
		"no-networks":      func() (*Lab, error) { return NewLab("https://keybash.lan:8443", accounts(t), FromSources(nil)) },
		"unmasked": func() (*Lab, error) {
			return NewLab("https://keybash.lan:8443", accounts(t), FromSources([]netip.Prefix{netip.MustParsePrefix("192.168.1.7/24")}))
		},
		"everything": func() (*Lab, error) {
			return NewLab("https://keybash.lan:8443", accounts(t), FromSources([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}))
		},
		"twice": func() (*Lab, error) {
			return NewLab("https://keybash.lan:8443", accounts(t), FromSources(lan), FromSources(lan))
		},
		"nil-option": func() (*Lab, error) { return NewLab("https://keybash.lan:8443", accounts(t), nil) },
	} {
		if l, e := build(); e == nil {
			_ = l.Close()
			t.Fatalf("%s lab accepted", name)
		}
	}
	l, e := NewLab("https://keybash.lan:8443", accounts(t), FromSources(lan))
	if e != nil {
		t.Fatal("valid exposed lab refused")
	}
	defer l.Close()
	from := func(l *Lab, addr string) *http.Request {
		r := request(l, "GET", "/", "", "")
		r.RemoteAddr = addr
		return r
	}
	for addr, admitted := range map[string]bool{
		"192.168.1.7:50000":          true,
		"[::ffff:192.168.1.7]:50000": true,
		"192.168.2.7:50000":          false,
		"127.0.0.1:50000":            false,
		"[fd00:1::7]:50000":          false,
		"192.168.1.7":                false,
	} {
		w := respond(l, from(l, addr))
		if (w.Code != http.StatusForbidden) != admitted {
			t.Fatalf("client %s admitted=%v", addr, !admitted)
		}
		if w.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
			t.Fatal("exposed lab sent no HSTS")
		}
	}
	// Another name for the same address (DNS rebinding) is refused.
	other := from(l, "192.168.1.7:50000")
	other.Host = "192.168.1.10:8443"
	if respond(l, other).Code != http.StatusForbidden {
		t.Fatal("a request for another host name was admitted")
	}
	loopback, e := NewLab("https://127.0.0.1:8443", accounts(t))
	if e != nil {
		t.Fatal("loopback lab refused")
	}
	defer loopback.Close()
	if respond(loopback, from(loopback, "192.168.1.7:50000")).Code != http.StatusForbidden || respond(loopback, from(loopback, "127.0.0.1:50000")).Code == http.StatusForbidden {
		t.Fatal("a loopback lab admitted a LAN client or refused a local one")
	}
}

// One source spending a name's budget does not keep its holder from signing in
// from another source, and the name's ceiling across sources still holds, for
// registered and unknown names alike.
func TestExposedLoginBudgetIsPerNameAndSource(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	l, e := NewLab("https://keybash.lan:8443", accounts(t), FromSources(lan))
	if e != nil {
		t.Fatal("valid exposed lab refused")
	}
	defer l.Close()
	login := func(addr, username, password string) int {
		r := request(l, "POST", "/api/session", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), "")
		r.RemoteAddr = addr
		return respond(l, r).Code
	}
	for _, name := range []string{"alice", "nobody"} {
		for i := range loginAttempts {
			if code := login("192.168.1.7:50000", name, bobPassword); code != http.StatusUnauthorized {
				t.Fatalf("%s attempt %d from one source answered %d", name, i, code)
			}
		}
		if login("192.168.1.7:50001", name, bobPassword) != http.StatusTooManyRequests {
			t.Fatalf("one source passed five attempts at %s", name)
		}
	}
	if login("192.168.1.8:50000", "alice", alicePassword) != http.StatusNoContent {
		t.Fatal("one source's failures kept alice from signing in from another")
	}
	// Six attempts used on each name so far (alice's sixth succeeded); the
	// ceiling across sources allows 30, then refuses every source.
	for _, name := range []string{"alice", "nobody"} {
		used := loginAttempts + 1
		if name == "nobody" {
			used = loginAttempts
		}
		for source := 20; used < loginNameAttempts; source++ {
			for i := 0; i < loginAttempts && used < loginNameAttempts; i++ {
				if code := login(fmt.Sprintf("192.168.1.%d:50000", source), name, bobPassword); code != http.StatusUnauthorized {
					t.Fatalf("%s attempt %d answered %d", name, used, code)
				}
				used++
			}
		}
		if login("192.168.1.200:50000", name, alicePassword) != http.StatusTooManyRequests {
			t.Fatalf("%s passed its ceiling across sources", name)
		}
	}
}

func TestExposedLoginCountsPerSource(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	l, e := NewLab("https://keybash.lan:8443", accounts(t), FromSources(lan))
	if e != nil {
		t.Fatal("valid exposed lab refused")
	}
	defer l.Close()
	login := func(l *Lab, addr, username, password string) int {
		r := request(l, "POST", "/api/session", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), "")
		r.RemoteAddr = addr
		return respond(l, r).Code
	}
	// Each name stays under its own budget; the source runs out after 30.
	for i := range 30 {
		if code := login(l, "192.168.1.7:50000", fmt.Sprint("probe-", i), bobPassword); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d from one source answered %d", i, code)
		}
	}
	if login(l, "192.168.1.7:50001", "probe-new", bobPassword) != http.StatusTooManyRequests || login(l, "192.168.1.7:50002", "alice", alicePassword) != http.StatusTooManyRequests {
		t.Fatal("a source beyond its budget could still try passwords")
	}
	l.mu.Lock()
	counted := false
	for key := range l.attempts {
		counted = counted || strings.HasPrefix(key, "login:probe-new")
	}
	l.mu.Unlock()
	if counted {
		t.Fatal("a refused source still created a per-name counter")
	}
	if login(l, "192.168.1.8:50000", "alice", alicePassword) != http.StatusNoContent {
		t.Fatal("one source's failures locked out another")
	}
	// A loopback lab has one shared source and counts only per name.
	loopback, e := NewLab("https://127.0.0.1:8443", accounts(t))
	if e != nil {
		t.Fatal("loopback lab refused")
	}
	defer loopback.Close()
	for i := range 31 {
		if code := login(loopback, "127.0.0.1:50000", fmt.Sprint("probe-", i), bobPassword); code != http.StatusUnauthorized {
			t.Fatalf("loopback attempt %d answered %d", i, code)
		}
	}
}
