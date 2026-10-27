package identity

import (
	"fmt"
	"net/http"
	"net/netip"
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
	_, counted := l.attempts["login:probe-new"]
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
