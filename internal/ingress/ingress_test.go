package ingress

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseSourcesIsExactAndBounded(t *testing.T) {
	sources, e := ParseSources("192.168.1.0/24,10.8.0.0/16,fd00:1::/64")
	if e != nil || len(sources) != 3 || sources[2] != netip.MustParsePrefix("fd00:1::/64") {
		t.Fatal("valid networks refused")
	}
	var many []string
	for i := range MaxSources {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16).String())
	}
	if _, e := ParseSources(strings.Join(many, ",")); e != nil {
		t.Fatal("the maximum number of networks refused")
	}
	for name, list := range map[string]string{
		"empty":       "",
		"empty-item":  "192.168.1.0/24,",
		"host-bits":   "192.168.1.1/24",
		"no-length":   "192.168.1.0",
		"everything":  "0.0.0.0/0",
		"everything6": "::/0",
		"loopback":    "127.0.0.0/8",
		"loopback6":   "::1/128",
		"unspecified": "0.0.0.0/8",
		"mapped":      "::ffff:192.168.1.0/120",
		"zone":        "fe80::%eth0/64",
		"duplicate":   "192.168.1.0/24,192.168.1.0/24",
		"space":       "192.168.1.0/24, 10.0.0.0/8",
		"uppercase":   "FD00:1::/64",
		"too-many":    strings.Join(many, ",") + ",172.16.0.0/12",
	} {
		if _, e := ParseSources(list); e == nil {
			t.Fatalf("%s network list accepted", name)
		}
	}
}

func TestAllowedAndSourceUnits(t *testing.T) {
	sources := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00:1::/64")}
	for addr, want := range map[string]bool{
		"192.168.1.7":        true,
		"::ffff:192.168.1.7": true,
		"192.168.2.7":        false,
		"fd00:1::9":          true,
		"fd00:2::9":          false,
		"127.0.0.1":          false,
	} {
		if Allowed(sources, netip.MustParseAddr(addr)) != want {
			t.Fatalf("%s allowed=%v", addr, !want)
		}
	}
	if Allowed(sources, netip.Addr{}) || Allowed(sources, netip.MustParseAddr("fd00:1::9%eth0")) {
		t.Fatal("an invalid or zoned address was allowed")
	}
	if Source(netip.MustParseAddr("fd00:1::1:2:3:4")) != Source(netip.MustParseAddr("fd00:1::ffff")) ||
		Source(netip.MustParseAddr("fd00:1::1")) == Source(netip.MustParseAddr("fd00:1:0:1::1")) {
		t.Fatal("IPv6 sources are not counted per /64")
	}
	if Source(netip.MustParseAddr("::ffff:192.168.1.7")) != netip.MustParseAddr("192.168.1.7") || Source(netip.MustParseAddr("192.168.1.7")) == Source(netip.MustParseAddr("192.168.1.8")) {
		t.Fatal("IPv4 sources are not counted per address")
	}
}

// accepted runs the wrapped listener and reports each admitted connection.
func accepted(t *testing.T, l net.Listener) <-chan net.Conn {
	t.Helper()
	out := make(chan net.Conn, 16)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				close(out)
				return
			}
			out <- c
		}
	}()
	return out
}

func dial(t *testing.T, address string) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal("fixture dial failed")
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// closedByServer reports whether the server side closed c without sending.
func closedByServer(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, e := c.Read(make([]byte, 1))
	return n == 0 && e != nil && !isTimeout(e)
}

func isTimeout(e error) bool {
	ne, ok := e.(net.Error)
	return ok && ne.Timeout()
}

func TestListenerAdmitsOnlyListedSourcesWithinLimits(t *testing.T) {
	inner, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	// Loopback stands in for a LAN here; operators cannot list it.
	l, e := Wrap(inner, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, 2, 3)
	if e != nil {
		t.Fatal("valid wrap refused")
	}
	defer l.Close()
	conns := accepted(t, l)
	take := func() net.Conn {
		select {
		case c := <-conns:
			return c
		case <-time.After(2 * time.Second):
			t.Fatal("an admitted connection was not accepted")
			return nil
		}
	}
	first, second := dial(t, l.Addr().String()), dial(t, l.Addr().String())
	a, b := take(), take()
	third := dial(t, l.Addr().String())
	if !closedByServer(third) {
		t.Fatal("a source beyond its limit was admitted")
	}
	select {
	case <-conns:
		t.Fatal("a refused connection reached the server")
	default:
	}
	_ = a.Close()
	_ = a.Close() // a second close releases nothing more
	fourth := dial(t, l.Addr().String())
	c := take()
	if closedByServer(fourth) {
		t.Fatal("a released slot was not reused")
	}
	if fifth := dial(t, l.Addr().String()); !closedByServer(fifth) {
		t.Fatal("a double close freed two slots")
	}
	if _, e := first.Write([]byte("x")); e != nil {
		t.Fatal("an admitted connection was closed")
	}
	_ = second
	_, _ = b, c

	// An unlisted network is closed before anything is read.
	inner3, _ := net.Listen("tcp", "127.0.0.1:0")
	elsewhere, _ := Wrap(inner3, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, 2, 3)
	defer elsewhere.Close()
	conns = accepted(t, elsewhere)
	if outside := dial(t, elsewhere.Addr().String()); !closedByServer(outside) {
		t.Fatal("an unlisted source was admitted")
	}
	select {
	case <-conns:
		t.Fatal("an unlisted source reached the server")
	case <-time.After(100 * time.Millisecond):
	}

	// The total bounds every source together: a second source, still under
	// its own limit, is refused once the listener is full.
	inner2, _ := net.Listen("tcp", "127.0.0.1:0")
	total, _ := Wrap(inner2, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, 2, 3)
	defer total.Close()
	conns = accepted(t, total)
	dial(t, total.Addr().String())
	dial(t, total.Addr().String())
	from := func(source string) net.Conn {
		d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
		c, e := d.Dial("tcp", total.Addr().String())
		if e != nil {
			t.Skip("this host cannot dial from a second loopback address")
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	from("127.0.0.2")
	take()
	take()
	take()
	if over := from("127.0.0.2"); !closedByServer(over) {
		t.Fatal("the total limit was exceeded")
	}

}

func TestWrapRefusesBadLimits(t *testing.T) {
	inner, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer inner.Close()
	one := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for name, wrap := range map[string]func() (*Listener, error){
		"nil":        func() (*Listener, error) { return Wrap(nil, one, 1, 1) },
		"no-sources": func() (*Listener, error) { return Wrap(inner, nil, 1, 1) },
		"zero":       func() (*Listener, error) { return Wrap(inner, one, 0, 1) },
		"total":      func() (*Listener, error) { return Wrap(inner, one, 2, 1) },
	} {
		if _, e := wrap(); e == nil {
			t.Fatalf("%s wrap accepted", name)
		}
	}
}
