package targetguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func namedFixture(t *testing.T, port uint16) (*NamedTarget, *Policy) {
	t.Helper()
	p := testPolicy(t, []netip.AddrPort{
		netip.AddrPortFrom(netip.MustParseAddr("10.20.30.40"), port),
		netip.AddrPortFrom(netip.MustParseAddr("10.20.30.41"), port),
		netip.AddrPortFrom(netip.MustParseAddr("fd42::5"), port),
	}, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")})
	target, err := NewNamedTarget(p, "Server.Example.", port, []netip.Addr{netip.MustParseAddr("10.20.30.40"), netip.MustParseAddr("fd42::5")})
	if err != nil {
		t.Fatal(err)
	}
	// No fixture may fall through to a real DNS query or TCP dial.
	target.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("unexpected DNS lookup")
		return nil, errors.New("synthetic failure")
	}
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("unexpected TCP dial")
		return nil, errors.New("synthetic failure")
	}
	return target, p
}

// A server without a DNS name is approved by address alone: nothing is ever
// resolved, and only the approved literal is dialed, through the policy.
func TestAddressTargetDialsTheApprovedLiteralWithoutDNS(t *testing.T) {
	for _, given := range []string{"10.20.30.40", "::ffff:10.20.30.40", "fd42::5"} {
		_, p := namedFixture(t, 22)
		target, err := NewAddressTarget(p, netip.MustParseAddr(given), 22)
		if err != nil {
			t.Fatal("approved literal refused")
		}
		want := netip.MustParseAddr(given).Unmap()
		if !target.Literal() || target.Hostname() != want.String() {
			t.Fatal("address target lost its canonical literal")
		}
		if snap := target.Snapshot(); snap.Hostname != want.String() || snap.Port != 22 || len(snap.Addresses) != 1 || snap.Addresses[0] != want.String() {
			t.Fatal("address target snapshot differs from its approval")
		}
		target.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
			t.Fatal("an address target resolved a name")
			return nil, nil
		}
		client, server := net.Pipe()
		dials := 0
		p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials++
			if network != "tcp" || addr != netip.AddrPortFrom(want, 22).String() {
				t.Fatal("address target dialed something other than its literal")
			}
			return client, nil
		}
		conn, err := target.DialContext(context.Background())
		if err != nil || conn != client || dials != 1 {
			t.Fatal("approved literal was not dialed exactly once")
		}
		_ = server.Close()
		_ = conn.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := target.DialContext(ctx); err == nil || dials != 1 {
			t.Fatal("a canceled request dialed")
		}
	}
	_, p := namedFixture(t, 22)
	for _, bad := range []struct {
		addr string
		port uint16
	}{{"10.99.0.5", 22}, {"10.20.30.40", 23}, {"10.20.30.40", 0}, {"127.0.0.1", 22}, {"169.254.169.254", 22}, {"fe80::1%eth0", 22}} {
		if target, err := NewAddressTarget(p, netip.MustParseAddr(bad.addr), bad.port); err == nil || target != nil {
			t.Fatalf("%s port %d was approved as an address target", bad.addr, bad.port)
		}
	}
	if target, err := NewAddressTarget(nil, netip.MustParseAddr("10.20.30.40"), 22); err == nil || target != nil {
		t.Fatal("an address target was approved without a policy")
	}
	if named, _ := namedFixture(t, 22); named.Literal() {
		t.Fatal("a named target reported itself as a bare address")
	}
}

func TestNamedTargetResolvesOnceAndDialsPinnedLiteral(t *testing.T) {
	for _, port := range []uint16{22, 3389} {
		for _, address := range []string{"10.20.30.40", "fd42::5", "::ffff:10.20.30.40"} {
			target, p := namedFixture(t, port)
			lookups, dials := 0, 0
			target.lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				lookups++
				if network != "ip" || host != "server.example." || target.Hostname() != "server.example" {
					t.Fatal("lookup changed the exact logical hostname")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("lookup has no bounded deadline")
				}
				return []netip.Addr{netip.MustParseAddr(address)}, nil
			}
			client, server := net.Pipe()
			p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dials++
				want := netip.AddrPortFrom(netip.MustParseAddr(address).Unmap(), port).String()
				if addr != want || network != "tcp" || ctx.Err() != nil {
					t.Fatal("dial re-resolved the name or changed the selected endpoint")
				}
				return client, nil
			}
			conn, err := target.DialContext(context.Background())
			if conn != client || err != nil || lookups != 1 || dials != 1 {
				t.Fatalf("pinned private connection failed: %v", err)
			}
			_ = client.Close()
			_ = server.Close()
		}
	}
}

func TestNamedTargetRejectsWholeAnswerBeforeAnyTCP(t *testing.T) {
	for _, bad := range []string{
		"10.20.30.41", // Approved globally, but belongs to another target.
		"10.99.0.1", "127.0.0.1", "::1", "169.254.169.254",
		"100.100.100.200", "168.63.129.16", "fd00:ec2::254",
		"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1",
		"fd42::5%eth0", "0.0.0.0", "ff02::1", "240.0.0.1",
	} {
		t.Run(bad, func(t *testing.T) {
			for _, mixed := range []bool{false, true} {
				target, _ := namedFixture(t, 22)
				target.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
					answers := []netip.Addr{netip.MustParseAddr(bad)}
					if mixed {
						answers = append([]netip.Addr{netip.MustParseAddr("10.20.30.40")}, answers...)
					}
					return answers, nil
				}
				if conn, err := target.DialContext(context.Background()); conn != nil || !errors.Is(err, ErrDenied) {
					t.Fatal("unsafe DNS answer was not refused before TCP")
				}
			}
		})
	}
	target, _ := namedFixture(t, 22)
	for _, answers := range [][]netip.Addr{{{}}, make([]netip.Addr, maxTargetAddresses+1)} {
		target.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return answers, nil }
		if conn, err := target.DialContext(context.Background()); conn != nil || !errors.Is(err, ErrDenied) {
			t.Fatal("invalid or oversized answer was accepted")
		}
	}
}

func TestNamedTargetRebindingDoesNotApproveAnotherServer(t *testing.T) {
	target, p := namedFixture(t, 22)
	lookups, dials := 0, 0
	target.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups == 1 {
			return []netip.Addr{netip.MustParseAddr("10.20.30.40")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.20.30.41")}, nil
	}
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, errors.New("synthetic failure")
	}
	if _, err := target.DialContext(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("approved address did not reach TCP")
	}
	if _, err := target.DialContext(context.Background()); !errors.Is(err, ErrDenied) || lookups != 2 || dials != 1 {
		t.Fatal("rebinding gained access to another approved server")
	}
}

func TestNamedTargetUsesFirstPinnedAnswerWithoutFallback(t *testing.T) {
	target, p := namedFixture(t, 22)
	target.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("fd42::5"), netip.MustParseAddr("10.20.30.40")}, nil
	}
	dials := 0
	p.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		dials++
		if address != "[fd42::5]:22" {
			t.Fatal("selected address changed after validation")
		}
		return nil, errors.New("synthetic failure")
	}
	if conn, err := target.DialContext(context.Background()); conn != nil || err != ErrUnavailable || dials != 1 {
		t.Fatal("failed first address triggered fallback or changed the result")
	}
}

func TestNamedTargetConfigurationFailsClosed(t *testing.T) {
	_, p := namedFixture(t, 22)
	good := []netip.Addr{netip.MustParseAddr("10.20.30.40")}
	longest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, host := range []string{"", ".", "server..example", "-server", "server-", "https://server.example", "server:22", "server/example", "server@example", " server", "server\x00", "sərver", "_ssh.example", "10.20.30.40", "10.20.30.40.", "fd42::5", strings.Repeat("a", 64) + ".example", strings.Repeat("a", 255), longest + "x"} {
		if got, err := NewNamedTarget(p, host, 22, good); got != nil || !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("malformed hostname accepted: %q", host)
		}
	}
	for _, host := range []string{"server", "Server.Example.", "xn--server-9za.example", longest, longest + "."} {
		if got, err := NewNamedTarget(p, host, 22, good); got == nil || err != nil {
			t.Fatal("valid hostname rejected")
		}
	}
	for _, pins := range [][]netip.Addr{nil, {{}}, {netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("10.99.0.1")}, {netip.MustParseAddr("10.20.30.42")}, {netip.MustParseAddr("fd42::5%eth0")}, make([]netip.Addr, maxTargetAddresses+1)} {
		if got, err := NewNamedTarget(p, "server.example", 22, pins); got != nil || !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("unapproved or malformed pins accepted")
		}
	}
	for _, policy := range []*Policy{nil, {}, p} {
		port := uint16(22)
		if policy == p {
			port = 0
		}
		if got, err := NewNamedTarget(policy, "server.example", port, good); got != nil || !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("unconfigured policy or zero port accepted")
		}
	}
	if got, err := NewNamedTarget(p, "server.example", 3389, good); got != nil || !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("approval was reused for another port")
	}
	for _, target := range []*NamedTarget{nil, {}} {
		if target.Hostname() != "" {
			t.Fatal("unconfigured target exposes an identity")
		}
		if conn, err := target.DialContext(context.Background()); conn != nil || !errors.Is(err, ErrDenied) {
			t.Fatal("unconfigured target did not fail closed")
		}
	}
}

func TestNamedTargetDNSFailureAndCancellationPerformNoTCP(t *testing.T) {
	target, _ := namedFixture(t, 22)
	//lint:ignore SA1012 deliberately test malformed caller context.
	if _, err := target.DialContext(nil); !errors.Is(err, ErrDenied) {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := target.DialContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request reached DNS")
	}
	for _, answers := range [][]netip.Addr{nil, {netip.MustParseAddr("10.20.30.40")}} {
		target.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
			return answers, errors.New("server.example synthetic private resolver diagnostic")
		}
		if conn, err := target.DialContext(context.Background()); conn != nil || err != ErrUnavailable {
			t.Fatal("DNS failure leaked diagnostics or used a partial answer")
		}
	}
	target.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil }
	if _, err := target.DialContext(context.Background()); err != ErrUnavailable {
		t.Fatal("empty DNS result accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	target.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("10.20.30.40")}, nil
	}
	if _, err := target.DialContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation during resolution was ignored")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	target.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if _, err := target.DialContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("resolver did not respect the caller's shorter deadline")
	}
}

func TestNamedTargetCopiesPinsAndSupportsConcurrentReads(t *testing.T) {
	_, p := namedFixture(t, 22)
	pins := []netip.Addr{netip.MustParseAddr("::ffff:10.20.30.40")}
	target, err := NewNamedTarget(p, "server.example", 22, pins)
	if err != nil {
		t.Fatal(err)
	}
	pins[0] = netip.MustParseAddr("10.20.30.41")
	target.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.20.30.40"), netip.MustParseAddr("::ffff:10.20.30.40")}, nil
	}
	p.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("synthetic failure") }
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Go(func() {
			if _, err := target.DialContext(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Error("caller mutation changed pinned address approval")
			}
		})
	}
	group.Wait()
}

func FuzzCanonicalHostname(f *testing.F) {
	for _, seed := range []string{"Server.Example.", "", "server..example", "sərver", "10.20.30.40", "server\x00", strings.Repeat("a", 254)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		host, ok := canonicalHostname(raw)
		if !ok {
			return
		}
		if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") || strings.ToLower(host) != host {
			t.Fatal("invalid canonical hostname")
		}
		if again, valid := canonicalHostname(host); !valid || again != host {
			t.Fatal("canonical hostname is not stable")
		}
		if rooted, valid := canonicalHostname(host + "."); !valid || rooted != host {
			t.Fatal("root dot normalization is not stable")
		}
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				t.Fatal("non-DNS character survived normalization")
			}
		}
	})
}
