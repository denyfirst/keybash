package targetguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func endpoint(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func testPolicy(t *testing.T, approved []netip.AddrPort, protected []netip.Prefix) *Policy {
	t.Helper()
	p, err := New(approved, protected)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDialApprovedPrivateTargetUsesLiteralAddress(t *testing.T) {
	for _, address := range []string{"10.20.30.40:22", "192.168.1.25:3389", "[fd42::5]:22"} {
		t.Run(address, func(t *testing.T) {
			p := testPolicy(t, []netip.AddrPort{endpoint(address)}, nil)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			calls := 0
			p.dial = func(ctx context.Context, network, target string) (net.Conn, error) {
				calls++
				if network != "tcp" || target != address || ctx == nil {
					t.Fatal("approved target was changed before the dial")
				}
				return client, nil
			}
			conn, err := p.DialContext(context.Background(), endpoint(address))
			if err != nil || conn != client || calls != 1 {
				t.Fatalf("approved private target was not dialed once: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestDialRejectsUnregisteredTargetWithoutNetwork(t *testing.T) {
	p := testPolicy(t, []netip.AddrPort{endpoint("10.20.30.40:22")}, nil)
	calls := 0
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("network must not be reached")
	}
	for _, address := range []string{"10.20.30.41:22", "10.20.30.40:3389", "[fd42::5]:22"} {
		conn, err := p.DialContext(context.Background(), endpoint(address))
		if conn != nil || !errors.Is(err, ErrDenied) {
			t.Fatal("unregistered target was not denied")
		}
	}
	if calls != 0 {
		t.Fatal("refusal performed network activity")
	}
}

func TestPolicyRejectsForbiddenApprovals(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1:22", "[::1]:22", "169.254.169.254:80", "[fe80::1]:22",
		"[ff02::1]:22", "224.0.0.1:22", "0.0.0.0:22", "0.1.2.3:22",
		"[::]:22", "255.255.255.255:22", "100.100.100.200:80", "168.63.129.16:80",
		"[fd00:ec2::254]:80", "[::ffff:169.254.169.254]:80", "[::ffff:127.0.0.1]:22",
		"[fd42::5%eth0]:22", "10.20.30.40:0",
		"240.0.0.1:22", "[::10.20.30.40]:22", "[64:ff9b::a9fe:a9fe]:80",
		"[64:ff9b:1::1]:22", "[2002:a9fe:a9fe::1]:80", "[2001::1]:22",
	} {
		t.Run(address, func(t *testing.T) {
			p, err := New([]netip.AddrPort{endpoint(address)}, nil)
			if p != nil || !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("forbidden approval was accepted")
			}
		})
	}
	if p, err := New([]netip.AddrPort{{}}, nil); p != nil || !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("invalid endpoint was accepted")
	}
}

func TestProtectedNetworksOverrideApprovalAndMappedAddress(t *testing.T) {
	protected := []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24"), netip.MustParsePrefix("fd42::/64")}
	for _, address := range []string{"10.20.30.40:22", "[::ffff:10.20.30.40]:22", "[fd42::5]:22"} {
		if p, err := New([]netip.AddrPort{endpoint(address)}, protected); p != nil || !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("protected network approval was accepted")
		}
	}
	for _, prefix := range []netip.Prefix{{}, netip.MustParsePrefix("::ffff:10.20.30.0/120")} {
		if p, err := New(nil, []netip.Prefix{prefix}); p != nil || !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid or ambiguous protected prefix was accepted")
		}
	}
}

func TestMappedApprovedAddressDialsCanonicalIPv4(t *testing.T) {
	p := testPolicy(t, []netip.AddrPort{endpoint("[::ffff:10.20.30.40]:22")}, nil)
	wantFailure := errors.New("synthetic failure")
	p.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "10.20.30.40:22" {
			t.Fatal("mapped target was not canonicalized")
		}
		return nil, wantFailure
	}
	for _, address := range []string{"10.20.30.40:22", "[::ffff:10.20.30.40]:22"} {
		if _, err := p.DialContext(context.Background(), endpoint(address)); !errors.Is(err, ErrUnavailable) {
			t.Fatal("canonical target did not reach the synthetic dialer")
		}
	}
}

func TestEmptyAndNilPolicyDenyEveryDial(t *testing.T) {
	for _, p := range []*Policy{nil, {}, testPolicy(t, nil, nil)} {
		if conn, err := p.DialContext(context.Background(), endpoint("10.20.30.40:22")); conn != nil || !errors.Is(err, ErrDenied) {
			t.Fatal("unconfigured policy did not fail closed")
		}
	}
	p := testPolicy(t, []netip.AddrPort{endpoint("10.20.30.40:22")}, nil)
	//lint:ignore SA1012 deliberately test malformed caller context and fail-closed refusal.
	if conn, err := p.DialContext(nil, endpoint("10.20.30.40:22")); conn != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("nil context was accepted")
	}
	if conn, err := p.DialContext(context.Background(), netip.AddrPort{}); conn != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("invalid dial endpoint was accepted")
	}
}

func TestCanceledContextPerformsNoDial(t *testing.T) {
	p := testPolicy(t, []netip.AddrPort{endpoint("10.20.30.40:22")}, nil)
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("canceled request performed network activity")
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := p.DialContext(ctx, endpoint("10.20.30.40:22")); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not preserved")
	}
}

func TestDialErrorsDoNotExposeTargetOrDiagnostics(t *testing.T) {
	const address = "10.20.30.40:22"
	p := testPolicy(t, []netip.AddrPort{endpoint(address)}, nil)
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("dial %s: synthetic sensitive diagnostic", address)
	}
	_, err := p.DialContext(context.Background(), endpoint(address))
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), address) || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("dial error exposed private diagnostics")
	}
	p.dial = func(context.Context, string, string) (net.Conn, error) { return nil, nil }
	if _, err := p.DialContext(context.Background(), endpoint(address)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil connection was reported as successful")
	}
}

func TestFailedDialClosesUnexpectedConnection(t *testing.T) {
	p := testPolicy(t, []netip.AddrPort{endpoint("10.20.30.40:22")}, nil)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		return client, errors.New("synthetic failure")
	}
	if conn, err := p.DialContext(context.Background(), endpoint("10.20.30.40:22")); conn != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed dial did not refuse the connection")
	}
	if _, err := server.Write([]byte("synthetic data")); err == nil {
		t.Fatal("failed dial leaked an open connection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return nil, errors.New("synthetic failure")
	}
	if _, err := p.DialContext(ctx, endpoint("10.20.30.40:22")); !errors.Is(err, context.Canceled) {
		t.Fatal("in-flight cancellation was lost")
	}
}

func TestPolicyCopiesInputsAndSupportsConcurrentReads(t *testing.T) {
	approved := []netip.AddrPort{endpoint("10.20.30.40:22")}
	protected := []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}
	p := testPolicy(t, approved, protected)
	approved[0] = endpoint("10.99.0.1:22")
	protected[0] = netip.MustParsePrefix("10.20.0.0/16")
	p.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("synthetic failure") }
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Go(func() {
			if _, err := p.DialContext(context.Background(), endpoint("10.20.30.40:22")); !errors.Is(err, ErrUnavailable) {
				t.Error("caller mutation changed the approved policy")
			}
			if _, err := p.DialContext(context.Background(), endpoint("10.99.0.1:22")); !errors.Is(err, ErrDenied) {
				t.Error("caller mutation granted a new target")
			}
		})
	}
	group.Wait()
}
