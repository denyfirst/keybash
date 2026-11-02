package targetguard

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// Target networks are canonical and lie wholly outside every address the guard
// refuses, because the kernel cannot carve a hole into an allowed network.
func TestTargetNetworksAvoidEveryRefusedAddress(t *testing.T) {
	protected := []netip.Prefix{netip.MustParsePrefix("10.90.0.0/24")}
	networks, e := ParseNetworks("192.168.1.0/24,10.91.0.0/16,fd00:1::/64,192.0.2.10/32", protected)
	if e != nil || len(networks) != 4 {
		t.Fatal("valid target networks refused")
	}
	for addr, want := range map[string]bool{"192.168.1.20": true, "::ffff:192.168.1.20": true, "fd00:1::5": true, "192.0.2.10": true, "192.0.2.11": false, "192.168.2.1": false, "10.90.0.5": false} {
		if Within(networks, netip.MustParseAddr(addr)) != want {
			t.Fatalf("Within(%s) is not %v", addr, want)
		}
	}
	for _, bad := range []string{
		"", ",", "192.168.1.0/24,", " 192.168.1.0/24", "not-a-network", "192.168.1.0/33", "192.168.001.0/24",
		"192.168.1.1/24",                // host bits set
		"192.168.1.0/24,192.168.1.0/24", // repeated
		"::ffff:192.168.1.0/120",        // IPv4 written inside IPv6
		"0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1",
		"127.0.0.0/8", "::1/128", "169.254.0.0/16", "169.254.169.254/32", "fe80::/64", "224.0.0.0/24", "ff02::/16",
		"240.0.0.0/8", "2002::/16", "2001::/32", "64:ff9b::/96",
		"100.64.0.0/10", "168.63.0.0/16", "fd00::/8", "fd20:ce::/32", // contain a platform metadata endpoint
		"10.90.0.0/24", "10.90.0.128/25", "10.0.0.0/8", // touch the protected network
	} {
		if _, e := ParseNetworks(bad, protected); e == nil {
			t.Fatalf("target networks %q accepted", bad)
		}
	}
	many := make([]string, MaxNetworks+1)
	for i := range many {
		many[i] = fmt.Sprintf("192.168.%d.0/24", i)
	}
	if _, e := ParseNetworks(strings.Join(many[:MaxNetworks], ","), nil); e != nil {
		t.Fatal("the largest allowed list was refused")
	}
	if _, e := ParseNetworks(strings.Join(many, ","), nil); e == nil {
		t.Fatal("more than the allowed number of networks accepted")
	}
	hosts := HostNetworks([]netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("::ffff:192.0.2.10"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.10")})
	if JoinNetworks(hosts) != "192.0.2.10/32,2001:db8::1/128" {
		t.Fatalf("host networks: %s", JoinNetworks(hosts))
	}
	if again, e := ParseNetworks(JoinNetworks(hosts), protected); e != nil || JoinNetworks(again) != JoinNetworks(hosts) {
		t.Fatal("host networks do not read back")
	}
}
