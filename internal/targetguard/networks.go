package targetguard

import (
	"net/netip"
	"slices"
	"strings"
)

// MaxNetworks bounds the target networks one gateway may reach.
const MaxNetworks = 64

// Ranges no target network may touch: an address here is never a server.
var nonTargetRanges = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// ParseNetworks reads the comma-separated networks a gateway may reach, such
// as "192.168.1.0/24,fd00:1::/64", as root set them at install. The kernel
// enforces them on the gateway's unit, where an allowed network cannot have
// a hole in it, so each must lie wholly outside every address the guard
// refuses: loopback, link-local, multicast, the translation ranges, the
// platform metadata endpoints and the deployment's protected networks. Each
// is written canonically (host bits zero) and appears once.
func ParseNetworks(list string, protected []netip.Prefix) ([]netip.Prefix, error) {
	if list == "" || len(list) > 4096 {
		return nil, ErrInvalidPolicy
	}
	refused := slices.Concat(nonTargetRanges[:], unsupportedRanges[:], protected)
	var networks []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		prefix, e := netip.ParsePrefix(item)
		if e != nil || prefix.Masked() != prefix || prefix.String() != item || prefix.Addr().Is4In6() ||
			slices.Contains(networks, prefix) || len(networks) >= MaxNetworks ||
			slices.ContainsFunc(refused, prefix.Overlaps) || slices.ContainsFunc(platformEndpoints[:], prefix.Contains) {
			return nil, ErrInvalidPolicy
		}
		networks = append(networks, prefix)
	}
	return networks, nil
}

// Within reports whether addr lies in one of the networks.
func Within(networks []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	return slices.ContainsFunc(networks, func(n netip.Prefix) bool { return n.Contains(addr) })
}

// HostNetworks returns one host network (/32 or /128) per address, in order and
// without repeats: the narrowest list that still reaches exactly these servers.
func HostNetworks(addrs []netip.Addr) []netip.Prefix {
	var networks []netip.Prefix
	for _, addr := range addrs {
		addr = addr.Unmap()
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		if !slices.Contains(networks, prefix) {
			networks = append(networks, prefix)
		}
	}
	return networks
}

// JoinNetworks writes networks the way ParseNetworks reads them.
func JoinNetworks(networks []netip.Prefix) string {
	words := make([]string, len(networks))
	for i, n := range networks {
		words[i] = n.String()
	}
	return strings.Join(words, ",")
}
