package targetguard

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const maxTargetAddresses = 16

// NamedTarget is an immutable hostname/port/pin snapshot. DNS is not an
// approval authority: pins must come from independently trusted configuration.
// A nil or zero target denies access. Recreate the target when approvals change.
type NamedTarget struct {
	policy  *Policy
	host    string
	port    uint16
	pins    map[netip.Addr]struct{}
	lookup  func(context.Context, string, string) ([]netip.Addr, error)
	literal netip.AddrPort // set only by NewAddressTarget; then there is no DNS
}

// NewAddressTarget approves one literal address and port for a server that has
// no DNS name, which is common on a small office network. Nothing is ever
// resolved, so there is no name to rebind or poison; the policy still decides
// at the dial. Hostname returns the canonical address, a label only: an SSH
// connection's identity remains its approved host key.
func NewAddressTarget(policy *Policy, address netip.Addr, port uint16) (*NamedTarget, error) {
	if port == 0 || !address.IsValid() || address.Zone() != "" {
		return nil, ErrInvalidPolicy
	}
	endpoint, allowed := policy.permitted(netip.AddrPortFrom(address, port))
	if !allowed {
		return nil, ErrInvalidPolicy
	}
	return &NamedTarget{policy: policy, host: endpoint.Addr().String(), port: port,
		pins: map[netip.Addr]struct{}{endpoint.Addr(): {}}, literal: endpoint}, nil
}

// Literal reports whether the target is a bare address with no DNS name.
// Protocols whose identity check needs a name (RDP certificates) refuse it.
func (t *NamedTarget) Literal() bool { return t != nil && t.literal.IsValid() }

// NewNamedTarget validates every pin against the installation policy and copies
// the pin set. host is an ASCII DNS name (IDNA A-labels may be supplied), not a
// URL, host:port, or IP literal. An optional root dot is normalized away.
func NewNamedTarget(policy *Policy, host string, port uint16, pins []netip.Addr) (*NamedTarget, error) {
	host, ok := canonicalHostname(host)
	if !ok || port == 0 || len(pins) == 0 || len(pins) > maxTargetAddresses {
		return nil, ErrInvalidPolicy
	}
	target := &NamedTarget{policy: policy, host: host, port: port, pins: make(map[netip.Addr]struct{}, len(pins))}
	for _, addr := range pins {
		endpoint, allowed := policy.permitted(netip.AddrPortFrom(addr, port))
		if !allowed {
			return nil, ErrInvalidPolicy
		}
		target.pins[endpoint.Addr()] = struct{}{}
	}
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true}
	target.lookup = resolver.LookupNetIP
	return target, nil
}

// Hostname returns the canonical logical identity for later SSH/TLS verification.
// Dialing a pinned IP does not authenticate the server behind that address.
func (t *NamedTarget) Hostname() string {
	if t == nil {
		return ""
	}
	return t.host
}

// Snapshot describes configured approval, never a DNS observation. Addresses
// are canonical, sorted and copied; callers cannot change dialing authority.
type Snapshot struct {
	Hostname  string   `json:"hostname"`
	Port      uint16   `json:"port"`
	Addresses []string `json:"addresses"`
}

func (t *NamedTarget) Snapshot() Snapshot {
	if t == nil {
		return Snapshot{}
	}
	result := Snapshot{Hostname: t.host, Port: t.port, Addresses: make([]string, 0, len(t.pins))}
	for address := range t.pins {
		result.Addresses = append(result.Addresses, address.String())
	}
	slices.Sort(result.Addresses)
	return result
}

// DialContext resolves exactly once per attempt and validates the whole answer
// before opening TCP. Even another address approved by the installation policy
// is denied if it is not pinned to this target. The selected address is passed
// to Policy.DialContext as a literal IP; there is no second hostname lookup.
// The first returned address is used, without fallback or automatic reapproval.
func (t *NamedTarget) DialContext(ctx context.Context) (net.Conn, error) {
	if t == nil || t.policy == nil || len(t.pins) == 0 || ctx == nil {
		return nil, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if t.literal.IsValid() {
		// The approved literal itself; the policy rechecks it at the dial.
		return t.policy.DialContext(ctx, t.literal)
	}
	if t.lookup == nil {
		return nil, ErrDenied
	}
	// A root dot prevents OS search domains from changing the configured name.
	addresses, err := t.lookup(ctx, "ip", t.host+".")
	if cancelErr := ctx.Err(); cancelErr != nil {
		return nil, cancelErr
	}
	if err != nil || len(addresses) == 0 {
		return nil, ErrUnavailable
	}
	if len(addresses) > maxTargetAddresses {
		return nil, ErrDenied
	}
	var selected netip.AddrPort
	for _, addr := range addresses {
		endpoint, allowed := t.policy.permitted(netip.AddrPortFrom(addr, t.port))
		if !allowed {
			return nil, ErrDenied
		}
		if _, pinned := t.pins[endpoint.Addr()]; !pinned {
			return nil, ErrDenied
		}
		if !selected.IsValid() {
			selected = endpoint
		}
	}
	return t.policy.DialContext(ctx, selected)
}

func canonicalHostname(host string) (string, bool) {
	// Bound before copying/lowercasing caller-controlled input.
	if len(host) == 0 || len(host) > 254 {
		return "", false
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return strings.ToLower(host), true
}
