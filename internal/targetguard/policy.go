// Package targetguard binds outbound TCP dials to approved IP/port pairs.
// NamedTarget also binds DNS results to an independently approved pin set.
// Credential ownership and protocol authentication are separate boundaries.
package targetguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

var (
	ErrInvalidPolicy = errors.New("invalid target policy")
	ErrDenied        = errors.New("target denied")
	ErrUnavailable   = errors.New("target unavailable")
)

// These platform endpoints are denied even if an operator approves them.
// Loopback, link-local, multicast, unspecified, and non-unicast addresses are
// rejected separately. Private unicast targets may be explicitly approved, so
// a cloud's metadata service on a unique-local IPv6 address must be named
// here: the link-local rule never sees it.
var platformEndpoints = [...]netip.Addr{
	netip.MustParseAddr("100.100.100.200"),    // Alibaba Cloud metadata
	netip.MustParseAddr("168.63.129.16"),      // Azure platform (WireServer)
	netip.MustParseAddr("fd00:ec2::254"),      // AWS instance metadata, IPv6
	netip.MustParseAddr("fd20:ce::254"),       // Google Compute Engine metadata, IPv6-only VMs
	netip.MustParseAddr("fd00:c1::a9fe:a9fe"), // Oracle Cloud instance metadata, IPv6
	netip.MustParseAddr("fd00:a9fe:a9fe::1"),  // Akamai (Linode) metadata, IPv6
}

// Address translation can hide a forbidden IPv4 destination inside IPv6.
// Supporting custom NAT64 requires an explicit translator-aware design; the
// first guard refuses standard translation/tunneling ranges outright.
var unsupportedRanges = [...]netip.Prefix{
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

// Policy is an immutable snapshot. Use a new policy when approvals change.
// The zero value and a nil policy deny every dial.
type Policy struct {
	approved  map[netip.AddrPort]struct{}
	protected []netip.Prefix
	dial      func(context.Context, string, string) (net.Conn, error)
}

// New copies its inputs and refuses invalid or forbidden approvals.
// protected must name deployment-specific database/control networks. The
// built-in exclusions alone do not know the installation's internal layout.
func New(approved []netip.AddrPort, protected []netip.Prefix) (*Policy, error) {
	p := &Policy{
		approved: make(map[netip.AddrPort]struct{}, len(approved)),
	}
	for _, prefix := range protected {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return nil, ErrInvalidPolicy
		}
		p.protected = append(p.protected, prefix.Masked())
	}
	for _, endpoint := range approved {
		canonical, ok := canonicalEndpoint(endpoint)
		if !ok || p.isProtected(canonical.Addr()) {
			return nil, ErrInvalidPolicy
		}
		p.approved[canonical] = struct{}{}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	p.dial = dialer.DialContext
	return p, nil
}

// DialContext checks the exact address at the point of connection and dials
// a literal IP, never a hostname that can resolve again after approval.
// Returned errors do not include the target address or dialer's diagnostics.
func (p *Policy) DialContext(ctx context.Context, endpoint netip.AddrPort) (net.Conn, error) {
	canonical, ok := p.permitted(endpoint)
	if !ok || ctx == nil || p.dial == nil {
		return nil, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := p.dial(ctx, "tcp", canonical.String())
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		if cancelErr := ctx.Err(); cancelErr != nil {
			return nil, cancelErr
		}
		return nil, ErrUnavailable
	}
	if conn == nil {
		return nil, ErrUnavailable
	}
	if cancelErr := ctx.Err(); cancelErr != nil {
		_ = conn.Close()
		return nil, cancelErr
	}
	return conn, nil
}

func (p *Policy) permitted(endpoint netip.AddrPort) (netip.AddrPort, bool) {
	if p == nil {
		return netip.AddrPort{}, false
	}
	canonical, ok := canonicalEndpoint(endpoint)
	if !ok || p.isProtected(canonical.Addr()) {
		return netip.AddrPort{}, false
	}
	if _, approved := p.approved[canonical]; !approved {
		return netip.AddrPort{}, false
	}
	return canonical, true
}

func (p *Policy) isProtected(addr netip.Addr) bool {
	for _, prefix := range unsupportedRanges {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, endpoint := range platformEndpoints {
		if addr == endpoint {
			return true
		}
	}
	for _, prefix := range p.protected {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func canonicalEndpoint(endpoint netip.AddrPort) (netip.AddrPort, bool) {
	addr := endpoint.Addr()
	if !endpoint.IsValid() || endpoint.Port() == 0 || addr.Zone() != "" {
		return netip.AddrPort{}, false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.AddrPort{}, false
	}
	// Other 0/8 addresses are not usable destinations even though the netip
	// unicast predicate accepts them. This is not a blanket private-IP ban.
	if addr.Is4() && addr.As4()[0] == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, endpoint.Port()), true
}
