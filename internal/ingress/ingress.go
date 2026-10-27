// Package ingress admits TCP connections to a non-loopback listener: only from
// networks the operator listed, and only a bounded number at once per source
// and in total. A refused connection is closed before any TLS or HTTP byte is
// read. It is not a firewall and does not replace one.
package ingress

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

var ErrIngress = errors.New("ingress refused")

const (
	// MaxSources bounds the operator's network list.
	MaxSources = 16
	// PerSource leaves room for several tabs, each with a terminal or desktop
	// socket, from one machine (or one IPv6 /64).
	PerSource = 64
	Total     = 1024
)

// ParseSources reads a comma-separated list of networks such as
// "192.168.1.0/24,fd00:1::/64". Each must be written canonically (host bits
// zero), may not be loopback or unspecified (so never the whole address
// space), and may not repeat.
func ParseSources(list string) ([]netip.Prefix, error) {
	if list == "" || len(list) > 1024 {
		return nil, ErrIngress
	}
	var sources []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		prefix, e := netip.ParsePrefix(item)
		if e != nil || prefix.Masked() != prefix || prefix.String() != item || prefix.Addr().Is4In6() ||
			prefix.Addr().IsLoopback() || prefix.Addr().IsUnspecified() || slices.Contains(sources, prefix) || len(sources) >= MaxSources {
			return nil, ErrIngress
		}
		sources = append(sources, prefix)
	}
	return sources, nil
}

// Allowed reports whether a client address is inside one of the networks.
func Allowed(sources []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	for _, prefix := range sources {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Source is the unit limits count by: an IPv4 address, or an IPv6 /64, since
// one IPv6 host can use any address in its subnet.
func Source(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().Addr()
	}
	return addr
}

// Listener wraps an accepted-connection stream with Allowed and the limits.
type Listener struct {
	net.Listener
	sources          []netip.Prefix
	perSource, total int
	mu               sync.Mutex
	open             map[netip.Addr]int
	count            int
}

func Wrap(inner net.Listener, sources []netip.Prefix, perSource, total int) (*Listener, error) {
	if inner == nil || len(sources) == 0 || len(sources) > MaxSources || perSource < 1 || total < perSource {
		return nil, ErrIngress
	}
	return &Listener{Listener: inner, sources: slices.Clone(sources), perSource: perSource, total: total, open: make(map[netip.Addr]int)}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		if source, ok := l.admit(c.RemoteAddr()); ok {
			return &conn{Conn: c, release: func() { l.release(source) }}, nil
		}
		_ = c.Close()
	}
}

func (l *Listener) admit(remote net.Addr) (netip.Addr, bool) {
	tcp, ok := remote.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(tcp.IP)
	if !ok || tcp.Zone != "" || !Allowed(l.sources, addr) {
		return netip.Addr{}, false
	}
	source := Source(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count >= l.total || l.open[source] >= l.perSource {
		return netip.Addr{}, false
	}
	l.count++
	l.open[source]++
	return source, true
}

func (l *Listener) release(source netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.count--
	if l.open[source]--; l.open[source] == 0 {
		delete(l.open, source)
	}
}

type conn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *conn) Close() error {
	e := c.Conn.Close()
	c.once.Do(c.release)
	return e
}
