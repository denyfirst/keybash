package rdplab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/targetguard"
)

// windowsCertificate is what Windows Server 2025 makes for itself: self-signed,
// its computer name as the common name, no alternative names, and key
// encipherment without digital signature.
func windowsCertificate(t *testing.T, key *rsa.PrivateKey, change func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	if key == nil {
		var e error
		if key, e = rsa.GenerateKey(rand.Reader, 2048); e != nil {
			t.Fatal(e)
		}
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "SYNTHETIC-HOST"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if change != nil {
		change(template)
	}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestExactIdentityTakesWindowsOwnCertificate(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	good := windowsCertificate(t, key, nil).Certificate[0]
	pin, e := NewExactIdentity(good)
	if e != nil || pin.name != exactLeaf || !bytes.Equal(pin.der, good) {
		t.Fatal("Windows' own certificate was refused for a literal address")
	}
	// The same certificate names nothing, so it never passes for a DNS name.
	if _, e = NewIdentity("synthetic-host", good); e == nil {
		t.Fatal("a certificate naming nothing passed for a DNS name")
	}
	if CheckIdentity("synthetic-host", good) == nil {
		t.Fatal("a certificate naming nothing passed the name check")
	}
	for name, der := range map[string][]byte{
		"empty":        nil,
		"garbage":      []byte("not a certificate"),
		"too long":     make([]byte, 32*1024+1),
		"expired":      windowsCertificate(t, key, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }).Certificate[0],
		"not yet":      windowsCertificate(t, key, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }).Certificate[0],
		"a CA":         windowsCertificate(t, key, func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }).Certificate[0],
		"signing CAs":  windowsCertificate(t, key, func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }).Certificate[0],
		"client only":  windowsCertificate(t, key, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }).Certificate[0],
		"no key usage": windowsCertificate(t, key, func(c *x509.Certificate) { c.KeyUsage = 0 }).Certificate[0],
	} {
		if _, e := NewExactIdentity(der); e != ErrConfiguration {
			t.Fatalf("%s passed as an exact identity", name)
		}
	}
	// A copy, so a caller cannot change the identity afterwards.
	copied := bytes.Clone(good)
	pin, e = NewExactIdentity(copied)
	if e != nil {
		t.Fatal("copy refused")
	}
	copied[len(copied)-1] ^= 1
	if !bytes.Equal(pin.der, good) {
		t.Fatal("the identity shares the caller's bytes")
	}
}

// openingContext notes that opening a session got as far as looking at it, the
// first thing it does after its identity check.
type openingContext struct {
	context.Context
	reached *atomic.Bool
}

func (c openingContext) Err() error {
	c.reached.Store(true)
	return c.Context.Err()
}

// An exact identity goes only with a literal address, and a named identity only
// with a name: neither can stand in for the other at any layer.
func TestIdentityGoesOnlyWithItsKindOfTarget(t *testing.T) {
	endpoint := netip.MustParseAddrPort("10.40.0.7:3389")
	policy, e := targetguard.New([]netip.AddrPort{endpoint}, nil)
	if e != nil {
		t.Fatal(e)
	}
	literal, e := targetguard.NewAddressTarget(policy, endpoint.Addr(), endpoint.Port())
	if e != nil {
		t.Fatal(e)
	}
	named, e := targetguard.NewNamedTarget(policy, "synthetic-rdp.invalid", endpoint.Port(), []netip.Addr{endpoint.Addr()})
	if e != nil {
		t.Fatal(e)
	}
	if targetguard.CanonicalHostname(exactLeaf) {
		t.Fatal("the exact-leaf mark could be a DNS name")
	}
	exact, e := NewExactIdentity(windowsCertificate(t, nil, nil).Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	byName := labIdentity(t)
	// A name that is the address itself still is not the exact certificate.
	asAddress := &Identity{name: literal.Hostname(), pin: byName.pin, roots: byName.roots, der: byName.der}
	for _, tc := range []struct {
		name   string
		id     *Identity
		target *targetguard.NamedTarget
		bound  bool
	}{
		{"exact at an address", exact, literal, true},
		{"named at its name", byName, named, true},
		{"exact at a name", exact, named, false},
		{"named at an address", byName, literal, false},
		{"named for the address at that address", asAddress, literal, false},
		{"exact nowhere", exact, nil, false},
		{"nothing at an address", nil, literal, false},
		{"an empty identity at an address", &Identity{}, literal, false},
	} {
		if tc.id.boundTo(tc.target) != tc.bound {
			t.Fatalf("%s: bound is not %v", tc.name, tc.bound)
		}
	}
	if byName.der == nil {
		byName = &Identity{name: byName.name, pin: byName.pin, roots: byName.roots, der: []byte{1}}
	}
	if _, e := newNativeBroker(literal, exact); e != nil {
		t.Fatal("an exact identity was refused at its literal address")
	}
	if _, e := newNativeBroker(named, exact); e != errNative {
		t.Fatal("an exact identity was brokered to a name")
	}
	if _, e := newNativeBroker(literal, byName); e != errNative {
		t.Fatal("a named identity was brokered to a literal address")
	}
	// A mismatch stops at the check, before anything else happens; the match
	// after it shows that the check is what stopped it.
	var reached atomic.Bool
	opening := openingContext{context.Background(), &reached}
	worker := ManagerWorker{SocketPath: "/synthetic/rdp-manager.sock"}
	if s, e := worker.open(opening, named, exact, "synthetic-user", "synthetic-password", 0, 0); s != nil || e != errNative {
		t.Fatal("a session opened with an exact identity at a name")
	}
	if s, e := worker.open(opening, literal, byName, "synthetic-user", "synthetic-password", 0, 0); s != nil || e != errNative {
		t.Fatal("a session opened with a named identity at an address")
	}
	if reached.Load() {
		t.Fatal("a mismatched identity went past the check")
	}
	if s, e := worker.open(opening, literal, exact, "synthetic-user", "synthetic-password", 0, 0); s != nil || e != errNative || !reached.Load() {
		t.Fatal("a matching identity did not go on towards the manager")
	}
	// The rules come from the target, never from the certificate.
	windows := windowsCertificate(t, nil, nil).Certificate[0]
	if pin, e := identityFor(literal, windows); e != nil || pin.name != exactLeaf {
		t.Fatal("a literal address did not take its exact certificate")
	}
	if _, e := identityFor(named, windows); e == nil {
		t.Fatal("Windows' own certificate passed for a server reached by name")
	}
	if s, e := worker.OpenRDP(context.Background(), identity.RDPRequest{Target: named, Certificate: windows, Username: "synthetic-user", Password: "synthetic-password"}); s != nil || e != errNative {
		t.Fatal("Windows' own certificate opened a server reached by name")
	}
	// A plan takes the exact mark; the manager's name file has room for it.
	if _, e := newNativePlan(exact, "synthetic-user", "synthetic-password"); e != nil || strings.TrimSpace(exactLeaf) != exactLeaf || len(exactLeaf) > 253 {
		t.Fatal("an exact identity does not reach the worker")
	}
	// The original probe is for a name: it never takes an exact identity.
	if Probe(context.Background(), literal, exact) != ErrConfiguration || Probe(context.Background(), named, exact) != ErrConfiguration {
		t.Fatal("the name-checking probe took an exact identity")
	}
}
