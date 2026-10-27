package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/targetguard"
	"golang.org/x/crypto/ssh"
)

func TestCheckTargetsNamesUnavailableServers(t *testing.T) {
	now := time.Now()
	named := func(host string, port uint16, ip string) *targetguard.NamedTarget {
		addr := netip.MustParseAddr(ip)
		policy, e := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(addr, port)}, nil)
		if e != nil {
			t.Fatal(e)
		}
		target, e := targetguard.NewNamedTarget(policy, host, port, []netip.Addr{addr})
		if e != nil {
			t.Fatal(e)
		}
		return target
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rdp := func(id, name string, until time.Time) identity.RemoteTarget {
		cert := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{"rdp.invalid"}, NotBefore: now.Add(-2 * time.Hour), NotAfter: until,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		return identity.RemoteTarget{ID: id, Name: name, Protocol: "rdp", Target: named("rdp.invalid", 3389, "10.34.0.8"), Identity: der}
	}
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hostKey)
	targets := []identity.RemoteTarget{
		rdp(strings.Repeat("a", 32), "Old desktop", now.Add(-time.Hour)),
		rdp(strings.Repeat("b", 32), "Current desktop", now.Add(time.Hour)),
		{ID: strings.Repeat("c", 32), Name: "Linux server", Protocol: "ssh", Target: named("ssh.invalid", 22, "10.34.0.9"), Identity: signer.PublicKey().Marshal()},
	}
	var out bytes.Buffer
	if reportUnavailable(&out, nil, targets, now) != nil || out.String() != "Unavailable until its approved certificate is replaced: \"Old desktop\" ("+strings.Repeat("a", 32)+").\n" {
		t.Fatalf("check-targets reported %q", out.String())
	}
	out.Reset()
	failed := errors.New("synthetic write failure")
	if reportUnavailable(&out, failed, targets, now) != failed || out.Len() != 0 {
		t.Fatal("a failed summary write was not returned")
	}
}
