package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/ingress"
)

func TestExposureNeedsNetworksAndASpecificAddress(t *testing.T) {
	for _, valid := range []struct{ listen, allow, name, origin string }{
		{"127.0.0.1:8443", "", "", "https://127.0.0.1:8443"},
		{"192.168.1.10:8443", "192.168.1.0/24", "", "https://192.168.1.10:8443"},
		{"192.168.1.10:8443", "192.168.1.0/24,10.8.0.0/16", "keybash.lan", "https://keybash.lan:8443"},
		{"[fd00:1::10]:8443", "fd00:1::/64", "", "https://[fd00:1::10]:8443"},
	} {
		origin, sources, ok := exposure(valid.listen, valid.allow, valid.name)
		if !ok || origin != valid.origin || (sources == nil) != (valid.allow == "") {
			t.Fatalf("%s with %q refused or misread", valid.listen, valid.allow)
		}
	}
	for name, invalid := range map[string][3]string{
		"loopback-networks": {"127.0.0.1:8443", "192.168.1.0/24", ""},
		"loopback-name":     {"127.0.0.1:8443", "", "keybash.lan"},
		"lan-no-networks":   {"192.168.1.10:8443", "", ""},
		"lan-name-only":     {"192.168.1.10:8443", "", "keybash.lan"},
		"all-interfaces":    {"0.0.0.0:8443", "192.168.1.0/24", ""},
		"all-interfaces6":   {"[::]:8443", "fd00:1::/64", ""},
		"link-local":        {"169.254.1.1:8443", "169.254.0.0/16", ""},
		"zero-port":         {"192.168.1.10:0", "192.168.1.0/24", ""},
		"hostname-listen":   {"keybash.lan:8443", "192.168.1.0/24", ""},
		"bad-networks":      {"192.168.1.10:8443", "192.168.1.7/24", ""},
		"everything":        {"192.168.1.10:8443", "0.0.0.0/0", ""},
		"mapped":            {"[::ffff:192.168.1.10]:8443", "192.168.1.0/24", ""},
		"no-port":           {"192.168.1.10", "192.168.1.0/24", ""},
	} {
		if _, _, ok := exposure(invalid[0], invalid[1], invalid[2]); ok {
			t.Fatalf("%s exposure accepted", name)
		}
	}
	if _, _, ok := exposure("192.168.1.10:8443", "192.168.1.0/24", "Keybash.lan"); !ok {
		// The name itself is checked by the lab; exposure only places it.
		t.Fatal("exposure rejected a name it does not judge")
	}
}

func certificate(t *testing.T, names []string, ips []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, ip := range ips {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
	}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestExposedCertificateMustCoverTheOrigin(t *testing.T) {
	now := time.Now()
	valid := certificate(t, []string{"keybash.lan"}, []string{"192.168.1.10"}, now.Add(-time.Hour), now.Add(time.Hour))
	for _, origin := range []string{"https://keybash.lan:8443", "https://192.168.1.10:8443"} {
		if !covers(valid, origin, now) {
			t.Fatalf("certificate refused for %s", origin)
		}
	}
	for name, check := range map[string]bool{
		"other-name":   covers(valid, "https://vault.lan:8443", now),
		"other-ip":     covers(valid, "https://192.168.1.11:8443", now),
		"expired":      covers(certificate(t, []string{"keybash.lan"}, nil, now.Add(-2*time.Hour), now.Add(-time.Hour)), "https://keybash.lan:8443", now),
		"not-yet":      covers(certificate(t, []string{"keybash.lan"}, nil, now.Add(time.Hour), now.Add(2*time.Hour)), "https://keybash.lan:8443", now),
		"empty":        covers(tls.Certificate{}, "https://keybash.lan:8443", now),
		"garbage":      covers(tls.Certificate{Certificate: [][]byte{[]byte("not a certificate")}}, "https://keybash.lan:8443", now),
		"wildcard-sub": covers(certificate(t, []string{"*.lan"}, nil, now.Add(-time.Hour), now.Add(time.Hour)), "https://a.keybash.lan:8443", now),
	} {
		if check {
			t.Fatalf("%s certificate accepted", name)
		}
	}
}

func TestExposedListenerAdmitsOnlyItsNetworks(t *testing.T) {
	plain, e := listen("127.0.0.1:0", nil)
	if e != nil {
		t.Fatal("loopback listener refused")
	}
	defer plain.Close()
	if _, wrapped := plain.(*ingress.Listener); wrapped {
		t.Fatal("a loopback listener was wrapped")
	}
	exposed, e := listen("127.0.0.1:0", []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")})
	if e != nil {
		t.Fatal("listener refused")
	}
	defer exposed.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, e := exposed.Accept(); e == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()
	c, e := net.DialTimeout("tcp", exposed.Addr().String(), time.Second)
	if e != nil {
		t.Fatal("fixture dial failed")
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, e := c.Read(make([]byte, 1)); n != 0 || e == nil {
		t.Fatal("an unlisted source stayed connected")
	}
	select {
	case <-accepted:
		t.Fatal("an unlisted source reached the server")
	case <-time.After(100 * time.Millisecond):
	}
}
