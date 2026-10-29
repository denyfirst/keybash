package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/ingress"
)

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

// pemFiles writes a pair as check-tls and the gateway read it.
func pemFiles(t *testing.T, pair tls.Certificate) (string, string) {
	t.Helper()
	dir := t.TempDir()
	der, e := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600) != nil ||
		os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600) != nil {
		t.Fatal("fixture TLS files failed")
	}
	return cert, key
}

func TestCheckTLSBeforeInstalling(t *testing.T) {
	now := time.Now()
	valid := certificate(t, []string{"keybash.lan"}, []string{"127.0.0.1", "192.168.1.10"}, now.Add(-time.Hour), now.Add(time.Hour))
	cert, key := pemFiles(t, valid)
	check := func(extra ...string) (string, error) {
		var out bytes.Buffer
		e := run(append([]string{"check-tls", "--tls-cert", cert, "--tls-key", key}, extra...), nil, &out)
		return out.String(), e
	}
	for _, args := range [][]string{
		nil,
		{"--listen", "192.168.1.10:8443", "--allow-from", "192.168.1.0/24"},
		{"--listen", "192.168.1.10:8443", "--allow-from", "192.168.1.0/24", "--server-name", "keybash.lan"},
	} {
		if out, e := check(args...); e != nil || !strings.HasPrefix(out, "TLS certificate valid for https://") {
			t.Fatalf("valid TLS refused with %v", args)
		}
	}
	for name, args := range map[string][]string{
		"other-name":      {"--listen", "192.168.1.10:8443", "--allow-from", "192.168.1.0/24", "--server-name", "vault.lan"},
		"other-address":   {"--listen", "192.168.1.11:8443", "--allow-from", "192.168.1.0/24"},
		"lan-no-networks": {"--listen", "192.168.1.10:8443"},
		"other-flag":      {"--data", t.TempDir()},
	} {
		if out, e := check(args...); e == nil || out != "" {
			t.Fatalf("%s TLS check passed", name)
		}
	}
	expired, expiredKey := pemFiles(t, certificate(t, nil, []string{"127.0.0.1"}, now.Add(-2*time.Hour), now.Add(-time.Hour)))
	other, otherKey := pemFiles(t, certificate(t, nil, []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(time.Hour)))
	for name, pair := range map[string][2]string{"expired": {expired, expiredKey}, "mismatched": {cert, otherKey}, "missing-key": {other, ""}} {
		if run([]string{"check-tls", "--tls-cert", pair[0], "--tls-key", pair[1]}, nil, &bytes.Buffer{}) == nil {
			t.Fatalf("%s TLS pair passed", name)
		}
	}
	// The catalog-only flag belongs to check-targets alone.
	if run([]string{"check-tls", "--tls-cert", cert, "--tls-key", key, "--ssh-only"}, nil, &bytes.Buffer{}) == nil {
		t.Fatal("check-tls accepted a catalog flag")
	}
}
