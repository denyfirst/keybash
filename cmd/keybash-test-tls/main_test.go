package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, path string) []byte {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("%s is not one PEM block", filepath.Base(path))
	}
	return block.Bytes
}

func TestTestTLSCoversOnlyItsGateway(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		flag, value, other string
	}{{"--name", "keybash.lan", "vault.lan"}, {"--address", "192.168.1.10", "192.168.1.11"}, {"--address", "127.0.0.1", "127.0.0.2"}} {
		dir := filepath.Join(t.TempDir(), "tls")
		var out bytes.Buffer
		if run([]string{c.flag, c.value, "--output", dir}, &out) != nil || !strings.Contains(out.String(), "SHA-256 ") {
			t.Fatalf("%s test TLS refused", c.value)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 3 {
			t.Fatal("test TLS wrote more than ca.pem, cert.pem and key.pem")
		}
		if runtime.GOOS != "windows" {
			for name, mode := range map[string]os.FileMode{"ca.pem": 0644, "cert.pem": 0644, "key.pem": 0600} {
				if info, e := os.Stat(filepath.Join(dir, name)); e != nil || info.Mode().Perm() != mode {
					t.Fatalf("%s mode is not %o", name, mode)
				}
			}
		}
		ca, e := x509.ParseCertificate(load(t, filepath.Join(dir, "ca.pem")))
		if e != nil || !ca.IsCA || !ca.MaxPathLenZero || !ca.PermittedDNSDomainsCritical || ca.NotAfter.After(now.Add(91*24*time.Hour)) {
			t.Fatal("authority is not a constrained short-lived CA")
		}
		leafCert, e := x509.ParseCertificate(load(t, filepath.Join(dir, "cert.pem")))
		if e != nil {
			t.Fatal(e)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		if _, e := leafCert.Verify(x509.VerifyOptions{DNSName: c.value, Roots: roots, CurrentTime: now}); e != nil {
			t.Fatalf("gateway certificate does not verify for %s", c.value)
		}
		if _, e := leafCert.Verify(x509.VerifyOptions{DNSName: c.other, Roots: roots, CurrentTime: now}); e == nil {
			t.Fatalf("gateway certificate verifies for %s", c.other)
		}
		// The server pair loads as the gateway loads it.
		if _, e := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")); e != nil {
			t.Fatal("certificate and key do not form a pair")
		}
		if bytes.Contains(load(t, filepath.Join(dir, "ca.pem")), []byte("PRIVATE")) {
			t.Fatal("authority file carries a key")
		}
		if run([]string{c.flag, c.value, "--output", dir}, &out) == nil {
			t.Fatal("existing output replaced")
		}
	}
}

// The constraints are what makes trusting the authority safe; a certificate
// it signed for anything else must not verify even though it is signed.
func TestTestTLSAuthorityConstraints(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		s      subject
		others []subject
	}{
		{subject{name: "keybash.lan"}, []subject{{name: "vault.lan"}, {name: "a.keybash.lan.evil"}, {addr: netip.MustParseAddr("192.168.1.10")}}},
		{subject{addr: netip.MustParseAddr("192.168.1.10")}, []subject{{addr: netip.MustParseAddr("192.168.1.11")}, {name: "keybash.lan"}}},
	} {
		ca, key, e := authority(c.s, now, time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		for _, other := range c.others {
			der, _, e := leaf(other, ca, key, now, time.Hour)
			if e != nil {
				t.Fatal(e)
			}
			cert, _ := x509.ParseCertificate(der)
			host := other.name
			if host == "" {
				host = other.addr.String()
			}
			if _, e := cert.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, CurrentTime: now}); e == nil {
				t.Fatalf("authority for %v vouched for %s", c.s, host)
			}
		}
	}
}

func TestTestTLSRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"none":       {"--output", filepath.Join(dir, "a")},
		"both":       {"--name", "keybash.lan", "--address", "192.168.1.10", "--output", filepath.Join(dir, "b")},
		"bad-name":   {"--name", "Keybash.lan", "--output", filepath.Join(dir, "c")},
		"localhost":  {"--name", "localhost", "--output", filepath.Join(dir, "d")},
		"link-local": {"--address", "169.254.1.1", "--output", filepath.Join(dir, "e")},
		"any":        {"--address", "0.0.0.0", "--output", filepath.Join(dir, "f")},
		"mapped":     {"--address", "::ffff:192.168.1.10", "--output", filepath.Join(dir, "g")},
		"relative":   {"--name", "keybash.lan", "--output", "tls"},
		"zero-days":  {"--name", "keybash.lan", "--output", filepath.Join(dir, "h"), "--days", "0"},
		"long":       {"--name", "keybash.lan", "--output", filepath.Join(dir, "i"), "--days", "398"},
		"extra":      {"--name", "keybash.lan", "--output", filepath.Join(dir, "j"), "more"},
	} {
		if run(args, &bytes.Buffer{}) == nil {
			t.Fatalf("%s input accepted", name)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("refused input wrote files")
	}
}
