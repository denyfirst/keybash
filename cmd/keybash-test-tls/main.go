// Test HTTPS material for one Keybash gateway: a short-lived certificate
// authority constrained to that one name or address, and a server certificate
// it signed. The authority's private key exists only in memory and is never
// written, so the authority cannot sign anything else; trusting its public
// certificate on a test PC vouches for this one gateway only. Not for
// production: there, use the organization's own CA or a public one.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/ingress"
)

var errRefused = errors.New("test TLS refused")

// subject is the one name or address a gateway certificate covers.
type subject struct {
	name string
	addr netip.Addr
}

func parseSubject(name, address string) (subject, error) {
	if (name == "") == (address == "") {
		return subject{}, errRefused
	}
	if name != "" {
		if !ingress.Name(name) {
			return subject{}, errRefused
		}
		return subject{name: name}, nil
	}
	addr, e := netip.ParseAddr(address)
	if e != nil || addr.Zone() != "" || addr.String() != address || addr.Is4In6() || !addr.IsLoopback() && !addr.IsGlobalUnicast() {
		return subject{}, errRefused
	}
	return subject{addr: addr}, nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// authority creates the constrained CA. Its name constraints permit only the
// subject: a name excludes every address, and an address permits only the
// reserved .invalid domain for names.
func authority(s subject, now time.Time, life time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, errRefused
	}
	number, e := serial()
	if e != nil {
		return nil, nil, errRefused
	}
	template := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: "Keybash test CA (one gateway)"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(life), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign, PermittedDNSDomainsCritical: true}
	if s.name != "" {
		template.PermittedDNSDomains = []string{s.name}
		template.ExcludedIPRanges = []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}}
	} else {
		template.PermittedDNSDomains = []string{"invalid"}
		template.PermittedIPRanges = []*net.IPNet{{IP: s.addr.AsSlice(), Mask: net.CIDRMask(s.addr.BitLen(), s.addr.BitLen())}}
	}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		return nil, nil, errRefused
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, nil, errRefused
	}
	return ca, key, nil
}

// leaf signs a server certificate for the subject with a new P-256 key.
func leaf(s subject, ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, life time.Duration) ([]byte, *ecdsa.PrivateKey, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, errRefused
	}
	number, e := serial()
	if e != nil {
		return nil, nil, errRefused
	}
	template := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: "Keybash gateway"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if s.name != "" {
		template.DNSNames = []string{s.name}
	} else {
		template.IPAddresses = []net.IP{s.addr.AsSlice()}
	}
	der, e := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if e != nil {
		return nil, nil, errRefused
	}
	return der, key, nil
}

// issue writes ca.pem, cert.pem and key.pem into a new 0700 directory and
// returns the authority's SHA-256 fingerprint for comparison when importing.
func issue(s subject, output string, now time.Time, days int) (string, error) {
	if days < 1 || days > 397 || !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return "", errRefused
	}
	life := time.Duration(days) * 24 * time.Hour
	ca, caKey, e := authority(s, now, life)
	if e != nil {
		return "", e
	}
	// caKey is never serialized; it goes out of scope with this call.
	der, key, e := leaf(s, ca, caKey, now, life)
	if e != nil {
		return "", e
	}
	pkcs8, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return "", errRefused
	}
	defer clear(pkcs8)
	if os.Mkdir(output, 0700) != nil {
		return "", errRefused
	}
	root, e := os.OpenRoot(output)
	if e != nil {
		return "", errRefused
	}
	defer root.Close()
	for _, file := range []struct {
		name  string
		block *pem.Block
		mode  os.FileMode
	}{
		{"ca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}, 0644},
		{"cert.pem", &pem.Block{Type: "CERTIFICATE", Bytes: der}, 0644},
		{"key.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}, 0600},
	} {
		f, e := root.OpenFile(file.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.mode)
		if e != nil {
			return "", errRefused
		}
		we := pem.Encode(f, file.block)
		se := f.Sync()
		if ce := f.Close(); we != nil || se != nil || ce != nil {
			return "", errRefused
		}
	}
	digest := sha256.Sum256(ca.Raw)
	pairs := make([]string, len(digest))
	for i, b := range digest {
		pairs[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(pairs, ":"), nil
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("keybash-test-tls", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", "", "the DNS name browsers will use")
	address := flags.String("address", "", "or the IP address browsers will use")
	out := flags.String("output", "", "new absolute directory for ca.pem, cert.pem and key.pem")
	days := flags.Int("days", 90, "validity in days, at most 397")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errRefused
	}
	s, e := parseSubject(*name, *address)
	if e != nil {
		return e
	}
	fingerprint, e := issue(s, *out, time.Now(), *days)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(output, "Test HTTPS files written to %s.\nInstall cert.pem and key.pem on the gateway. Trust ca.pem on the test PC only after comparing its fingerprint:\nSHA-256 %s\nIts private key was never written: it cannot sign anything else.\n", *out, fingerprint)
	return e
}

func main() {
	if run(os.Args[1:], os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "test TLS refused: give exactly one of --name or --address, a new absolute --output directory and 1-397 --days")
		os.Exit(1)
	}
}
