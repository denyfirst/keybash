//go:build browserlab

package identity

// Go-only interactive preview for a workstation without Node: the same
// synthetic account, credentials and simulated workers as demo-browser.mjs,
// prepared through the store operations the HTTP flow uses and served on a
// fixed loopback address for a person to open in their own browser. Every
// seam stays in _test.go; nothing here enters the shipped command.
import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const demoServePassword = "Synthetic Keybash demo password 73!"

// demoServeCertificate is minted per run. httptest's built-in certificate has
// a private key published in Go's source; a person accepting a browser
// exception for the demo must not be accepting that one.
func demoServeCertificate(t *testing.T, ip netip.Addr) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("demo certificate key failed")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal("demo certificate serial failed")
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour),
		IPAddresses: []net.IP{ip.AsSlice()}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("demo certificate failed")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestInteractiveDemoServe(t *testing.T) {
	address := os.Getenv("KEYBASH_DEMO_SERVE")
	if address == "" {
		t.Skip("opt-in workstation preview; use scripts/demo.ps1 -Serve")
	}
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().Is4() || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 || endpoint.String() != address {
		t.Fatal("demo address must be a numeric IPv4 loopback address with a port")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	store, _, _, code := custodyFixture(t)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("demo address is busy")
	}
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener = listener
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.IdleTimeout = 10 * time.Second
	server.Config.MaxHeaderBytes = 8192
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("demo entropy failed")
	}
	block, err := ssh.MarshalPrivateKey(key, "ephemeral interactive demo")
	if err != nil {
		t.Fatal("demo key encoding failed")
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal("demo signer failed")
	}
	desktop := remoteTargetFixture(t)
	desktop.Name = "Desktop demo (simulation, not Windows)"
	terminal := desktop
	terminal.ID, terminal.Name, terminal.Protocol = strings.Repeat("b", 32), "Linux SSH UI demo (simulation)", "ssh"
	terminal.Identity = signer.PublicKey().Marshal()
	worker := &demoWorker{}
	origin := "https://" + address
	lab, err := NewRemoteLab(origin, store, []RemoteTarget{terminal, desktop}, worker, worker)
	if err != nil {
		t.Fatal("demo admission failed")
	}
	defer lab.Close()

	// The account, factor, credentials and connections are prepared through
	// the same store operations the browser flow reaches, so every boundary
	// the person then exercises (login, MFA, ownership, trust) is the real one.
	hash, err := HashPassword(demoServePassword)
	if err != nil || store.bootstrap(code, "demo", hash, time.Now()) != nil {
		t.Fatal("demo account failed")
	}
	account, err := store.lookup("demo")
	if err != nil {
		t.Fatal("demo account missing")
	}
	seed, err := newSeed()
	if err != nil {
		t.Fatal("demo factor seed failed")
	}
	now := time.Now()
	recovery, err := store.enroll(account.ID, account.Revision, seed, otpCode(t, seed, now.Unix()/30), now, false)
	if err != nil {
		t.Fatal("demo factor enrollment failed")
	}
	for _, sample := range []struct {
		target RemoteTarget
		record Credential
	}{
		{terminal, Credential{Name: "Linux SSH · UI simulyasiyası", Kind: "ssh-key", Username: "synthetic-user", Secret: string(pem.EncodeToMemory(block))}},
		{desktop, Credential{Name: "Desktop · UI simulyasiyası (Windows deyil)", Kind: "password", Username: "synthetic-user", Secret: demoRemotePassword}},
	} {
		if validateCredential(&sample.record) != nil {
			t.Fatal("demo credential refused")
		}
		id, err := store.putCredential(account.ID, sample.record)
		if err != nil {
			t.Fatal("demo credential failed")
		}
		if _, err = store.putConnection(account.ID, connection{Name: sample.record.Name, Target: sample.target.ID, Credential: id,
			Approval: approvalFingerprint(sample.target), Fingerprint: identityFingerprint(sample.target)}); err != nil {
			t.Fatal("demo connection failed")
		}
	}

	server.Config.Handler = lab
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{demoServeCertificate(t, endpoint.Addr())}}
	server.StartTLS()
	defer server.Close()
	// Synthetic, single-run demo factors only; they die with this process.
	fmt.Printf("\nKeybash demo hazırdır: %s/login\n", origin)
	fmt.Printf("İstifadəçi: demo\nŞifrə: %s\n", demoServePassword)
	fmt.Printf("MFA seed (autentifikatora əl ilə əlavə et): %s\n", seed)
	fmt.Printf("Birdəfəlik bərpa kodları (MFA kodu yerinə, hər biri bir dəfə):\n  %s\n", strings.Join(recovery, "\n  "))
	fmt.Printf("Sertifikat bu işə salma üçün yaradılıb; brauzer xəbərdarlığını yalnız bu ünvan üçün qəbul et.\n")
	fmt.Printf("Simulyasiyadır: real Linux shell və Windows yoxdur. Ctrl+C və ya bir saat sonra dayanır.\n\n")
	<-ctx.Done()
}
