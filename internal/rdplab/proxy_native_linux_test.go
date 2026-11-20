//go:build linux && amd64 && nativelab

package rdplab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

// The browser's first message as IronRDP's connector sends it, told TLS only:
// RDCleanPath version 3390, two ignored strings and an X.224 request for TLS.
// rdp-proxy/src/session.rs makes the same bytes in its tests.
var browserRDCleanPathRequest = func() []byte {
	b, err := hex.DecodeString("3033a00402020d3ea2090c0769676e6f726564a3090c0769676e6f726564a6150413030000130ee000000000000100080001000000")
	if err != nil {
		panic("fixture")
	}
	return b
}()

// nativeProxyChild runs as the unprivileged gateway: it opens a desktop
// through the manager and the sandboxed proxy, and sends what a browser sends.
func nativeProxyChild(t *testing.T, ctx context.Context, cancel context.CancelFunc, path string, dial func(context.Context) (net.Conn, error), dialed *bool, pin *Identity, mode string) {
	password := "Synthetic-managed-NLA-password"
	if mode == "proxy-wrong-password" {
		password = "Not-the-synthetic-password"
	}
	s, err := (ManagerWorker{SocketPath: path}).openBrowserDial(ctx, dial, pin, "synthetic-user", password)
	if mode == "wrong-peer" {
		if s != nil || err == nil || *dialed {
			t.Fatal("a wrong gateway peer obtained launch authority")
		}
		return
	}
	if err != nil || s == nil {
		t.Fatal("managed proxy setup failed")
	}
	defer s.Close()
	if s.WriteMessage(browserRDCleanPathRequest) != nil {
		t.Fatal("the browser's request did not reach the proxy")
	}
	answer, err := s.ReadMessage()
	switch mode {
	case "proxy", "service":
		// The proxy answers only after TLS with the pinned certificate and NLA.
		if err != nil || len(answer) < 2 || answer[0] != 0x30 || !bytes.Contains(answer, pin.der) {
			t.Fatalf("no RDCleanPath response with the pinned certificate (reason %q)", s.Reason())
		}
	case "proxy-wrong-password":
		if err == nil || s.Reason() != terminalweb.ReasonCredentials {
			t.Fatalf("a wrong password ended as %q", s.Reason())
		}
		return
	case "proxy-refusal":
		if err == nil || s.Reason() != terminalweb.ReasonRefused {
			t.Fatalf("a refused server ended as %q", s.Reason())
		}
		return
	default:
		t.Fatalf("unknown proxy mode %q", mode)
	}
	if mode == "service" {
		fmt.Fprintln(os.Stdout, "KB_SERVICE_READY")
		var ack [1]byte
		if _, e := io.ReadFull(os.Stdin, ack[:]); e != nil || ack[0] != 1 {
			t.Fatal("service parent acknowledgement failed")
		}
		if m, e := s.ReadMessage(); e == nil || len(m) != 0 {
			t.Fatal("manager stop retained desktop output")
		}
		if s.WriteMessage([]byte{0x04, 0x02, 0x00}) == nil {
			t.Fatal("manager stop retained desktop input")
		}
	}
	// Revocation: the lease's context ends, and nothing more crosses.
	cancel()
	_ = s.Close()
	if m, e := s.ReadMessage(); e == nil || len(m) != 0 {
		t.Fatal("revoked desktop output escaped")
	}
	if s.WriteMessage([]byte{0x04, 0x02, 0x00}) == nil {
		t.Fatal("revoked desktop input escaped")
	}
}

func serveNativeManager(t *testing.T, ctx context.Context, c ManagerConfig) {
	t.Helper()
	done := make(chan error, 1)
	life, stop := context.WithCancel(ctx)
	go func() { done <- ServeRDPManager(life, c) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("manager shutdown failed to reap")
		}
	})
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); time.Sleep(10 * time.Millisecond) {
		if st, e := os.Stat(c.SocketPath); e == nil && st.Mode().Perm() == 0660 {
			return
		}
	}
	t.Fatal("native manager socket unavailable")
}

// Every desktop is Keybash's RDP proxy in the worker's sandbox, meeting the
// test peer (IronRDP's own server) through the guarded transport:
//   - the right password gets the RDCleanPath answer with the pinned
//     certificate, by name and by Windows' own certificate pinned exactly, and
//     revocation ends it;
//   - a wrong password ends as "credentials";
//   - a gateway that is not the configured one gets nothing, and nothing is
//     dialled;
//   - a server showing another certificate, one past or before its dates, an
//     old TLS version, or a protocol other than NLA, ends as "refused" before
//     any credential leaves the proxy.
func TestNativeRDPManagerProxyMeetsNLAInTheSandbox(t *testing.T) {
	c := nativeManagerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	serveNativeManager(t, ctx, c)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := labCertificate(t, nil, key)
	pin, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	address := testPeer(t, ctx, nativePrefix(t), cert, "Synthetic-managed-NLA-password")
	runManagedGateway(t, c, address, pin, "wrong-peer", 65532)
	runManagedGateway(t, c, address, pin, "proxy", 65533)
	runManagedGateway(t, c, address, pin, "proxy-wrong-password", 65533)

	windows := windowsCertificate(t, key, nil)
	exact, err := NewExactIdentity(windows.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	runManagedGateway(t, c, testPeer(t, ctx, nativePrefix(t), windows, "Synthetic-managed-NLA-password"), exact, "proxy", 65533)

	expired := func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }
	notYet := func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
	}
	for _, refusal := range []struct {
		name     string
		pin      *Identity
		shown    tls.Certificate
		version  uint16
		selected byte
	}{
		{"changed", pin, firstCertificate(labCertificate(t, func(c *x509.Certificate) { c.SerialNumber = big.NewInt(778) }, key)), tls.VersionTLS12, 2},
		{"expired", nil, firstCertificate(labCertificate(t, expired, key)), tls.VersionTLS12, 2},
		{"not yet valid", nil, firstCertificate(labCertificate(t, notYet, key)), tls.VersionTLS12, 2},
		{"TLS 1.1", pin, cert, tls.VersionTLS11, 2},
		{"TLS without NLA", pin, cert, tls.VersionTLS12, 1},
		{"plain RDP", pin, cert, tls.VersionTLS12, 0},
		{"exact, renewed", exact, windowsCertificate(t, key, func(c *x509.Certificate) { c.SerialNumber = big.NewInt(779) }), tls.VersionTLS12, 2},
		{"exact, expired", nil, windowsCertificate(t, key, expired), tls.VersionTLS12, 2},
	} {
		identity := refusal.pin
		if identity == nil {
			// The server shows exactly what is pinned; only its dates are wrong,
			// which the constructors would refuse first: the proxy's own rules
			// are what refuse here.
			name := "synthetic-rdp.invalid"
			if refusal.name == "exact, expired" {
				name = exactLeaf
			}
			identity = rawIdentity(t, name, refusal.shown.Certificate[0])
		}
		address, noCredentials := nativeTLSRefusalPeer(t, refusal.shown, refusal.version, refusal.selected)
		output, failed := tryManagedGateway(c, address, identity, "proxy-refusal", 65533)
		// The peer's evidence first: whether anything after TLS left the proxy.
		select {
		case err := <-noCredentials:
			if err != nil {
				t.Fatalf("%s: %v", refusal.name, err)
			}
		case <-ctx.Done():
			t.Fatalf("%s: the refusal lacked evidence", refusal.name)
		}
		if failed != nil {
			t.Fatalf("%s: managed gateway failed: %s", refusal.name, output)
		}
	}
}

// firstCertificate keeps labCertificate's certificate and drops its digest.
func firstCertificate(cert tls.Certificate, _ [32]byte) tls.Certificate { return cert }
