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
	"math/big"
	"net"
	"os"
	"path/filepath"
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

// nativeProxyChild runs as the unprivileged gateway: it opens a browser desktop
// through the manager and the sandboxed proxy, and sends what a browser sends.
func nativeProxyChild(t *testing.T, ctx context.Context, path string, dial func(context.Context) (net.Conn, error), pin *Identity, mode string) {
	password := "Synthetic-managed-NLA-password"
	if mode == "proxy-wrong-password" {
		password = "Not-the-synthetic-password"
	}
	s, err := (ManagerWorker{SocketPath: path}).openBrowserDial(ctx, dial, pin, "synthetic-user", password)
	if mode == "proxy-unavailable" {
		if s != nil || err == nil {
			t.Fatal("a runtime without the proxy started one")
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
	case "proxy":
		// The proxy answers only after TLS with the pinned certificate and NLA.
		if err != nil || len(answer) < 2 || answer[0] != 0x30 || !bytes.Contains(answer, pin.der) {
			t.Fatalf("no RDCleanPath response with the pinned certificate (reason %q)", s.Reason())
		}
	case "proxy-wrong-password":
		if err == nil || s.Reason() != terminalweb.ReasonCredentials {
			t.Fatalf("a wrong password ended as %q", s.Reason())
		}
	case "proxy-refusal":
		if err == nil || s.Reason() != terminalweb.ReasonRefused {
			t.Fatalf("another certificate ended as %q", s.Reason())
		}
	default:
		t.Fatalf("unknown proxy mode %q", mode)
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

// The proxy runs in the worker's sandbox in guacd's place and meets the
// synthetic NLA peer through the guarded transport: the right password gets
// the RDCleanPath answer with the pinned certificate, a wrong one ends as
// "credentials", another certificate ends before any credential, and a
// runtime without the proxy refuses the lease.
func TestNativeRDPManagerProxyMeetsNLAInTheSandbox(t *testing.T) {
	c := nativeManagerFixture(t)
	if !runtimeHasProxy(c) {
		t.Fatal("the native lab runtime lacks the proxy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
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
	address, _ := nativePeerWithInput(t, ctx, nativePrefix(t), cert, "Synthetic-managed-NLA-password")
	runManagedGateway(t, c, address, pin, "proxy", 65533)
	runManagedGateway(t, c, address, pin, "proxy-wrong-password", 65533)
	changed, _ := labCertificate(t, func(c *x509.Certificate) { c.SerialNumber = big.NewInt(779) }, key)
	refusal, noCredentials := nativeTLSRefusalPeer(t, changed, tls.VersionTLS12, 2)
	runManagedGateway(t, c, refusal, pin, "proxy-refusal", 65533)
	select {
	case err := <-noCredentials:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("the proxy's TLS refusal lacked evidence")
	}

	// The same runtime without the proxy: the lease is refused.
	bare := nativeManagerFixture(t)
	if os.Remove(filepath.Join(bare.Runtime, rdpProxyPath)) != nil || runtimeHasProxy(bare) {
		t.Fatal("proxy removal fixture failed")
	}
	digest, err := RuntimeInventory(bare.Runtime)
	if err != nil {
		t.Fatal("runtime without the proxy refused by inventory")
	}
	bare.RuntimeDigest = digest
	serveNativeManager(t, ctx, bare)
	runManagedGateway(t, bare, address, pin, "proxy-unavailable", 65533)
}
