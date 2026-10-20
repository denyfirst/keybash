//go:build linux && amd64 && nativelab

package rdplab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func nativeManagerFixture(t *testing.T) ManagerConfig {
	t.Helper()
	prefix := nativePrefix(t)
	dir, e := os.MkdirTemp("/tmp", "keybash-managed-")
	if e != nil || os.Chmod(dir, 0755) != nil {
		t.Fatal("managed stage failed")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if os.CopyFS(filepath.Join(dir, "runtime"), os.DirFS(filepath.Join(prefix, "runtime-stage"))) != nil {
		t.Fatal("minimal runtime copy failed")
	}
	worker, e := os.ReadFile(filepath.Join(prefix, "bin/keybash-rdp-worker"))
	if e != nil {
		t.Fatal("worker source build unavailable")
	}
	path := filepath.Join(dir, "worker")
	if os.WriteFile(path, worker, 0755) != nil {
		t.Fatal("worker stage failed")
	} // #nosec G306 -- public static test worker.
	digest, e := RuntimeInventory(filepath.Join(dir, "runtime"))
	if e != nil {
		t.Fatal("native runtime inventory refused")
	}
	c := ManagerConfig{SocketPath: filepath.Join(dir, "control.sock"), WorkerPath: path, Runtime: filepath.Join(dir, "runtime"), WorkerDigest: sha256.Sum256(worker), RuntimeDigest: digest, GatewayUID: 65533, GatewayGID: 65533, WorkerUID: 65531, WorkerGID: 65531, MaxSessions: 2}
	if image, e := openRDPImage(c); e != nil {
		t.Fatal("approved native image refused")
	} else {
		_ = image.Close()
	}
	return c
}

func TestNativeRDPManagerRuntimeAndProvenance(t *testing.T) {
	c := nativeManagerFixture(t)
	for _, bad := range []func(*ManagerConfig){func(c *ManagerConfig) { c.RuntimeDigest[0] ^= 1 }, func(c *ManagerConfig) { c.WorkerDigest[0] ^= 1 }, func(c *ManagerConfig) { c.WorkerUID = c.GatewayUID }} {
		x := c
		bad(&x)
		if f, e := openRDPImage(x); e == nil {
			_ = f.Close()
			t.Fatal("unapproved runtime or image accepted")
		}
	}
	link := filepath.Join(c.Runtime, "unexpected")
	if os.Symlink("/etc/passwd", link) != nil {
		t.Fatal("symlink fixture failed")
	}
	if _, e := RuntimeInventory(c.Runtime); e == nil {
		t.Fatal("runtime symlink accepted")
	}
	_ = os.Remove(link)
	if os.Chmod(c.Runtime, 0775) != nil {
		t.Fatal("mode fixture failed")
	}
	if _, e := RuntimeInventory(c.Runtime); e == nil {
		t.Fatal("writable runtime accepted")
	}
	_ = os.Chmod(c.Runtime, 0755)
	file, e := sealedRDPFile([]byte("public trust"))
	if e != nil {
		t.Fatal("sealed trust failed")
	}
	defer file.Close()
	if _, e = file.WriteAt([]byte("changed"), 0); !errors.Is(e, unix.EPERM) {
		t.Fatal("public trust could be changed")
	}
	if _, e := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, 0); !errors.Is(e, unix.EPERM) {
		t.Fatal("trust seal policy remained mutable")
	}
}

func runManagedGateway(t *testing.T, c ManagerConfig, address string, pin *Identity, mode string, uid uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeRDPManagerGatewayChild$", "-test.v", "-test.timeout=20s") // #nosec G204 -- this exact compiled fixture and fixed selector.
	cmd.Dir = "/tmp"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "KEYBASH_MANAGED_SOCKET=" + c.SocketPath, "KEYBASH_MANAGED_ADDRESS=" + address, "KEYBASH_MANAGED_PIN=" + base64.StdEncoding.EncodeToString(pin.der), "KEYBASH_MANAGED_MODE=" + mode}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: c.GatewayGID, Groups: []uint32{c.GatewayGID}}}
	if data, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("managed gateway failed: %s", data)
	}
}

func TestNativeRDPManagerAuthenticationRevocationAndRefusal(t *testing.T) {
	c := nativeManagerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeRDPManager(ctx, c) }()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error("manager shutdown failed")
			}
		case <-time.After(4 * time.Second):
			t.Error("manager shutdown failed to reap")
		}
	}()
	ready := false
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		if st, e := os.Stat(c.SocketPath); e == nil && st.Mode().Perm() == 0660 {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("native manager socket unavailable")
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	cert, _ := labCertificate(t, nil, key)
	pin, e := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	address, marker := nativePeerWithInput(t, ctx, nativePrefix(t), cert, "Synthetic-managed-NLA-password")
	runManagedGateway(t, c, address, pin, "wrong-peer", 65532)
	runManagedGateway(t, c, address, pin, "positive", 65533)
	select {
	case <-marker.ready:
	default:
		t.Fatal("manager success did not authenticate native NLA")
	}
	changed, _ := labCertificate(t, func(c *x509.Certificate) { c.SerialNumber = big.NewInt(778) }, key)
	refusal, noCredentials := nativeTLSRefusalPeer(t, changed, tls.VersionTLS12, 2)
	runManagedGateway(t, c, refusal, pin, "refusal", 65533)
	select {
	case e := <-noCredentials:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("managed TLS refusal lacked evidence")
	}
	t.Log("Actual isolated RDP manager: dedicated identity, minimal runtime, NLA, pin-before-CredSSP, wrong peer and revoked I/O passed")
}

func TestNativeRDPManagerGatewayChild(t *testing.T) {
	path := os.Getenv("KEYBASH_MANAGED_SOCKET")
	if path == "" {
		t.Skip("fixed unprivileged gateway child")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, e := base64.StdEncoding.DecodeString(os.Getenv("KEYBASH_MANAGED_PIN"))
	if e != nil {
		t.Fatal("fixture pin failed")
	}
	pin, e := NewIdentity("synthetic-rdp.invalid", p)
	if e != nil {
		t.Fatal("fixture identity failed")
	}
	dialed := false
	dial := func(c context.Context) (net.Conn, error) {
		dialed = true
		return (&net.Dialer{}).DialContext(c, "tcp", os.Getenv("KEYBASH_MANAGED_ADDRESS"))
	}
	s, e := (ManagerWorker{SocketPath: path}).openDial(ctx, dial, pin, "synthetic-user", "Synthetic-managed-NLA-password")
	mode := os.Getenv("KEYBASH_MANAGED_MODE")
	if mode == "wrong-peer" {
		if s != nil || e == nil || dialed {
			t.Fatal("wrong gateway peer obtained launch authority")
		}
		return
	}
	if e != nil || s == nil {
		t.Fatal("managed RDP setup failed")
	}
	defer s.Close()
	if mode == "refusal" {
		_, e = io.Copy(io.Discard, s)
		if e == nil || ctx.Err() != nil {
			t.Fatal("managed invalid pin failed to refuse")
		}
		return
	}
	if _, e = s.Write(encodedInstruction(t, instruction{"mouse", "120", "120", "0"})); e != nil {
		t.Fatal("managed input failed")
	}
	got := make(chan error, 1)
	go func() {
		reader := make([]byte, 8192)
		var all bytes.Buffer
		for all.Len() < 256*1024 {
			n, e := s.Read(reader)
			_, _ = all.Write(reader[:n])
			if bytes.Contains(all.Bytes(), []byte("5.cfill")) || bytes.Contains(all.Bytes(), []byte("3.img")) {
				got <- nil
				return
			}
			if e != nil {
				got <- e
				return
			}
		}
		got <- errNative
	}()
	select {
	case e := <-got:
		if e != nil {
			t.Fatal("managed native desktop did not render")
		}
	case <-ctx.Done():
		t.Fatal("managed native desktop stalled")
	}
	cancel()
	if s.Close() != nil {
		t.Fatal("managed revocation failed")
	}
	var b [1024]byte
	if n, _ := s.Read(b[:]); n != 0 {
		t.Fatal("revoked native output escaped")
	}
	if _, e = s.Write(encodedInstruction(t, instruction{"key", "97", "1"})); e == nil {
		t.Fatal("revoked native input escaped")
	}
}
