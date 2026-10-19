//go:build linux && amd64 && sshprocesslab

package sshtransport

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const gatewayFixtureUID = 65533

func startManagerFixture(t *testing.T) (ManagerConfig, context.CancelFunc, <-chan error) {
	t.Helper()
	w := processFixtureManager(t)
	dir, err := os.MkdirTemp(filepath.Dir(w.Path), "manager-")
	if err != nil || os.Chmod(dir, 0755) != nil {
		t.Fatal("manager directory failed")
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	config := ManagerConfig{SocketPath: filepath.Join(dir, "control.sock"), Worker: w, GatewayUID: gatewayFixtureUID, GatewayGID: gatewayFixtureUID}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSSHManager(ctx, config) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("manager shutdown failed")
			}
		case <-time.After(3 * time.Second):
			t.Error("manager shutdown did not join leases")
		}
	})
	for until := time.Now().Add(2 * time.Second); time.Now().Before(until); {
		if info, err := os.Stat(config.SocketPath); err == nil && info.Mode().Perm() == 0660 {
			return config, cancel, done
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("manager did not create protected socket")
	return ManagerConfig{}, cancel, done
}

func runGatewayFixture(t *testing.T, config ManagerConfig, mode string, uid, gid uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHManagerGatewayChild$", "-test.timeout=30s", "-test.v") // #nosec G204 -- fixed test executable and test-only environment, no command from IPC.
	cmd.Dir = filepath.Dir(config.Worker.Path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "KEYBASH_MANAGER_FIXTURE=" + config.SocketPath, "KEYBASH_MANAGER_MODE=" + mode}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{gatewayFixtureUID}}}
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged gateway fixture failed (%s): %s", mode, data)
	}
}

func TestSSHManagerUnprivilegedGateway(t *testing.T) {
	config, _, _ := startManagerFixture(t)
	if ServeSSHManager(context.Background(), config) == nil {
		t.Fatal("second manager replaced a live socket")
	}
	runGatewayFixture(t, config, "positive", gatewayFixtureUID, gatewayFixtureUID)
}

func TestSSHManagerRejectsWrongPeer(t *testing.T) {
	config, _, _ := startManagerFixture(t)
	runGatewayFixture(t, config, "wrong-peer", 65532, gatewayFixtureUID)
	runGatewayFixture(t, config, "wrong-peer", gatewayFixtureUID, 65532)
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: config.SocketPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal("root peer fixture dial failed")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if expectManagerPacket(conn, managerHello) == nil {
		t.Fatal("root was accepted as gateway")
	}
}

func TestSSHManagerMalformedReplayAndQuota(t *testing.T) {
	config, _, _ := startManagerFixture(t)
	runGatewayFixture(t, config, "abuse", gatewayFixtureUID, gatewayFixtureUID)
}

func TestSSHManagerShutdownRevokesGateway(t *testing.T) {
	config, cancel, _ := startManagerFixture(t)
	// The child writes a nonsecret readiness marker through stdout only after
	// real SSH authentication. Parent then stops the separate root manager.
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHManagerGatewayChild$", "-test.timeout=12s") // #nosec G204 -- fixed synthetic test executable.
	cmd.Dir = filepath.Dir(config.Worker.Path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "KEYBASH_MANAGER_FIXTURE=" + config.SocketPath, "KEYBASH_MANAGER_MODE=shutdown"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: gatewayFixtureUID, Gid: gatewayFixtureUID}}
	output, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		t.Fatal("shutdown gateway start failed")
	}
	marker := make([]byte, len("gateway-ready\n"))
	if _, err := io.ReadFull(output, marker); err != nil || string(marker) != "gateway-ready\n" {
		t.Fatal("gateway did not authenticate before manager shutdown")
	}
	cancel()
	if data, err := io.ReadAll(output); err != nil {
		t.Fatal("shutdown output failed")
	} else if cmd.Wait() != nil {
		t.Fatalf("manager shutdown did not revoke gateway: %s", data)
	}
}

func TestSSHManagerCrashRevokesGateway(t *testing.T) {
	w := processFixtureManager(t)
	dir, err := os.MkdirTemp(filepath.Dir(w.Path), "crash-")
	if err != nil || os.Chmod(dir, 0755) != nil {
		t.Fatal("crash directory failed")
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join(dir, "control.sock")); _ = os.Remove(dir) })
	config := ManagerConfig{SocketPath: filepath.Join(dir, "control.sock"), Worker: w, GatewayUID: gatewayFixtureUID, GatewayGID: gatewayFixtureUID}
	manager := exec.Command(filepath.Join(filepath.Dir(w.Path), "manager"), "-socket", config.SocketPath, "-worker", w.Path, "-worker-sha256", hex.EncodeToString(w.Digest[:]), "-gateway-uid", "65533", "-gateway-gid", "65533") // #nosec G204 -- fixed root-owned synthetic manager and administrator config, never browser input.
	manager.Env = []string{"PATH=/usr/bin:/bin"}
	if manager.Start() != nil {
		t.Fatal("separate manager did not start")
	}
	defer func() { _ = manager.Process.Kill(); _ = manager.Wait() }()
	ready := false
	for until := time.Now().Add(2 * time.Second); time.Now().Before(until); {
		if info, err := os.Stat(config.SocketPath); err == nil && info.Mode().Perm() == 0660 {
			ready = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ready {
		t.Fatal("separate manager socket missing")
	}
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	gateway := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHManagerGatewayChild$", "-test.timeout=12s") // #nosec G204 -- fixed synthetic gateway test executable.
	gateway.Dir = filepath.Dir(w.Path)
	gateway.Env = []string{"PATH=/usr/bin:/bin", "KEYBASH_MANAGER_FIXTURE=" + config.SocketPath, "KEYBASH_MANAGER_MODE=shutdown"}
	gateway.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: gatewayFixtureUID, Gid: gatewayFixtureUID}}
	output, err := gateway.StdoutPipe()
	if err != nil || gateway.Start() != nil {
		t.Fatal("crash gateway start failed")
	}
	defer func() { _ = gateway.Process.Kill() }()
	marker := make([]byte, len("gateway-ready\n"))
	if _, err := io.ReadFull(output, marker); err != nil || string(marker) != "gateway-ready\n" {
		t.Fatal("gateway did not authenticate before manager crash")
	}
	if manager.Process.Kill() != nil {
		t.Fatal("manager crash fixture failed")
	}
	data, err := io.ReadAll(output)
	if err != nil {
		t.Fatal("crash output failed")
	}
	if gateway.Wait() != nil {
		t.Fatalf("manager crash did not revoke gateway: %s", data)
	}
}

func dialManagerFixture(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal("manager fixture dial failed")
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	return conn
}

func TestSSHManagerGatewayChild(t *testing.T) {
	path, mode := os.Getenv("KEYBASH_MANAGER_FIXTURE"), os.Getenv("KEYBASH_MANAGER_MODE")
	if path == "" {
		t.Skip("only a dedicated unprivileged subprocess runs this fixture")
	}
	if os.Geteuid() == 0 || !strings.HasPrefix(path, "/tmp/keybash-ssh-process.") {
		t.Fatal("invalid unprivileged fixture")
	}
	if mode == "wrong-peer" {
		conn := dialManagerFixture(t, path)
		if expectManagerPacket(conn, managerHello) == nil {
			t.Fatal("wrong gateway peer accepted")
		}
		return
	}
	if os.Geteuid() != gatewayFixtureUID || os.Getegid() != gatewayFixtureUID {
		t.Fatal("gateway did not drop privileges")
	}
	if mode == "abuse" {
		testManagerAbuse(t, path)
		return
	}
	worker := ManagerWorker{SocketPath: path}
	user, _ := processFixtureKey(t)
	host := syntheticSigner(t)
	closed := make(chan struct{})
	f := newFixture(t, fixtureOptions{host: host, user: user, shellFixture: func(c ssh.Channel) { defer close(closed); _, _ = io.Copy(c, c) }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := worker.open(ctx, "ssh.invalid", func(context.Context) (net.Conn, error) { return f.client, nil }, host.PublicKey().Marshal(), "lab-user", user)
	if err != nil {
		t.Fatal("valid unprivileged gateway refused")
	}
	defer s.Close()
	text := []byte("manager SSH: əöğ\r\n")
	got := make([]byte, len(text))
	if _, err := s.Write(text); err != nil {
		t.Fatal("manager terminal input refused")
	}
	if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, text) {
		t.Fatal("manager terminal bytes changed")
	}
	if s.Resize(150, 45) != nil || s.Resize(501, 45) == nil {
		t.Fatal("manager resize boundary failed")
	}
	if mode == "shutdown" {
		_, _ = os.Stdout.WriteString("gateway-ready\n")
		select {
		case <-closed:
		case <-time.After(4 * time.Second):
			t.Fatal("manager shutdown retained SSH connection")
		}
		if n, err := s.Read(got); n != 0 || err == nil {
			t.Fatal("manager shutdown retained output")
		}
		return
	}
	holders := make([]*net.UnixConn, 0, managerSlots-1)
	for range managerSlots - 1 {
		conn := dialManagerFixture(t, path)
		if expectManagerPacket(conn, managerHello) != nil {
			t.Fatal("active manager quota refused within capacity")
		}
		holders = append(holders, conn)
	}
	excess := dialManagerFixture(t, path)
	if expectManagerPacket(excess, managerHello) == nil {
		t.Fatal("active manager lease did not count against quota")
	}
	for _, conn := range holders {
		_ = conn.Close()
	}
	_ = excess.Close()
	cancel()
	if s.Close() != nil {
		t.Fatal("manager cancellation did not reap child")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("manager cancellation retained SSH connection")
	}
	if n, err := s.Read(got); n != 0 || err == nil {
		t.Fatal("revoked manager output remained readable")
	}
	// A second launch uses a different synthetic host/key; the manager must not
	// retain the previous launch's parameters or turn a refusal into readiness.
	f2 := newFixture(t, fixtureOptions{host: host, user: user})
	refusal, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	dialed := false
	s2, err := worker.open(refusal, "ssh.invalid", func(context.Context) (net.Conn, error) { dialed = true; return f2.client, nil }, syntheticSigner(t).PublicKey().Marshal(), "lab-user", user)
	if s2 != nil {
		_ = s2.Close()
	}
	if err == nil || f2.auth.Load() != 0 || !dialed || refusal.Err() != nil {
		t.Fatal("manager changed pin reached authentication")
	}
}

func testManagerAbuse(t *testing.T, path string) {
	t.Helper()
	// Malformed schemas, arbitrary regular files and extra capabilities never
	// receive active. All packets are local synthetic data; no secrets are sent.
	in, inWrite := testManagerPipe(t)
	_, out := testManagerPipe(t)
	for _, bad := range []struct {
		packet string
		files  []*os.File
	}{
		{"start/v2", nil}, {managerStart, nil}, {managerStart, []*os.File{in, in, out}},
		{managerStart, []*os.File{in, in, out, out}},
		{managerStart, []*os.File{in, in, out, out, out}}, {strings.Repeat("x", 65), nil},
	} {
		conn := dialManagerFixture(t, path)
		if expectManagerPacket(conn, managerHello) != nil {
			t.Fatal("valid gateway admission refused")
		}
		if writeManagerPacket(conn, bad.packet, bad.files...) != nil {
			t.Fatal("malformed fixture send failed")
		}
		if expectManagerPacket(conn, managerActive) == nil {
			t.Fatal("unsafe manager launch accepted")
		}
		_ = conn.Close()
	}
	// Hold every pending slot without sending key material or launching a child.
	holders := make([]*net.UnixConn, 0, managerSlots)
	for range managerSlots {
		conn := dialManagerFixture(t, path)
		if expectManagerPacket(conn, managerHello) != nil {
			t.Fatal("manager quota refused within capacity")
		}
		holders = append(holders, conn)
	}
	excess := dialManagerFixture(t, path)
	if expectManagerPacket(excess, managerHello) == nil {
		t.Fatal("manager quota exceeded")
	}
	for _, conn := range holders {
		_ = conn.Close()
	}
	_ = excess.Close()
	// Capacity is returned after an authenticated peer disconnects. Poll until
	// the server observes EOF, bounded well below the five-second setup timeout.
	var conn *net.UnixConn
	for until := time.Now().Add(time.Second); time.Now().Before(until); {
		candidate := dialManagerFixture(t, path)
		if expectManagerPacket(candidate, managerHello) == nil {
			conn = candidate
			break
		}
		_ = candidate.Close()
		time.Sleep(5 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("manager did not release disconnected lease capacity")
	}
	// A connected TCP plus correctly oriented pipes can launch one child, but
	// a repeated start on its lease must kill it, before any SSH key is sent.
	f := newFixture(t, fixtureOptions{host: syntheticSigner(t), user: syntheticSigner(t)})
	tcp, err := f.client.(*net.TCPConn).File()
	if err != nil {
		t.Fatal("replay TCP fixture failed")
	}
	defer tcp.Close()
	if writeManagerPacket(conn, managerStart, tcp, in, out) != nil || expectManagerPacket(conn, managerActive) != nil {
		t.Fatal("valid descriptor launch refused")
	}
	_ = in.Close()
	_ = out.Close()
	if writeManagerPacket(conn, managerStart) != nil || expectManagerPacket(conn, managerDone) != nil {
		t.Fatal("replayed launch did not terminate lease")
	}
	if _, err := inWrite.Write([]byte("not-a-start")); err == nil {
		t.Fatal("replayed manager lease retained worker input")
	}
	stalled := dialManagerFixture(t, path)
	if expectManagerPacket(stalled, managerHello) != nil {
		t.Fatal("stalled fixture admission refused")
	}
	started := time.Now()
	if expectManagerPacket(stalled, managerActive) == nil || time.Since(started) < 4*time.Second || time.Since(started) > 7*time.Second {
		t.Fatal("stalled manager setup did not expire")
	}
}
