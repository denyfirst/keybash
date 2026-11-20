//go:build linux && nativelab

package rdplab

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// All process launching/synthetic root setup is test-only. No installed worker
// launcher, public service or production credential. Read-only system library
// directories are mounted; user homes and credential stores are not.
func nativePrefix(t *testing.T) string {
	t.Helper()
	p := os.Getenv("KEYBASH_NATIVE_PREFIX")
	if os.Geteuid() != 0 || !filepath.IsAbs(p) || !strings.HasPrefix(p, "/tmp/keybash-native.") {
		t.Fatal("native lab requires its isolated CI builder")
	}
	return p
}

func sandboxArgs(prefix string) []string {
	return []string{"--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
		"--hostname", "keybash-native-lab",
		"--cap-drop", "ALL", "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP", "--clearenv",
		"--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
		"--proc", "/proc", "--dev", "/dev", "--perms", "1777", "--tmpfs", "/tmp", "--chmod", "0755", "/",
		"--perms", "0755", "--dir", filepath.Dir(prefix), "--chmod", "0755", filepath.Dir(prefix),
		"--ro-bind", prefix, prefix, "--dir", "/run",
		"--setenv", "HOME", "/tmp", "--setenv", "LANG", "C", "--setenv", "KEYBASH_NATIVE_PREFIX", prefix}
}

// Root performs mount/network setup only. The fixed setpriv helper drops the
// real host UID/GID and every capability before any fixture/worker executes.
// A remapped namespace-root is never the fixture's UID 65534.
func dropNativePrivileges() []string {
	return []string{"--", "/usr/bin/setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--"}
}

type nativeProcess struct {
	done <-chan struct{}
	exit error // written before done closes; read only after done
}

type nativeSetupErrors struct{ text string }

func (d *nativeSetupErrors) Write(p []byte) (int, error) {
	if len(d.text) < 4096 {
		d.text += string(p[:min(len(p), 4096-len(d.text))])
	}
	return len(p), nil
}

func runSandbox(t *testing.T, ctx context.Context, args []string, stdout io.Writer) *nativeProcess {
	t.Helper()
	launch := append([]string{"--clear-groups", "--no-new-privs", "--", "/usr/bin/bwrap"}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", launch...) // #nosec G204 -- fixed sandbox/test binaries, only generated local paths; no browser input.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Stdout = stdout
	diagnostics := &nativeSetupErrors{}
	cmd.Stderr = diagnostics
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatal("native sandbox start failed")
	}
	done := make(chan struct{})
	process := &nativeProcess{done: done}
	go func() {
		process.exit = cmd.Wait()
		if process.exit != nil {
			// Reflect only setup-tool diagnostics, whose inputs are fixed paths/
			// flags. Native library/session logs are never printed.
			for _, line := range strings.Split(diagnostics.text, "\n") {
				if strings.HasPrefix(line, "bwrap: ") || strings.HasPrefix(line, "setpriv: ") {
					fmt.Fprintln(os.Stdout, line)
				}
			}
		}
		close(done)
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
	return process
}

func TestNativeRDPSandboxPreparation(t *testing.T) {
	prefix := nativePrefix(t)
	parent, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, omitNetwork := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		args := sandboxArgs(prefix)
		if omitNetwork {
			args = args[1:]
		}
		args = append(args, "--setenv", "KEYBASH_NATIVE_ROLE", "preflight", "--setenv", "KEYBASH_PARENT_NETNS", parent)
		args = append(args, dropNativePrivileges()...)
		args = append(args, prefix+"/bin/lab.test", "-test.run=^TestNativeRDPChild$", "-test.timeout=2s")
		output := &nativeSetupErrors{}
		process := runSandbox(t, ctx, args, output)
		select {
		case <-process.done:
		case <-ctx.Done():
			cancel()
			t.Fatal("sandbox preparation stalled")
		}
		cancel()
		if !omitNetwork && process.exit != nil {
			t.Fatal("sandbox preparation failed")
		}
		if omitNetwork && (process.exit == nil || !strings.Contains(output.text, "worker shares host network")) {
			t.Fatal("network isolation sabotage escaped its intended assertion")
		}
		if omitNetwork {
			t.Log("Removing the native network namespace failed its intended assertion")
		}
	}
}

// TestNativeRDPChild is the sandbox's preflight child: the worker's identity,
// privileges and network as the manager's sandbox leaves them.
func TestNativeRDPChild(t *testing.T) {
	if os.Getenv("KEYBASH_NATIVE_ROLE") != "preflight" {
		t.Skip("required fixed sandbox child")
	}
	if os.Geteuid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("worker identity was not dropped")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatal("worker retained groups")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal("worker proc unavailable")
	}
	for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapAmb"} {
		if !strings.Contains(string(status), field+":\t0000000000000000") {
			t.Fatal("worker retained capabilities")
		}
	}
	if !strings.Contains(string(status), "NoNewPrivs:\t1") {
		t.Fatal("new privileges permitted")
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns == os.Getenv("KEYBASH_PARENT_NETNS") {
		t.Fatal("worker shares host network")
	}
}

func writeLabFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if os.WriteFile(path, data, 0600) != nil || os.Chmod(path, 0444) != nil {
		t.Fatal("fixture file creation failed")
	}
}

// testPeer runs Keybash's test peer (rdp-testpeer/, IronRDP's own server at
// the pinned commit) in the lab's sandbox: TLS with cert, and NLA for
// synthetic-user with password.
func testPeer(t *testing.T, ctx context.Context, prefix string, cert tls.Certificate, password string) string {
	t.Helper()
	address, _ := testPeerSaying(t, ctx, prefix, cert, password)
	return address
}

// peerLines keeps what the test peer says (`keybash-testpeer: ...`): each
// desktop it opens, each key press and click, and the first pointer move.
// Nothing else it prints is kept or shown.
type peerLines struct {
	mu      sync.Mutex
	pending string
	lines   []string
}

func (p *peerLines) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range b {
		if c != '\n' {
			if len(p.pending) < 64 {
				p.pending += string(c)
			}
			continue
		}
		if line, ok := strings.CutPrefix(p.pending, "keybash-testpeer: "); ok && len(p.lines) < 256 {
			p.lines = append(p.lines, line)
		}
		p.pending = ""
	}
	return len(b), nil
}

// said reports whether the peer said a line that starts with each prefix.
func (p *peerLines) said(prefixes ...string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, prefix := range prefixes {
		if !slices.ContainsFunc(p.lines, func(line string) bool { return strings.HasPrefix(line, prefix) }) {
			return false
		}
	}
	return true
}

// testPeerSaying is testPeer that also keeps what the peer says.
func testPeerSaying(t *testing.T, ctx context.Context, prefix string, cert tls.Certificate, password string) (string, *peerLines) {
	t.Helper()
	dir := t.TempDir()
	writeLabFile(t, filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal("fixture key encoding failed")
	}
	writeLabFile(t, filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	clear(key)
	secret := []byte("synthetic-user\n" + password + "\n")
	writeLabFile(t, filepath.Join(dir, "secret"), secret)
	clear(secret)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_ = probe.Close()
	args := sandboxArgs(prefix)
	// The peer needs a host loopback listener for the broker. Its namespace is
	// still filesystem/PID isolated, but it intentionally shares the host network.
	args = append(args[:0], args[1:]...)
	args = append(args, "--dir", "/run/fixture", "--ro-bind", filepath.Join(dir, "cert.pem"), "/run/fixture/cert.pem",
		"--ro-bind", filepath.Join(dir, "key.pem"), "/run/fixture/key.pem", "--ro-bind", filepath.Join(dir, "secret"), "/run/fixture/secret",
		"--chdir", "/tmp")
	args = append(args, dropNativePrivileges()...)
	args = append(args, prefix+"/bin/keybash-rdp-testpeer", address, "/run/fixture/cert.pem", "/run/fixture/key.pem", "/run/fixture/secret")
	said := &peerLines{}
	runSandbox(t, ctx, args, said)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = c.Close()
			return address, said
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatal("the test peer did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The proxy's TLS refusals are observed by a synthetic Go TLS peer:
// handshake failure/closure must precede ANY CredSSP application data.
func nativeTLSRefusalPeer(t *testing.T, cert tls.Certificate, version uint16, selected byte) (string, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	done := make(chan error, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		reader := bufio.NewReader(raw)
		header := make([]byte, 4)
		if _, err := io.ReadFull(reader, header); err != nil {
			done <- err
			return
		}
		length := int(header[2])<<8 | int(header[3])
		if header[0] != 3 || length < 19 || length > 2048 {
			done <- errors.New("bad synthetic negotiation")
			return
		}
		body := make([]byte, length-4)
		if _, err := io.ReadFull(reader, body); err != nil {
			done <- err
			return
		}
		if bytes.Contains(body, []byte("synthetic-user")) || bytes.Contains(body, []byte("must-not-be-sent")) {
			done <- errors.New("account material leaked in cleartext RDP negotiation")
			return
		}
		confirmation := hybridConfirmation
		confirmation[15] = selected
		if _, err := raw.Write(confirmation[:]); err != nil {
			done <- err
			return
		}
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
		if err := server.Handshake(); err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				done <- errors.New("the TLS refusal timed out without evidence")
				return
			}
			done <- nil
			return
		}
		var b [1]byte
		n, err := server.Read(b[:])
		if n != 0 {
			done <- errors.New("the proxy sent CredSSP before its certificate refusal")
			return
		}
		var timeout net.Error
		if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
			done <- errors.New("the refusal lacked connection closure")
			return
		}
		done <- nil
	}()
	return l.Addr().String(), done
}
