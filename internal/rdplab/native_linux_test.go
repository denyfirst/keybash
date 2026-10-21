//go:build linux && nativelab

package rdplab

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"image/png"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
	"golang.org/x/sys/unix"
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
		"--setenv", "LD_LIBRARY_PATH", prefix + "/lib", "--setenv", "HOME", "/tmp", "--setenv", "LANG", "C",
		"--setenv", "WLOG_LEVEL", "ERROR", "--setenv", "KEYBASH_NATIVE_PREFIX", prefix}
}

// Root performs mount/network setup only. The fixed setpriv helper drops the
// real host UID/GID and every capability before any fixture/worker executes.
// A remapped namespace-root must never be accepted as the IPC's UID 65534.
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

// Only generated integration-stage constants can reach CI. Native diagnostic
// lines, credential values and remote text are discarded, not reflected.
type nativeStages struct{ pending string }

func (s *nativeStages) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			if strings.HasPrefix(s.pending, "KB_NATIVE_ERROR_") {
				codes := strings.Split(strings.TrimPrefix(s.pending, "KB_NATIVE_ERROR_"), "_")
				if len(codes) == 2 {
					_, first := strconv.ParseUint(codes[0], 10, 32)
					_, second := strconv.ParseUint(codes[1], 10, 32)
					if first == nil && second == nil {
						fmt.Fprintln(os.Stdout, s.pending)
					}
				}
			}
			for _, stage := range []string{"KB_STAGE_CONTEXT", "KB_STAGE_NETWORK", "KB_STAGE_SETTINGS", "KB_STAGE_GDI", "KB_STAGE_GDI_READY", "KB_STAGE_CHANNELS", "KB_STAGE_IDENTITY", "KB_STAGE_POST_READY", "KB_STAGE_CONNECTED"} {
				if s.pending == stage {
					fmt.Fprintln(os.Stdout, stage)
				}
			}
			s.pending = ""
		} else if len(s.pending) < 256 {
			s.pending += string(b)
		}
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

type nativeMarker struct {
	mu                         sync.Mutex
	tail                       string
	ready                      chan struct{}
	once                       sync.Once
	keys, mouse                chan struct{}
	keysOnce, mouseOnce        sync.Once
	clipboard, resized         chan struct{}
	clipboardOnce, resizedOnce sync.Once
}

func (m *nativeMarker) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range p {
		if b == '\n' {
			switch m.tail {
			case "KB_AUTHENTICATED":
				m.once.Do(func() { close(m.ready) })
			case "KB_INPUT_A":
				m.keysOnce.Do(func() { close(m.keys) })
			case "KB_INPUT_MOUSE":
				m.mouseOnce.Do(func() { close(m.mouse) })
			case "KB_CLIPBOARD_LOCAL":
				m.clipboardOnce.Do(func() { close(m.clipboard) })
			case "KB_DESKTOP_RESIZED":
				m.resizedOnce.Do(func() { close(m.resized) })
			}
			m.tail = ""
		} else if len(m.tail) < 256 {
			m.tail += string(b)
		}
	}
	return len(p), nil
}

func writeLabFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if os.WriteFile(path, data, 0600) != nil || os.Chmod(path, 0444) != nil {
		t.Fatal("fixture file creation failed")
	}
}

func nativePeer(t *testing.T, ctx context.Context, prefix string, cert tls.Certificate, password string) (string, <-chan struct{}) {
	address, marker := nativePeerWithInput(t, ctx, prefix, cert, password)
	return address, marker.ready
}

func nativePeerWithInput(t *testing.T, ctx context.Context, prefix string, cert tls.Certificate, password string) (string, *nativeMarker) {
	t.Helper()
	dir := t.TempDir()
	writeLabFile(t, filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("fixture requires fresh RSA")
	}
	writeLabFile(t, filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	// NTLM's legacy SAM hash exists only for the synthetic peer, never a vault.
	h := md4.New()
	var encoded []byte
	for _, r := range utf16.Encode([]rune(password)) {
		encoded = append(encoded, byte(r), byte(r>>8))
	}
	_, _ = h.Write(encoded)
	clear(encoded)
	sam := []byte("synthetic-user:::" + hex.EncodeToString(h.Sum(nil)) + ":\n")
	writeLabFile(t, filepath.Join(dir, "SAM"), sam)
	clear(sam)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	args := sandboxArgs(prefix)
	// Peer needs a host loopback listener for the broker. Its namespace is still
	// filesystem/PID isolated, but it intentionally shares the test host network.
	args = append(args[:0], args[1:]...)
	args = append(args, "--dir", "/run/fixture", "--ro-bind", filepath.Join(dir, "cert.pem"), "/run/fixture/cert.pem",
		"--ro-bind", filepath.Join(dir, "key.pem"), "/run/fixture/key.pem", "--ro-bind", filepath.Join(dir, "SAM"), "/run/fixture/SAM",
		"--ro-bind", prefix+"/share/lab/test_icon.bmp", "/tmp/test_icon.bmp", "--chdir", "/tmp")
	args = append(args, dropNativePrivileges()...)
	args = append(args, prefix+"/bin/sfreerdp-server", fmt.Sprintf("--port=%d", port), "--cert=/run/fixture/cert.pem", "--key=/run/fixture/key.pem")
	marker := &nativeMarker{ready: make(chan struct{}), keys: make(chan struct{}), mouse: make(chan struct{}), clipboard: make(chan struct{}), resized: make(chan struct{})}
	runSandbox(t, ctx, args, marker)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatal("synthetic NLA peer did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return address, marker
}

func nativeSocket(t *testing.T, path string) *net.UnixListener {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(path, 0666) != nil {
		t.Fatal("test IPC permissions failed")
	}
	// Host parent directory remains 0700. Only individual socket inodes are
	// bound into the isolated UID's namespace; they are not public listeners.
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func acceptNative(ctx context.Context, l *net.UnixListener) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	c, err := l.AcceptUnix()
	if err != nil {
		return nil, errNative
	}
	_ = l.Close()
	raw, err := c.SyscallConn()
	if err != nil {
		_ = c.Close()
		return nil, errNative
	}
	allowed := false
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		allowed = e == nil && cred.Uid == 65534
	})
	if err != nil || !allowed {
		_ = c.Close()
		return nil, errNative
	}
	return c, nil
}

func TestNativeRDPControlIPCRejectsWrongUID(t *testing.T) {
	_ = nativePrefix(t)
	path := filepath.Join(t.TempDir(), "control.sock")
	l := nativeSocket(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		t.Fatal("synthetic wrong-UID IPC dial failed")
	}
	defer client.Close()
	// The trusted parent runs as root; it must not impersonate the dropped
	// worker merely by reaching the socket. The real native cases prove that
	// UID 65534 succeeds inside its private mounted capability boundary.
	connection, err := acceptNative(ctx, l)
	if connection != nil {
		_ = connection.Close()
		t.Fatal("wrong-UID process obtained native IPC")
	}
	if err != errNative {
		t.Fatal("wrong-UID native IPC was not refused")
	}
	if client.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("synthetic IPC deadline failed")
	}
	var b [1]byte
	n, err := client.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("refused IPC transport stayed open")
	}
}

func launchNativeWorker(t *testing.T, ctx context.Context, prefix string, identity *Identity, dial func(context.Context) (net.Conn, error)) (net.Conn, *nativeProcess, <-chan error) {
	t.Helper()
	dir := t.TempDir()
	control := nativeSocket(t, filepath.Join(dir, "control.sock"))
	target := nativeSocket(t, filepath.Join(dir, "target.sock"))
	writeLabFile(t, filepath.Join(dir, "approved.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.der}))
	writeLabFile(t, filepath.Join(dir, "name"), []byte(identity.name))
	writeLabFile(t, filepath.Join(dir, "host-sentinel"), []byte("synthetic host secret"))
	parentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	args := sandboxArgs(prefix)
	args = append(args, "--dir", "/run/keybash")
	for _, file := range []string{"control.sock", "target.sock", "approved.pem", "name"} {
		args = append(args, "--ro-bind", filepath.Join(dir, file), "/run/keybash/"+file)
	}
	args = append(args, "--setenv", "KEYBASH_NATIVE_ROLE", "worker", "--setenv", "KEYBASH_PARENT_NETNS", parentNS,
		"--setenv", "KEYBASH_HOST_SENTINEL", filepath.Join(dir, "host-sentinel"))
	args = append(args, dropNativePrivileges()...)
	args = append(args, prefix+"/bin/lab.test", "-test.run=^TestNativeRDPChild$", "-test.timeout=35s")
	// Only this fixed Go test child's assertions reach stdout. guacd and native
	// peer diagnostics remain discarded; they may contain session material.
	cmd := runSandbox(t, ctx, args, os.Stdout)
	lifetime, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() {
		select {
		case <-cmd.done:
		case <-ctx.Done():
		}
		cancel()
	}()
	broker := &nativeBroker{dial: dial}
	done := make(chan error, 1)
	go func() {
		c, err := acceptNative(lifetime, target)
		if err != nil {
			done <- err
			return
		}
		done <- broker.serve(lifetime, c)
	}()
	c, err := acceptNative(lifetime, control)
	if err != nil {
		t.Fatal("worker did not establish private control IPC")
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, cmd, done
}

func TestNativeRDPChild(t *testing.T) {
	role := os.Getenv("KEYBASH_NATIVE_ROLE")
	if role != "worker" && role != "preflight" {
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
	if role == "preflight" {
		return
	}
	if _, err := os.ReadFile(os.Getenv("KEYBASH_HOST_SENTINEL")); err == nil {
		t.Fatal("worker read host file")
	}
	if f, err := os.OpenFile("/run/keybash/name", os.O_WRONLY, 0); err == nil {
		_ = f.Close()
		t.Fatal("worker can replace trust")
	}
	for _, address := range []string{"192.0.2.1:3389", "[2001:db8::1]:3389"} {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		cancel()
		if c != nil {
			_ = c.Close()
		}
		if err == nil {
			t.Fatal("worker obtained independent egress")
		}
	}
	prefix := os.Getenv("KEYBASH_NATIVE_PREFIX")
	guacd := exec.Command("/usr/bin/prlimit", "--as=2147483648", "--cpu=20", "--nofile=64", "--nproc=128", "--core=0", "--", prefix+"/sbin/guacd", "-f", "-b", "127.0.0.1", "-p", "4822", "-L", "error") // #nosec G204 -- verified, read-only CI prefix; never supplied by a browser.
	guacd.Stdout = &nativeStages{}
	guacd.Stderr = io.Discard
	if guacd.Start() != nil {
		t.Fatal("guacd launch failed")
	}
	defer func() { _ = guacd.Process.Kill(); _ = guacd.Wait() }()
	bridge, err := net.Listen("tcp", "127.0.0.1:3390")
	if err != nil {
		t.Fatal("private loopback bridge failed")
	}
	defer bridge.Close()
	go func() {
		local, err := bridge.Accept()
		_ = bridge.Close()
		if err != nil {
			return
		}
		upstream, err := net.Dial("unix", "/run/keybash/target.sock")
		if err != nil {
			_ = local.Close()
			return
		}
		relayNative(local, upstream)
	}()
	var guac net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		guac, err = net.DialTimeout("tcp", "127.0.0.1:4822", 50*time.Millisecond)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("guacd did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	control, err := net.Dial("unix", "/run/keybash/control.sock")
	if err != nil {
		_ = guac.Close()
		t.Fatal("private control IPC failed")
	}
	relayNative(control, guac)
}

func relayNative(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
		_ = src.Close()
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
}

func TestNativeRDPAuthenticationRenderingAndRevocation(t *testing.T) {
	prefix := nativePrefix(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := labCertificate(t, nil, key)
	identity, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprintf("password_valid_%t", valid), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			address, authenticated := nativePeer(t, ctx, prefix, cert, "Synthetic-NLA-password")
			control, process, brokerDone := launchNativeWorker(t, ctx, prefix, identity, func(c context.Context) (net.Conn, error) {
				fmt.Fprintln(os.Stdout, "KB_BROKER_DIAL")
				return (&net.Dialer{}).DialContext(c, "tcp", address)
			})
			password := "wrong-synthetic-password"
			if valid {
				password = "Synthetic-NLA-password"
			}
			plan, err := newNativePlan(identity, "synthetic-user", password)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := nativeConnect(ctx, control, plan)
			if err != nil {
				t.Fatal("native control handshake failed")
			}
			defer stream.close()
			if valid {
				select {
				case <-authenticated:
				case <-ctx.Done():
					t.Fatal("native account did not authenticate")
				}
				// The sample's initial solid background can become a cfill. Its
				// mouse handler paints the nonuniform fixture icon onto layer 0.
				if writeInstruction(control, instruction{"mouse", "120", "120", "0"}) != nil {
					t.Fatal("authenticated native mouse input failed")
				}
			}
			image := false
			type nativeImage struct {
				layer  string
				pixels []byte
			}
			images := make(map[string]*nativeImage)
			imageBytes := 0
			decodedLayers := make(map[string]bool)
			seen := make(map[string]int)
			for {
				in, err := stream.next()
				if err != nil {
					if valid {
						t.Logf("bounded display instruction counts: %v", seen)
						t.Fatalf("native RDP did not render (%v)", stream.failure.Load())
					}
					if ctx.Err() != nil {
						t.Fatal("native password refusal timed out without evidence")
					}
					break
				}
				seen[in[0]]++ // next admits only fixed opcode constants
				if in[0] == "sync" && (len(in) == 2 || len(in) == 3) {
					_ = writeInstruction(control, in)
				}
				if in[0] == "img" {
					if len(in) != 7 || in[4] != "image/png" || len(images) >= 8 || images[in[1]] != nil {
						t.Fatal("invalid or excessive native image streams")
					}
					id, err := strconv.ParseUint(in[1], 10, 16)
					if err != nil || strconv.FormatUint(id, 10) != in[1] {
						t.Fatal("invalid native image stream ID")
					}
					images[in[1]] = &nativeImage{layer: in[3]}
				}
				if in[0] == "blob" {
					if len(in) != 3 || images[in[1]] == nil {
						t.Fatal("unexpected native image blob")
					}
					current := images[in[1]]
					data, err := base64.StdEncoding.Strict().DecodeString(in[2])
					if err != nil || len(current.pixels)+len(data) > 256*1024 || imageBytes+len(data) > 1024*1024 {
						t.Fatal("invalid or excessive native image")
					}
					current.pixels = append(current.pixels, data...)
					imageBytes += len(data)
					if writeInstruction(control, instruction{"ack", in[1], "OK", "0"}) != nil {
						t.Fatal("native image acknowledgement failed")
					}
				}
				if in[0] == "end" {
					if len(in) != 2 || images[in[1]] == nil {
						t.Fatal("unexpected native image end")
					}
					current := images[in[1]]
					config, err := png.DecodeConfig(bytes.NewReader(current.pixels))
					if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 1024 || config.Height > 768 {
						t.Fatal("invalid native image dimensions")
					}
					if _, err := png.Decode(bytes.NewReader(current.pixels)); err != nil {
						t.Fatal("native image payload did not decode")
					}
					if len(decodedLayers) >= 32 {
						t.Fatal("excessive fixture image layers")
					}
					decodedLayers[current.layer] = true
					image = current.layer == "0"
					imageBytes -= len(current.pixels)
					delete(images, in[1])
				}
				if (in[0] == "copy" || in[0] == "transfer") && len(in) == 10 && in[7] == "0" && decodedLayers[in[1]] {
					image = true
				}
				if in[0] == "dispose" && len(in) == 2 {
					delete(decodedLayers, in[1])
				}
				if image {
					break
				}
			}
			if valid {
				select {
				case <-authenticated:
				case <-ctx.Done():
					t.Fatal("render without verified NLA authentication")
				}
				if !image {
					t.Fatal("no native image")
				}
			} else {
				select {
				case <-authenticated:
					t.Fatal("wrong password authenticated")
				default:
				}
				if image {
					t.Fatal("wrong password rendered")
				}
			}
			cancel()
			stream.close()
			select {
			case <-brokerDone:
			case <-time.After(time.Second):
				t.Fatal("revoked target broker stayed open")
			}
			// Context revocation must stop the sandbox without a manual kill.
			select {
			case <-process.done:
			case <-time.After(time.Second):
				t.Fatal("revoked worker stayed alive")
			}
		})
	}
}

// Actual native TLS cert refusals are observed by a synthetic Go TLS peer:
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
				done <- errors.New("native TLS refusal timed out without evidence")
				return
			}
			done <- nil
			return
		}
		var b [1]byte
		n, err := server.Read(b[:])
		if n != 0 {
			done <- errors.New("native worker sent CredSSP before certificate refusal")
			return
		}
		var timeout net.Error
		if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
			done <- errors.New("native credential refusal lacked connection closure")
			return
		}
		done <- nil
	}()
	return l.Addr().String(), done
}

func TestNativeRDPCertificateRefusalBeforeCredentials(t *testing.T) {
	prefix := nativePrefix(t)
	for _, reason := range []string{"changed", "expired", "name", "purpose", "critical", "TLS11", "TLS-only", "plain-RDP"} {
		t.Run(reason, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			cert, _ := labCertificate(t, nil, key)
			identity, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			serverCert := cert
			version := uint16(tls.VersionTLS12)
			selected := byte(2)
			switch reason {
			case "changed":
				serverCert, _ = labCertificate(t, func(c *x509.Certificate) { c.SerialNumber = big.NewInt(2) }, key)
			case "expired":
				serverCert, _ = labCertificate(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, key)
				identity.der = bytes.Clone(serverCert.Certificate[0])
			case "name":
				identity.name = "different.invalid"
			case "purpose":
				serverCert, _ = labCertificate(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, key)
				identity.der = bytes.Clone(serverCert.Certificate[0])
			case "critical":
				serverCert, _ = labCertificate(t, func(c *x509.Certificate) {
					c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
				}, key)
				identity.der = bytes.Clone(serverCert.Certificate[0])
			case "TLS11":
				version = tls.VersionTLS11
			case "TLS-only":
				selected = 1
			case "plain-RDP":
				selected = 0
			}
			address, noCredentials := nativeTLSRefusalPeer(t, serverCert, version, selected)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			control, _, _ := launchNativeWorker(t, ctx, prefix, identity, func(c context.Context) (net.Conn, error) {
				fmt.Fprintln(os.Stdout, "KB_BROKER_DIAL")
				return (&net.Dialer{}).DialContext(c, "tcp", address)
			})
			plan, err := newNativePlan(identity, "synthetic-user", "must-not-be-sent")
			if err != nil {
				t.Fatal(err)
			}
			stream, err := nativeConnect(ctx, control, plan)
			if err != nil {
				t.Fatal("private native handshake failed")
			}
			defer stream.close()
			for {
				in, err := stream.next()
				if err != nil {
					if ctx.Err() != nil {
						t.Fatal("native certificate refusal timed out without evidence")
					}
					break
				}
				if in[0] == "img" && len(in) == 7 && in[3] == "0" {
					t.Fatal("invalid certificate rendered")
				}
			}
			select {
			case err := <-noCredentials:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("native certificate refusal evidence missing")
			}
		})
	}
}
