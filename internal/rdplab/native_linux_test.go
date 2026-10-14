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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
		"--uid", "65534", "--gid", "65534", "--cap-drop", "ALL", "--clearenv",
		"--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
		"--ro-bind", prefix, prefix, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/run",
		"--setenv", "LD_LIBRARY_PATH", prefix + "/lib", "--setenv", "HOME", "/tmp", "--setenv", "LANG", "C",
		"--setenv", "WLOG_LEVEL", "ERROR", "--setenv", "KEYBASH_NATIVE_PREFIX", prefix}
}

func runSandbox(t *testing.T, ctx context.Context, args []string, stdout io.Writer) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", args...) // #nosec G204 -- fixed sandbox/test binaries, only generated local paths; no browser input.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatal("native sandbox start failed")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

type nativeMarker struct {
	mu    sync.Mutex
	tail  string
	ready chan struct{}
	once  sync.Once
}

func (m *nativeMarker) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tail += string(p)
	if strings.Contains(m.tail, "KB_AUTHENTICATED") {
		m.once.Do(func() { close(m.ready) })
	}
	if len(m.tail) > 256 {
		m.tail = m.tail[len(m.tail)-256:]
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
		"--ro-bind", prefix+"/share/lab/test_icon.bmp", "/tmp/test_icon.bmp", "--chdir", "/tmp",
		prefix+"/bin/sfreerdp", fmt.Sprintf("--port=%d", port), "--cert=/run/fixture/cert.pem", "--key=/run/fixture/key.pem")
	marker := &nativeMarker{ready: make(chan struct{})}
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
	return address, marker.ready
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

func launchNativeWorker(t *testing.T, ctx context.Context, prefix string, identity *Identity, dial func(context.Context) (net.Conn, error)) (net.Conn, *exec.Cmd, <-chan error) {
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
		"--setenv", "KEYBASH_HOST_SENTINEL", filepath.Join(dir, "host-sentinel"), prefix+"/bin/lab.test", "-test.run=^TestNativeRDPChild$", "-test.timeout=35s")
	cmd := runSandbox(t, ctx, args, io.Discard)
	broker := &nativeBroker{dial: dial}
	done := make(chan error, 1)
	go func() {
		c, err := acceptNative(ctx, target)
		if err != nil {
			done <- err
			return
		}
		done <- broker.serve(ctx, c)
	}()
	c, err := acceptNative(ctx, control)
	if err != nil {
		t.Fatal("worker did not establish private control IPC")
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, cmd, done
}

func TestNativeRDPChild(t *testing.T) {
	if os.Getenv("KEYBASH_NATIVE_ROLE") != "worker" {
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
	guacd := exec.Command("/usr/bin/prlimit", "--as=2147483648", "--cpu=20", "--nofile=64", "--nproc=128", "--", prefix+"/sbin/guacd", "-f", "-b", "127.0.0.1", "-p", "4822", "-L", "error") // #nosec G204 -- verified, read-only CI prefix; never supplied by a browser.
	guacd.Stdout = io.Discard
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
			control, process, brokerDone := launchNativeWorker(t, ctx, prefix, identity, func(c context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(c, "tcp", address) })
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
			image := false
			for {
				in, err := stream.next()
				if err != nil {
					if valid {
						t.Fatal("native RDP did not render")
					}
					break
				}
				if in[0] == "sync" && len(in) == 2 {
					_ = writeInstruction(control, in)
				}
				if in[0] == "img" {
					image = true
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
			stopped := make(chan struct{})
			go func() { _ = process.Wait(); close(stopped) }()
			select {
			case <-stopped:
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
			control, _, _ := launchNativeWorker(t, ctx, prefix, identity, func(c context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(c, "tcp", address) })
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
					break
				}
				if in[0] == "img" {
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
