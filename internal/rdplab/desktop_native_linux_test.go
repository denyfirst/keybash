//go:build linux && amd64 && nativelab && browserlab

package rdplab

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// The account and the server the desktop test uses; both are synthetic.
const (
	desktopAccountPassword = "Synthetic owned account password 73!"
	desktopNLAPassword     = "Synthetic-desktop-NLA-password"
)

// peerWorker is the gateway's RDP worker in the desktop test: the manager and
// its sandboxed proxy, exactly as the service runs them, with the guarded dial
// to the server replaced by a dial to the test peer. The gateway says when a
// desktop's lease ends.
type peerWorker struct{ socket, peer string }

func (w peerWorker) OpenBrowserRDP(ctx context.Context, request identity.RDPRequest) (terminalweb.MessageStream, error) {
	if request.Target == nil {
		return nil, errNative
	}
	pin, err := identityFor(request.Target, request.Certificate)
	if err != nil || !pin.boundTo(request.Target) {
		return nil, errNative
	}
	dial := func(c context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(c, "tcp", w.peer) }
	stream, err := ManagerWorker{SocketPath: w.socket}.openBrowserDial(ctx, dial, pin, request.Username, request.Password)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { fmt.Fprintln(os.Stdout, "KB_DESKTOP_ENDED") })
	return stream, nil
}

// TestNativeRDPDesktopGatewayChild is the desktop test's gateway: a fresh
// installation's lab as the gateway's own UID, with one RDP server whose
// certificate is the peer's. It prints where it listens and the setup code,
// then serves until its parent closes its input.
func TestNativeRDPDesktopGatewayChild(t *testing.T) {
	socket := os.Getenv("KEYBASH_DESKTOP_SOCKET")
	if socket == "" {
		t.Skip("fixed unprivileged gateway child")
	}
	der, err := base64.StdEncoding.DecodeString(os.Getenv("KEYBASH_DESKTOP_CERTIFICATE"))
	if err != nil {
		t.Fatal("fixture certificate failed")
	}
	base := t.TempDir()
	data, keys := filepath.Join(base, "data"), filepath.Join(base, "keys")
	for _, dir := range []string{data, keys} {
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("private desktop fixture mkdir failed")
		}
	}
	store, code, err := identity.InitializeFiles(data, filepath.Join(keys, "instance.key"))
	if err != nil {
		t.Fatal("desktop fixture store failed")
	}
	defer store.Close()
	// The gateway's target is never dialled: peerWorker reaches the peer.
	ip := netip.MustParseAddr("10.44.0.3")
	policy, err := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 3389)}, nil)
	if err != nil {
		t.Fatal("fixture policy failed")
	}
	named, err := targetguard.NewNamedTarget(policy, "synthetic-rdp.invalid", 3389, []netip.Addr{ip})
	if err != nil {
		t.Fatal("fixture target failed")
	}
	target := identity.RemoteTarget{ID: strings.Repeat("a", 32), Name: "Synthetic desktop", Protocol: "rdp", Target: named, Identity: der}
	server := httptest.NewUnstartedServer(nil)
	lab, err := identity.NewRemoteLab("https://"+server.Listener.Addr().String(), store, []identity.RemoteTarget{target}, nil, peerWorker{socket: socket, peer: os.Getenv("KEYBASH_DESKTOP_PEER")})
	if err != nil {
		t.Fatal("desktop fixture lab failed")
	}
	defer lab.Close()
	server.Config.Handler = lab
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.IdleTimeout = 10 * time.Second
	server.Config.MaxHeaderBytes = 8192
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, _ := json.Marshal(struct{ Origin, Code, Target string }{server.URL, code, target.ID})
	fmt.Fprintf(os.Stdout, "KB_DESKTOP_CONFIG %s\n", config)
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// gatewayOutput reads the gateway child's fixed lines: its configuration, and
// each desktop lease that ended.
type gatewayOutput struct {
	mu      sync.Mutex
	pending string
	config  chan string
	ended   chan struct{}
	once    sync.Once
}

func (g *gatewayOutput) Write(b []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range b {
		if c != '\n' {
			if len(g.pending) < 4096 {
				g.pending += string(c)
			}
			continue
		}
		if config, ok := strings.CutPrefix(g.pending, "KB_DESKTOP_CONFIG "); ok {
			select {
			case g.config <- config:
			default:
			}
		}
		if g.pending == "KB_DESKTOP_ENDED" {
			g.once.Do(func() { close(g.ended) })
		}
		g.pending = ""
	}
	return len(b), nil
}

// driverOutput passes the browser driver's fixed lines on, and says when the
// driver has sent the person's input to the desktop.
type driverOutput struct {
	mu      sync.Mutex
	pending string
	sent    chan struct{}
	once    sync.Once
}

func (d *driverOutput) Write(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range b {
		if c != '\n' {
			if len(d.pending) < 512 {
				d.pending += string(c)
			}
			continue
		}
		if d.pending == "KB_INPUT_SENT" {
			d.once.Do(func() { close(d.sent) })
		} else {
			fmt.Fprintln(os.Stdout, d.pending)
		}
		d.pending = ""
	}
	return len(b), nil
}

// The whole desktop path on Linux: a fresh installation's pages in a real
// browser, the gateway as its own UID, the RDP manager, the proxy in the
// worker's sandbox, and the test peer, IronRDP's own server, at the end.
//   - The person signs up, enrols a second factor, saves the server's password
//     and opens the desktop; the page draws the peer's grey desktop.
//   - A click and a key on the page reach the peer.
//   - Signing out ends the desktop: the page says so and keeps no picture, and
//     the gateway's lease for it ends.
func TestNativeRDPDesktopFromThePageToThePeer(t *testing.T) {
	prefix := nativePrefix(t)
	c := nativeManagerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	serveNativeManager(t, ctx, c)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := labCertificate(t, nil, key)
	address, peer := testPeerSaying(t, ctx, prefix, cert, desktopNLAPassword)

	gateway := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeRDPDesktopGatewayChild$", "-test.v", "-test.timeout=170s") // #nosec G204 -- this exact compiled fixture and fixed selector.
	gateway.Dir = "/tmp"
	gateway.Env = []string{"PATH=/usr/bin:/bin", "KEYBASH_DESKTOP_SOCKET=" + c.SocketPath, "KEYBASH_DESKTOP_PEER=" + address,
		"KEYBASH_DESKTOP_CERTIFICATE=" + base64.StdEncoding.EncodeToString(cert.Certificate[0])}
	gateway.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.GatewayUID, Gid: c.GatewayGID, Groups: []uint32{c.GatewayGID}}}
	said := &gatewayOutput{config: make(chan string, 1), ended: make(chan struct{})}
	gateway.Stdout, gateway.Stderr = said, said
	gatewayIn, err := gateway.StdinPipe()
	if err != nil || gateway.Start() != nil {
		t.Fatal("gateway child start failed")
	}
	// Closed when the child is reaped; a wait never takes its result.
	gatewayDone := make(chan struct{})
	go func() { _ = gateway.Wait(); close(gatewayDone) }()
	defer func() {
		_ = gatewayIn.Close()
		select {
		case <-gatewayDone:
		case <-time.After(5 * time.Second):
			_ = gateway.Process.Kill()
			<-gatewayDone
		}
	}()
	var config struct{ Origin, Code, Target string }
	select {
	case line := <-said.config:
		if json.Unmarshal([]byte(line), &config) != nil {
			t.Fatal("gateway configuration unreadable")
		}
	case <-gatewayDone:
		t.Fatal("gateway child ended before serving")
	case <-ctx.Done():
		t.Fatal("gateway child never served")
	}

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture source path unavailable")
	}
	script := filepath.Join(filepath.Dir(source), "..", "..", "web", "desktop-native-browser-test.mjs")
	driver := exec.CommandContext(ctx, prefix+"/bin/node", script) // #nosec G204 -- test-only fixed source-relative script; synthetic secrets via stdin.
	driver.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "PLAYWRIGHT_BROWSERS_PATH=" + os.Getenv("KEYBASH_NATIVE_BROWSER_CACHE")}
	driver.Stderr = io.Discard
	input := &driverOutput{sent: make(chan struct{})}
	driver.Stdout = input
	driverIn, err := driver.StdinPipe()
	if err != nil || driver.Start() != nil {
		t.Fatal("browser driver start failed")
	}
	var driverErr error
	driverDone := make(chan struct{})
	go func() { driverErr = driver.Wait(); close(driverDone) }()
	defer func() { _ = driver.Process.Kill(); <-driverDone }()
	line, _ := json.Marshal(struct{ Origin, Code, Target, Password, Secret string }{config.Origin, config.Code, config.Target, desktopAccountPassword, desktopNLAPassword})
	if _, err := driverIn.Write(append(line, '\n')); err != nil {
		t.Fatal("browser driver configuration failed")
	}
	select {
	case <-input.sent:
	case <-driverDone:
		t.Fatalf("browser driver ended before its input: %v", driverErr)
	case <-ctx.Done():
		t.Fatal("browser driver never sent its input")
	}
	// The peer, not the page, says what arrived: a desktop opened, the pointer
	// moved, a click and the A key (scan code 0x1e).
	for deadline := time.Now().Add(15 * time.Second); !peer.said("desktop", "pointer", "click ", "key 0x1e"); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the page's input did not reach the peer")
		}
	}
	if _, err := driverIn.Write([]byte("peer-saw-input\n")); err != nil {
		t.Fatal("browser driver acknowledgement failed")
	}
	select {
	case <-driverDone:
		if driverErr != nil {
			t.Fatalf("browser driver failed: %v", driverErr)
		}
	case <-ctx.Done():
		t.Fatal("browser driver stalled")
	}
	select {
	case <-said.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("signing out did not end the desktop's lease")
	}
}
