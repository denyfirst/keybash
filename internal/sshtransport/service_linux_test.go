//go:build linux && amd64 && sshprocesslab && servicelab

package sshtransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/servicepolicy"
	"golang.org/x/crypto/ssh"
)

// This gate installs only synthetic source-built fixtures on a disposable CI
// runner. It refuses any existing Keybash paths, units or account names.
func TestKeybashSystemdServiceBoundary(t *testing.T) {
	build := os.Getenv("KEYBASH_SERVICE_BUILD")
	if os.Geteuid() != 0 || !strings.HasPrefix(build, "/tmp/keybash-service-build.") {
		t.Fatal("requires disposable service runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := func(name string, args ...string) ([]byte, error) {
		call, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		c := exec.CommandContext(call, name, args...) // #nosec G204 -- fixed test tools and synthetic paths, never runtime/browser input.
		c.Env = []string{"PATH=/usr/bin:/bin"}
		return c.CombinedOutput()
	}
	run := func(name string, args ...string) []byte {
		t.Helper()
		raw, err := command(name, args...)
		if err != nil {
			t.Fatalf("service fixture command failed: %s %v: %s", name, args, raw)
		}
		return raw
	}
	units := []string{"keybash-gateway.service", "keybash-ssh-manager.service", "keybash.slice"}
	dirs := []string{"/usr/local/libexec/keybash", "/etc/keybash", "/var/lib/keybash"}
	for _, dir := range dirs {
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatal("refuse existing service fixture path")
		}
	}
	if _, err := os.Lstat("/run/keybash-manager"); !os.IsNotExist(err) {
		t.Fatal("refuse existing manager runtime directory")
	}
	for _, unit := range units {
		if _, err := os.Lstat("/etc/systemd/system/" + unit); !os.IsNotExist(err) {
			t.Fatal("refuse existing unit")
		}
		for _, inventory := range []string{"list-unit-files", "list-units"} {
			// Query the whole inventory: systemctl versions differ on the exit
			// status of an empty name-filtered result. A failed full query refuses.
			raw, err := command("/usr/bin/systemctl", inventory, "--all", "--no-legend", "--no-pager")
			if err != nil {
				t.Fatalf("refuse existing service unit inventory: %s: %s", inventory, raw)
			}
			for _, field := range strings.Fields(string(raw)) {
				if field == unit {
					t.Fatal("refuse existing loaded or installed unit")
				}
			}
		}
	}
	if _, err := os.Lstat("/run/systemd/system.control/keybash.slice.d"); !os.IsNotExist(err) {
		t.Fatal("refuse existing runtime slice overrides")
	}
	for _, account := range []string{"keybash-gateway", "keybash-worker"} {
		if _, err := command("/usr/bin/getent", "passwd", account); err == nil {
			t.Fatal("refuse existing service account")
		}
		if _, err := command("/usr/bin/getent", "group", account); err == nil {
			t.Fatal("refuse existing service group")
		}
	}
	for _, number := range []string{"65533", "65531"} {
		if _, err := command("/usr/bin/getent", "passwd", number); err == nil {
			t.Fatal("refuse occupied fixture UID")
		}
		if _, err := command("/usr/bin/getent", "group", number); err == nil {
			t.Fatal("refuse occupied fixture GID")
		}
	}
	if err := os.MkdirAll("/usr/local/libexec", 0755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range dirs {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		path := dir
		t.Cleanup(func() { _ = os.RemoveAll(path) })
	}
	t.Cleanup(func() {
		_, _ = command("/usr/bin/systemctl", "stop", "keybash-gateway.service", "keybash-ssh-manager.service", "keybash.slice")
		_, _ = command("/usr/bin/systemctl", "reset-failed", "keybash-gateway.service", "keybash-ssh-manager.service")
		for _, unit := range units {
			_ = os.Remove("/etc/systemd/system/" + unit)
		}
		_ = os.RemoveAll("/run/systemd/system.control/keybash.slice.d")
		_, _ = command("/usr/bin/systemctl", "daemon-reload")
		for _, account := range []string{"keybash-gateway", "keybash-worker"} {
			_, _ = command("/usr/sbin/userdel", account)
			_, _ = command("/usr/sbin/groupdel", account)
		}
	})
	for _, bin := range []string{"keybash", "keybash-ssh-manager", "keybash-ssh-worker", "keybash-service-check"} {
		raw, err := os.ReadFile(filepath.Join(build, bin))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("/usr/local/libexec/keybash/"+bin, raw, 0555); err != nil {
			t.Fatal(err)
		}
	}
	worker, _ := os.ReadFile("/usr/local/libexec/keybash/keybash-ssh-worker")
	digest := sha256.Sum256(worker)
	cfg := servicepolicy.Default()
	cfg.GatewayUID, cfg.GatewayGID, cfg.WorkerUID, cfg.WorkerGID = gatewayFixtureUID, gatewayFixtureUID, 65531, 65531
	cfg.WorkerDigest = hex.EncodeToString(digest[:])
	files, err := servicepolicy.Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(build, "plan")
	// Exercise the actual offline plan CLI, including refusal to overwrite.
	run(filepath.Join(build, "keybash-service-plan"), "--gateway-uid=65533", "--gateway-gid=65533", "--worker-uid=65531", "--worker-gid=65531", "--worker-digest="+cfg.WorkerDigest, "--output="+plan)
	t.Cleanup(func() { _ = os.RemoveAll(plan) })
	if _, err := command(filepath.Join(build, "keybash-service-plan"), "--gateway-uid=65533", "--gateway-gid=65533", "--worker-uid=65531", "--worker-gid=65531", "--worker-digest="+cfg.WorkerDigest, "--output="+plan); err == nil {
		t.Fatal("plan overwrote existing output")
	}
	for name, expected := range files {
		raw, e := os.ReadFile(filepath.Join(plan, name))
		if e != nil || string(raw) != expected {
			t.Fatal("service CLI plan mismatch")
		}
		if name != "keybash.conf" {
			if os.WriteFile("/etc/systemd/system/"+name, raw, 0644) != nil {
				t.Fatal("unit write failed")
			}
		}
	} // #nosec G306 -- public fixed synthetic unit files.
	run("/usr/bin/systemd-sysusers", filepath.Join(plan, "keybash.conf"))
	run("/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/keybash-gateway.service", "/etc/systemd/system/keybash-ssh-manager.service", "/etc/systemd/system/keybash.slice")
	for _, dir := range []string{"/etc/keybash/keys", "/etc/keybash/tls", "/var/lib/keybash"} {
		if dir != "/var/lib/keybash" {
			if os.Mkdir(dir, 0700) != nil {
				t.Fatal("private fixture directory failed")
			}
		}
		if os.Chmod(dir, 0700) != nil || os.Chown(dir, gatewayFixtureUID, gatewayFixtureUID) != nil {
			t.Fatal("fixture directory identity failed")
		}
	}
	init := exec.CommandContext(ctx, "/usr/local/libexec/keybash/keybash", "init", "--data=/var/lib/keybash", "--key-file=/etc/keybash/keys/instance.key")
	init.Env = []string{}
	init.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: gatewayFixtureUID, Gid: gatewayFixtureUID}}
	if raw, e := init.Output(); e != nil || len(strings.TrimSpace(string(raw))) != 43 {
		t.Fatal("service private initialization failed")
	} // Never print the bootstrap fixture code.
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(80), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, private)
	if e != nil {
		t.Fatal(e)
	}
	pkcs8, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	for name, raw := range map[string][]byte{"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})} {
		path := "/etc/keybash/tls/" + name
		if os.WriteFile(path, raw, 0600) != nil || os.Chown(path, gatewayFixtureUID, gatewayFixtureUID) != nil {
			t.Fatal("TLS fixture failed")
		}
	}
	catalog, _ := json.Marshal(map[string]any{"version": 1, "protected_networks": []string{"10.99.0.0/16"}, "targets": []any{map[string]any{"id": strings.Repeat("a", 32), "name": "Synthetic service SSH", "protocol": "ssh", "hostname": "ssh.invalid", "port": 22, "addresses": []string{"10.44.0.8"}, "ssh_host_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(syntheticSigner(t).PublicKey())))}}})
	if os.WriteFile("/etc/keybash/targets.json", catalog, 0644) != nil {
		t.Fatal("public fixture catalog failed")
	} // #nosec G306 -- public root-owned synthetic metadata.
	run("/usr/bin/systemctl", "daemon-reload")
	run("/usr/bin/systemctl", "start", "keybash-gateway.service")
	t.Cleanup(func() {
		if t.Failed() {
			raw, _ := command("/usr/bin/journalctl", "--no-pager", "-n", "50", "-u", "keybash-gateway.service", "-u", "keybash-ssh-manager.service")
			t.Logf("fixed service diagnostics: %s", raw)
		}
	})
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	ready := false
	for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
		resp, e := client.Get("https://127.0.0.1:8443/api/setup")
		if e == nil {
			_ = resp.Body.Close()
			ready = resp.StatusCode == 200
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("systemd gateway TLS readiness refused")
	}
	for _, unit := range units[:2] {
		run("/usr/bin/systemctl", "is-active", "--quiet", unit)
	}
	serviceSSH := func() {
		t.Helper()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKeybashServiceSSHChild$", "-test.timeout=15s") // #nosec G204 -- fixed synthetic test executable.
		child.Env = []string{"PATH=/usr/bin:/bin", "KEYBASH_SERVICE_SSH=1"}
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: gatewayFixtureUID, Gid: gatewayFixtureUID}}
		out, e := child.StdoutPipe()
		if e != nil || child.Start() != nil {
			t.Fatal("service SSH gateway failed to start")
		}
		defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
		marker := make([]byte, len("gateway-ready\n"))
		if _, e := io.ReadFull(out, marker); e != nil || string(marker) != "gateway-ready\n" {
			rest, _ := io.ReadAll(io.LimitReader(out, 4096))
			t.Fatalf("service SSH worker refused: %s%s", marker, rest)
		}
		procs, e := os.ReadFile("/sys/fs/cgroup/keybash.slice/keybash-ssh-manager.service/cgroup.procs")
		if e != nil {
			t.Fatal("manager cgroup missing")
		}
		found := false
		for _, pid := range strings.Fields(string(procs)) {
			status, _ := os.ReadFile("/proc/" + pid + "/status")
			if bytes.Contains(status, []byte("Uid:\t65531\t65531\t65531\t65531")) {
				membership, _ := os.ReadFile("/proc/" + pid + "/cgroup")
				if string(membership) != "0::/keybash.slice/keybash-ssh-manager.service\n" {
					t.Fatal("worker escaped aggregate cgroup")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("dedicated worker identity lost")
		}
		pid := strings.TrimSpace(string(run("/usr/bin/systemctl", "show", "-p", "MainPID", "--value", "keybash-ssh-manager.service")))
		if _, e := os.Stat("/proc/" + pid + "/root/etc/keybash/keys/instance.key"); e == nil {
			t.Fatal("manager service can see custody key")
		}
		run("/usr/bin/systemctl", "stop", "keybash-ssh-manager.service")
		data, e := io.ReadAll(out)
		if e != nil || child.Wait() != nil {
			t.Fatalf("service stop did not revoke worker: %s", data)
		}
		procs, e = os.ReadFile("/sys/fs/cgroup/keybash.slice/keybash-ssh-manager.service/cgroup.procs")
		if e == nil && len(bytes.TrimSpace(procs)) != 0 {
			t.Fatal("service stop retained descendants")
		}
		if _, e = command("/usr/bin/systemctl", "is-active", "--quiet", "keybash-gateway.service"); e == nil {
			t.Fatal("manager loss retained gateway service")
		}
	}
	serviceSSH()
	// Each changed kernel limit must prevent startup BEFORE a socket/listener.
	for _, setting := range []string{"TasksMax=infinity", "MemoryMax=infinity", "CPUQuota=100%", "MemorySwapMax=1M"} {
		run("/usr/bin/systemctl", "set-property", "--runtime", "keybash.slice", setting)
		if _, e := command("/usr/bin/systemctl", "start", "keybash-ssh-manager.service"); e == nil {
			t.Fatal("unenforced service startup accepted")
		}
		if _, e := os.Stat("/run/keybash-manager/control.sock"); e == nil {
			t.Fatal("refused service exposed manager socket")
		}
		run("/usr/bin/systemctl", "set-property", "--runtime", "keybash.slice", "TasksMax=512", "MemoryMax=1024M", "CPUQuota=200%", "MemorySwapMax=0")
		run("/usr/bin/systemctl", "reset-failed", "keybash-ssh-manager.service", "keybash-gateway.service")
	}
	run("/usr/bin/systemctl", "start", "keybash-gateway.service")
	serviceSSH() // Restored policy actually admits SSH and clean restart again.
	// Kernel probes inherit the SAME parent slice. No individual child limits.
	readCounter := func(file, key string) uint64 {
		raw, e := os.ReadFile("/sys/fs/cgroup/keybash.slice/" + file)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == key {
				n, _ := strconv.ParseUint(f[1], 10, 64)
				return n
			}
		}
		t.Fatal("kernel event counter missing")
		return 0
	}
	probe := func(mode string) ([]byte, error) {
		return command("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=keybash-resource-probe", "--slice=keybash.slice", "--property=User=65533", "--property=Group=65533", "--setenv=KEYBASH_SERVICE_PROBE="+mode, os.Args[0], "-test.run=^TestKeybashServiceResourceProbeChild$", "-test.timeout=12s")
	}
	run("/usr/bin/systemctl", "set-property", "--runtime", "keybash.slice", "CPUQuota=20%", "TasksMax=128")
	before := readCounter("cpu.stat", "nr_throttled")
	if raw, e := probe("cpu"); e != nil || !bytes.Contains(raw, []byte("cpu-throttled")) || readCounter("cpu.stat", "nr_throttled") <= before {
		t.Fatalf("aggregate CPU enforcement missing: %s", raw)
	}
	before = readCounter("pids.events", "max")
	if raw, e := probe("pids"); e != nil || !bytes.Contains(raw, []byte("pids-refused")) || readCounter("pids.events", "max") <= before {
		t.Fatalf("aggregate pids enforcement missing: %s", raw)
	}
	run("/usr/bin/systemctl", "set-property", "--runtime", "keybash.slice", "CPUQuota=200%", "MemoryMax=64M")
	before = readCounter("memory.events", "oom_kill")
	if raw, e := probe("memory"); e == nil || readCounter("memory.events", "oom_kill") <= before {
		t.Fatalf("aggregate memory OOM enforcement missing: %s", raw)
	}
	t.Log("Actual systemd identity/TLS/SSH/cgroup membership, startup refusal, restart/revocation and kernel CPU/pids/OOM gates passed")
}

var serviceProbeMemory [][]byte

// A separate service-only fixture keeps the older /tmp-only laboratory guard
// intact. The installed socket path and synthetic dial exist in this test only.
func TestKeybashServiceSSHChild(t *testing.T) {
	if os.Getenv("KEYBASH_SERVICE_SSH") != "1" {
		t.Skip("dedicated service SSH fixture")
	}
	if os.Geteuid() != gatewayFixtureUID || os.Getegid() != gatewayFixtureUID {
		t.Fatal("service fixture identity wrong")
	}
	user, _ := processFixtureKey(t)
	host := syntheticSigner(t)
	closed := make(chan struct{})
	f := newFixture(t, fixtureOptions{host: host, user: user, shellFixture: func(c ssh.Channel) { defer close(closed); _, _ = io.Copy(c, c) }})
	// Temporary synthetic pre-drop inspection. No worker hello, SSH startup,
	// private seed or terminal data is sent through these pipes.
	diagnostic := dialManagerFixture(t, "/run/keybash-manager/control.sock")
	if expectManagerPacket(diagnostic, managerHello) != nil {
		t.Fatal("diagnostic admission refused")
	}
	tcp := f.client.(*net.TCPConn)
	transport, e := tcp.File()
	if e != nil {
		t.Fatal(e)
	}
	defer transport.Close()
	in, inWriter, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	defer inWriter.Close()
	outReader, out, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer outReader.Close()
	defer out.Close()
	if writeManagerPacket(diagnostic, managerStart, transport, in, out) != nil || expectManagerPacket(diagnostic, managerActive) != nil {
		t.Fatal("diagnostic start refused")
	}
	_ = in.Close()
	_ = out.Close()
	raw, e := io.ReadAll(io.LimitReader(outReader, 4096))
	if e != nil {
		t.Fatal(e)
	}
	t.Fatalf("synthetic pre-drop capabilities: %s", raw)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w := ManagerWorker{SocketPath: "/run/keybash-manager/control.sock"}
	dialed := false
	s, err := w.open(ctx, "ssh.invalid", func(context.Context) (net.Conn, error) { dialed = true; return f.client, nil }, host.PublicKey().Marshal(), "lab-user", user)
	if err != nil {
		t.Fatalf("service synthetic SSH refused (admitted dial=%t)", dialed)
	}
	defer s.Close()
	text := []byte("service SSH: əöğ\r\n")
	got := make([]byte, len(text))
	if _, err := s.Write(text); err != nil {
		t.Fatal("service SSH input refused")
	}
	if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, text) || s.Resize(150, 45) != nil || s.Resize(501, 45) == nil {
		t.Fatal("service SSH bytes/resize changed")
	}
	_, _ = os.Stdout.WriteString("gateway-ready\n")
	select {
	case <-closed:
	case <-time.After(4 * time.Second):
		t.Fatal("service stop retained SSH")
	}
	if n, err := s.Read(got); n != 0 || err == nil {
		t.Fatal("service stop retained output")
	}
}

func TestKeybashServiceResourceProbeChild(t *testing.T) {
	mode := os.Getenv("KEYBASH_SERVICE_PROBE")
	if mode == "" {
		t.Skip("fixed disposable kernel probe")
	}
	if os.Geteuid() != gatewayFixtureUID {
		t.Fatal("probe must be unprivileged")
	}
	switch mode {
	case "cpu":
		start := time.Now()
		var count uint64
		for time.Since(start) < 1500*time.Millisecond {
			count++
		}
		var usage syscall.Rusage
		if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil || count == 0 {
			t.Fatal("CPU probe failed")
		}
		used := time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second + time.Duration(usage.Utime.Usec+usage.Stime.Usec)*time.Microsecond
		if used >= time.Since(start)*65/100 {
			t.Fatal("CPU quota did not throttle")
		}
		fmt.Println("cpu-throttled")
	case "pids":
		var children []*exec.Cmd
		defer func() {
			for _, c := range children {
				_ = c.Process.Kill()
				_ = c.Wait()
			}
		}()
		for i := 0; i < 160; i++ {
			c := exec.Command("/usr/bin/sleep", "20")
			if c.Start() != nil {
				if len(children) < 20 {
					t.Fatal("pids probe failed too early")
				}
				fmt.Println("pids-refused")
				return
			}
			children = append(children, c)
		}
		t.Fatal("pids quota did not refuse")
	case "memory":
		for i := 0; i < 256; i++ {
			b := make([]byte, 1024*1024)
			for j := 0; j < len(b); j += 4096 {
				b[j] = byte(i)
			}
			serviceProbeMemory = append(serviceProbeMemory, b)
		}
		t.Fatal("memory quota did not kill")
	default:
		t.Fatal("unknown kernel probe")
	}
}
