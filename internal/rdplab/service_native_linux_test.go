//go:build linux && amd64 && nativelab

package rdplab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/denyfirst/keybash/internal/servicepolicy"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeRDPSystemdServiceBoundary(t *testing.T) {
	prefix := nativePrefix(t)
	fixture := nativeManagerFixture(t)
	build := filepath.Join(prefix, "bin")
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
	units := []string{"keybash-gateway.service", "keybash-ssh-manager.service", "keybash-rdp-manager.service", "keybash.slice"}
	dirs := []string{"/usr/local/libexec/keybash", "/etc/keybash", "/var/lib/keybash", "/usr/local/lib/keybash"}
	for _, dir := range dirs {
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatal("refuse existing service fixture path")
		}
	}
	if _, err := os.Lstat("/run/keybash-rdp-manager"); !os.IsNotExist(err) {
		t.Fatal("refuse existing RDP runtime directory")
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
		_, _ = command("/usr/bin/systemctl", "stop", "keybash-gateway.service", "keybash-ssh-manager.service", "keybash-rdp-manager.service", "keybash.slice")
		_, _ = command("/usr/bin/systemctl", "reset-failed", "keybash-gateway.service", "keybash-ssh-manager.service", "keybash-rdp-manager.service")
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
	for _, bin := range []string{"keybash", "keybash-ssh-manager", "keybash-ssh-worker", "keybash-service-check", "keybash-rdp-worker", "keybash-rdp-manager"} {
		raw, err := os.ReadFile(filepath.Join(build, bin))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("/usr/local/libexec/keybash/"+bin, raw, 0555); err != nil {
			t.Fatal(err)
		}
	}
	if os.CopyFS("/usr/local/lib/keybash/rdp", os.DirFS(fixture.Runtime)) != nil {
		t.Fatal("service runtime staging failed")
	}
	worker, _ := os.ReadFile("/usr/local/libexec/keybash/keybash-ssh-worker")
	digest := sha256.Sum256(worker)
	cfg := servicepolicy.Default()
	cfg.GatewayUID, cfg.GatewayGID, cfg.WorkerUID, cfg.WorkerGID = 65533, 65533, 65531, 65531
	cfg.WorkerDigest = hex.EncodeToString(digest[:])
	rdpWorker, e := os.ReadFile("/usr/local/libexec/keybash/keybash-rdp-worker")
	if e != nil {
		t.Fatal(e)
	}
	rdpDigest := sha256.Sum256(rdpWorker)
	cfg.RDPWorkerDigest = hex.EncodeToString(rdpDigest[:])
	runtimeDigest, e := RuntimeInventory("/usr/local/lib/keybash/rdp")
	if e != nil {
		t.Fatal("service runtime provenance failed")
	}
	cfg.RDPRuntimeDigest = hex.EncodeToString(runtimeDigest[:])
	files, err := servicepolicy.Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(build, "plan")
	// Exercise the actual offline plan CLI, including refusal to overwrite.
	run(filepath.Join(build, "keybash-service-plan"), "--gateway-uid=65533", "--gateway-gid=65533", "--worker-uid=65531", "--worker-gid=65531", "--worker-digest="+cfg.WorkerDigest, "--rdp-worker-digest="+cfg.RDPWorkerDigest, "--rdp-runtime-digest="+cfg.RDPRuntimeDigest, "--output="+plan)
	t.Cleanup(func() { _ = os.RemoveAll(plan) })
	if _, err := command(filepath.Join(build, "keybash-service-plan"), "--gateway-uid=65533", "--gateway-gid=65533", "--worker-uid=65531", "--worker-gid=65531", "--worker-digest="+cfg.WorkerDigest, "--rdp-worker-digest="+cfg.RDPWorkerDigest, "--rdp-runtime-digest="+cfg.RDPRuntimeDigest, "--output="+plan); err == nil {
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
	run("/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/keybash-gateway.service", "/etc/systemd/system/keybash-ssh-manager.service", "/etc/systemd/system/keybash-rdp-manager.service", "/etc/systemd/system/keybash.slice")
	for _, dir := range []string{"/etc/keybash/keys", "/etc/keybash/tls", "/var/lib/keybash"} {
		if dir != "/var/lib/keybash" {
			if os.Mkdir(dir, 0700) != nil {
				t.Fatal("private fixture directory failed")
			}
		}
		if os.Chmod(dir, 0700) != nil || os.Chown(dir, 65533, 65533) != nil {
			t.Fatal("fixture directory identity failed")
		}
	}
	init := exec.CommandContext(ctx, "/usr/local/libexec/keybash/keybash", "init", "--data=/var/lib/keybash", "--key-file=/etc/keybash/keys/instance.key")
	init.Env = []string{}
	init.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
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
		if os.WriteFile(path, raw, 0600) != nil || os.Chown(path, 65533, 65533) != nil {
			t.Fatal("TLS fixture failed")
		}
	}
	rdpKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	rdpCert, _ := labCertificate(t, nil, rdpKey)
	pin, e := NewIdentity("synthetic-rdp.invalid", rdpCert.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	address, _ := nativePeerWithInput(t, ctx, prefix, rdpCert, "Synthetic-managed-NLA-password")
	catalog, _ := json.Marshal(map[string]any{"version": 1, "protected_networks": []string{"10.99.0.0/16"}, "targets": []any{map[string]any{"id": strings.Repeat("b", 32), "name": "Synthetic service RDP", "protocol": "rdp", "hostname": "synthetic-rdp.invalid", "port": 3389, "addresses": []string{"10.44.0.3"}, "rdp_certificate": base64.StdEncoding.EncodeToString(pin.der)}}})
	if os.WriteFile("/etc/keybash/targets.json", catalog, 0644) != nil {
		t.Fatal("public fixture catalog failed")
	} // #nosec G306 -- public root-owned synthetic metadata.
	run("/usr/bin/systemctl", "daemon-reload")
	managerReady := func() {
		t.Helper()
		// Type=exec confirms exec, not completion of the manager's runtime
		// inventory/bind. Await the protected IPC state, never retry credentials.
		for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
			st, e := os.Lstat("/run/keybash-rdp-manager/control.sock")
			if e == nil && st.Mode()&os.ModeSocket != 0 && st.Mode().Perm() == 0660 {
				if owner, ok := st.Sys().(*syscall.Stat_t); ok && owner.Uid == 0 && owner.Gid == 65533 {
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("installed RDP manager protected IPC never became ready")
	}
	run("/usr/bin/systemctl", "start", "keybash-gateway.service")
	managerReady()
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
	for _, unit := range units[:3] {
		run("/usr/bin/systemctl", "is-active", "--quiet", unit)
	}
	fixture.SocketPath = "/run/keybash-rdp-manager/control.sock"
	runManagedGateway(t, fixture, address, pin, "service", 65533, func() {
		procs, e := os.ReadFile("/sys/fs/cgroup/keybash.slice/keybash-rdp-manager.service/cgroup.procs")
		if e != nil {
			t.Fatal("RDP service cgroup missing")
		}
		found := false
		for _, pid := range strings.Fields(string(procs)) {
			status, e := os.ReadFile("/proc/" + pid + "/status")
			if e != nil {
				continue
			}
			if strings.Contains(string(status), "Uid:\t65531\t65531\t65531\t65531") {
				member, e := os.ReadFile("/proc/" + pid + "/cgroup")
				if e != nil || string(member) != "0::/keybash.slice/keybash-rdp-manager.service\n" {
					t.Fatal("RDP descendant escaped service cgroup")
				}
				if !strings.Contains(string(status), "CapEff:\t0000000000000000") || !strings.Contains(string(status), "NoNewPrivs:\t1") {
					t.Fatal("RDP descendant retained privileges")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("dedicated live RDP service worker identity lost")
		}
		for file, want := range map[string]string{"cpu.max": "200000 100000\n", "memory.max": "1073741824\n", "memory.swap.max": "0\n", "pids.max": "512\n"} {
			raw, e := os.ReadFile("/sys/fs/cgroup/keybash.slice/" + file)
			if e != nil || string(raw) != want {
				t.Fatal("RDP aggregate kernel bound mismatch: " + file)
			}
		}
		run("/usr/bin/systemctl", "stop", "keybash-rdp-manager.service")
		if _, e := command("/usr/bin/systemctl", "is-active", "--quiet", "keybash-gateway.service"); e == nil {
			t.Fatal("RDP manager stop did not stop gateway")
		}
		if raw, e := os.ReadFile("/sys/fs/cgroup/keybash.slice/keybash-rdp-manager.service/cgroup.procs"); e == nil && len(strings.TrimSpace(string(raw))) != 0 {
			t.Fatal("RDP service stop retained descendants")
		}
	})
	run("/usr/bin/systemctl", "set-property", "--runtime", "keybash.slice", "TasksMax=513")
	if _, e := command("/usr/bin/systemctl", "start", "keybash-rdp-manager.service"); e == nil {
		t.Fatal("RDP service accepted mismatched actual kernel limit")
	}
	if _, e := os.Lstat("/run/keybash-rdp-manager/control.sock"); !os.IsNotExist(e) {
		t.Fatal("RDP preflight refusal left launch socket")
	}
	run("/usr/bin/systemctl", "set-property", "--runtime", "keybash.slice", "TasksMax=512")
	run("/usr/bin/systemctl", "reset-failed", "keybash-rdp-manager.service")
	run("/usr/bin/systemctl", "start", "keybash-gateway.service")
	managerReady()
	runManagedGateway(t, fixture, address, pin, "positive", 65533)
	t.Log("Actual installed RDP/gateway units: NLA, worker identity/cgroup, aggregate bounds, refusal, restart and descendant revocation passed")
}
