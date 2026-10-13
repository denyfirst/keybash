//go:build linux && workerlab

package rdplab

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This is a test-only network namespace experiment, not a worker launcher.
// CI's root helper creates an empty namespace, then drops UID/GID/capabilities
// before running the fixed test child. No host network settings are changed.
func TestRDPEmptyWorkerNamespaceDeniesEgress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	parentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// All arguments are fixed or locally generated test metadata. No shell,
	// credential, persistent listener, namespace name, or host mount is involved.
	childArgs := []string{"--reuid=65534", "--regid=65534", "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
		"/usr/bin/env", "-i", "KEYBASH_WORKER_CHILD=1", "KEYBASH_WORKER_ENDPOINT=" + listener.Addr().String(),
		"KEYBASH_PARENT_NETNS=" + parentNS, executable, "-test.run=^TestRDPWorkerNamespaceChild$", "-test.timeout=5s", "-test.v"}
	runChild := func(isolated bool) ([]byte, error) {
		args := []string{"-n"}
		if isolated {
			args = append(args, "unshare", "--net")
		}
		args = append(args, "/usr/bin/setpriv")
		args = append(args, childArgs...)
		cmd := exec.CommandContext(ctx, "sudo", args...) // #nosec G204 -- fixed test binary and synthetic endpoint; no caller-controlled commands.
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		return cmd.CombinedOutput()
	}
	output, err := runChild(true)
	if err != nil {
		t.Fatalf("network namespace evidence failed (never skipped): %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "--- PASS: TestRDPWorkerNamespaceChild") {
		t.Fatal("child evidence missing")
	}
	// Sabotage isolation without changing the child's assertions: the same
	// unprivileged child on the host namespace must fail at the namespace check.
	output, err = runChild(false)
	if err == nil || !strings.Contains(string(output), "worker shares host network namespace") {
		t.Fatalf("missing namespace was not detected: %v\n%s", err, output)
	}
	// A connect attempt must not reach even the host's loopback sentinel.
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if conn != nil {
		_ = conn.Close()
		t.Fatal("worker reached host sentinel")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("sentinel observation failed: %v", err)
	}
}

func TestRDPWorkerNamespaceChild(t *testing.T) {
	if os.Getenv("KEYBASH_WORKER_CHILD") != "1" {
		t.Skip("fixed child invoked by namespace orchestrator")
	}
	if os.Geteuid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("worker retained setup identity")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatal("worker retained supplementary groups")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapAmb"} {
		if !strings.Contains(string(status), field+":\t0000000000000000") {
			t.Fatal("worker retained capabilities")
		}
	}
	if !strings.Contains(string(status), "NoNewPrivs:\t1") {
		t.Fatal("worker can acquire new privileges")
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns == os.Getenv("KEYBASH_PARENT_NETNS") {
		t.Fatal("worker shares host network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp != 0 {
		t.Fatal("unexpected network interface or usable loopback")
	}
	for _, attempt := range []struct{ network, address string }{
		{"tcp", os.Getenv("KEYBASH_WORKER_ENDPOINT")},
		{"tcp", "192.0.2.1:3389"}, {"tcp", "[2001:db8::1]:3389"},
		{"udp", "192.0.2.53:53"}, {"udp", "[2001:db8::53]:53"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(ctx, attempt.network, attempt.address)
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatalf("unapproved %s egress succeeded", attempt.network)
		}
	}
	// This denies all egress. An approved-only broker path is a later test gate;
	// it is not implied by an empty namespace or this test's synthetic probes.
}
