package servicepolicy

import (
	"strings"
	"testing"
)

func fixtureConfig() Config {
	c := Default()
	c.GatewayUID, c.GatewayGID, c.WorkerUID, c.WorkerGID = 65533, 65533, 65531, 65531
	c.WorkerDigest = strings.Repeat("a", 64)
	return c
}

func TestServiceRDPPlanAndSharedKernelBoundary(t *testing.T) {
	c := fixtureConfig()
	c.RDPWorkerDigest = strings.Repeat("b", 64)
	c.RDPRuntimeDigest = strings.Repeat("c", 64)
	files, e := Render(c)
	if e != nil || len(files) != 5 {
		t.Fatal("valid RDP service plan refused")
	}
	for _, required := range []string{"Slice=keybash.slice", "PrivateNetwork=yes", "KillMode=control-group", "--role=rdp-manager", "--runtime-sha256=" + c.RDPRuntimeDigest, "--worker-sha256=" + c.RDPWorkerDigest, "InaccessiblePaths=-/var/lib/keybash -/etc/keybash/keys -/etc/keybash/tls"} {
		if !strings.Contains(files["keybash-rdp-manager.service"], required) {
			t.Fatal("RDP service boundary missing: " + required)
		}
	}
	for _, required := range []string{"BindsTo=keybash-ssh-manager.service keybash-rdp-manager.service", "serve-remote-lab", "--rdp-manager=/run/keybash-rdp-manager/control.sock"} {
		if !strings.Contains(files["keybash-gateway.service"], required) {
			t.Fatal("gateway RDP boundary missing")
		}
	}
	good := map[string]string{"cpu.max": "200000 100000\n", "memory.max": "1073741824\n", "memory.swap.max": "0\n", "pids.max": "512\n"}
	if validateState(c, "rdp-manager", "0::/keybash.slice/keybash-rdp-manager.service\n", good) != nil {
		t.Fatal("valid RDP kernel boundary refused")
	}
	if validateState(fixtureConfig(), "rdp-manager", "0::/keybash.slice/keybash-rdp-manager.service\n", good) == nil || validateState(c, "rdp-manager", "0::/keybash.slice/keybash-ssh-manager.service\n", good) == nil {
		t.Fatal("unconfigured or wrong RDP kernel boundary accepted")
	}
	for _, bad := range []func(*Config){func(c *Config) { c.RDPWorkerDigest = "" }, func(c *Config) { c.RDPRuntimeDigest = "" }, func(c *Config) { c.RDPWorkerDigest += "\nExecStart=/bin/sh" }, func(c *Config) { c.RDPRuntimeDigest = strings.Repeat("0", 64) }} {
		copy := c
		bad(&copy)
		if _, e := Render(copy); e == nil {
			t.Fatal("invalid RDP image profile accepted")
		}
	}
}

func TestServicePlanFiniteIdentityAndInjection(t *testing.T) {
	c := fixtureConfig()
	files, err := Render(c)
	if err != nil || len(files) != 4 || !strings.Contains(files["keybash.slice"], "MemoryMax=1024M\nMemorySwapMax=0\nTasksMax=512") {
		t.Fatal("valid finite service plan refused")
	}
	for _, name := range []string{"keybash-gateway.service", "keybash-ssh-manager.service"} {
		for _, required := range []string{"Slice=keybash.slice", "KillMode=control-group", "NoNewPrivileges=yes", "ProtectControlGroups=yes", "keybash-service-check", "Restart=no"} {
			if !strings.Contains(files[name], required+"\n") && !strings.Contains(files[name], required+" ") {
				t.Fatalf("service boundary missing: %s %s", name, required)
			}
		}
	}
	if !strings.Contains(files["keybash-ssh-manager.service"], "PrivateNetwork=yes\n") ||
		!strings.Contains(files["keybash-ssh-manager.service"], "RestrictAddressFamilies=AF_UNIX AF_NETLINK\n") {
		t.Fatal("manager private setup address families changed")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.CPUPercent = 0 }, func(c *Config) { c.CPUPercent = 6401 },
		func(c *Config) { c.MemoryMiB = 0 }, func(c *Config) { c.MemoryMiB = 1048577 },
		func(c *Config) { c.Tasks = 0 }, func(c *Config) { c.Tasks = 32769 },
		func(c *Config) { c.WorkerUID = c.GatewayUID }, func(c *Config) { c.WorkerGID = c.GatewayGID },
		func(c *Config) { c.WorkerUID = 0 }, func(c *Config) { c.GatewayUID = 65534 },
		func(c *Config) { c.WorkerGID = 2147483648 }, func(c *Config) { c.WorkerDigest = strings.Repeat("0", 64) },
		func(c *Config) { c.WorkerDigest = strings.Repeat("A", 64) }, func(c *Config) { c.WorkerDigest += "\nExecStart=/bin/sh" },
	} {
		bad := c
		mutate(&bad)
		if got, err := Render(bad); err == nil || got != nil {
			t.Fatal("invalid or injected service plan accepted")
		}
	}
}

func TestServiceKernelSnapshotRefusesUnenforcedAndWrongGroup(t *testing.T) {
	c := fixtureConfig()
	good := map[string]string{"cpu.max": "200000 100000\n", "memory.max": "1073741824\n", "memory.swap.max": "0\n", "pids.max": "512\n"}
	for _, role := range []string{"gateway", "manager"} {
		unit := "keybash-gateway.service"
		if role == "manager" {
			unit = "keybash-ssh-manager.service"
		}
		if validateState(c, role, "0::/keybash.slice/"+unit+"\n", good) != nil {
			t.Fatal("valid kernel boundary refused")
		}
	}
	for _, member := range []string{"", "0::/system.slice/keybash-gateway.service\n", "0::/keybash.slice/other.service\n", "0::/keybash.slice/keybash-gateway.service/sub\n", "0::/keybash.slice/keybash-gateway.service\n1:cpu:/other\n"} {
		if validateState(c, "gateway", member, good) == nil {
			t.Fatal("wrong kernel membership accepted")
		}
	}
	for key := range good {
		for _, raw := range []string{"", "max\n", "max 100000\n", "0\n", "18446744073709551616\n", "18446744073709551615 100000\n", "1 0\n", "10 100000\n", "512\nextra", "00\n"} {
			if key == "memory.swap.max" && raw == "0\n" || key == "pids.max" && raw == "512\n" {
				continue
			}
			bad := make(map[string]string)
			for k, v := range good {
				bad[k] = v
			}
			bad[key] = raw
			if validateState(c, "gateway", "0::/keybash.slice/keybash-gateway.service\n", bad) == nil {
				t.Fatalf("unenforced kernel boundary accepted: %s", key)
			}
		}
	}
	badSwap := map[string]string{"cpu.max": good["cpu.max"], "memory.max": good["memory.max"], "memory.swap.max": "1\n", "pids.max": good["pids.max"]}
	if validateState(c, "gateway", "0::/keybash.slice/keybash-gateway.service\n", badSwap) == nil {
		t.Fatal("swap escape accepted")
	}
}

func TestServiceCheckOutsideInstalledBoundaryRefuses(t *testing.T) {
	if Check(fixtureConfig(), "gateway") == nil || Check(fixtureConfig(), "arbitrary") == nil {
		t.Fatal("uninstalled service boundary accepted")
	}
}
