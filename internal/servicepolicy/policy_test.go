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
