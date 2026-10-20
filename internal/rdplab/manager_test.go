package rdplab

import (
	"context"
	"strings"
	"testing"
)

func TestRDPManagerConfigurationAndIdentityRefusal(t *testing.T) {
	c := ManagerConfig{GatewayUID: 1001, GatewayGID: 1001, WorkerUID: 1002, WorkerGID: 1002, MaxSessions: 8, WorkerDigest: [32]byte{1}, RuntimeDigest: [32]byte{2}}
	if !c.valid() {
		t.Fatal("valid RDP manager configuration refused")
	}
	for _, bad := range []func(*ManagerConfig){func(c *ManagerConfig) { c.WorkerUID = c.GatewayUID }, func(c *ManagerConfig) { c.WorkerGID = c.GatewayGID }, func(c *ManagerConfig) { c.WorkerUID = 0 }, func(c *ManagerConfig) { c.WorkerGID = 65534 }, func(c *ManagerConfig) { c.GatewayUID = 1 << 31 }, func(c *ManagerConfig) { c.WorkerDigest = [32]byte{} }, func(c *ManagerConfig) { c.RuntimeDigest = [32]byte{} }, func(c *ManagerConfig) { c.MaxSessions = 0 }, func(c *ManagerConfig) { c.MaxSessions = 129 }} {
		copy := c
		bad(&copy)
		if copy.valid() {
			t.Fatal("invalid RDP manager policy accepted")
		}
	}
	for _, id := range []string{"0", "65534", "-1", "01", "1\n", "2147483648", strings.Repeat("9", 128)} {
		if _, e := ParseWorkerID(id); e == nil {
			t.Fatal("malformed worker identity accepted")
		}
	}
	if id, e := ParseWorkerID("1002"); e != nil || id != 1002 {
		t.Fatal("valid worker identity refused")
	}
	if s, e := (ManagerWorker{}).openDial(context.Background(), nil, nil, "user", "password"); s != nil || e == nil {
		t.Fatal("unconfigured RDP launcher opened a session")
	}
}
