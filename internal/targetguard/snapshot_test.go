package targetguard

import "testing"

func TestNamedTargetSnapshotIsSortedCopiedAndNetworkFree(t *testing.T) {
	target, _ := namedFixture(t, 22)
	first := target.Snapshot()
	if first.Hostname != "server.example" || first.Port != 22 || len(first.Addresses) != 2 || first.Addresses[0] != "10.20.30.40" || first.Addresses[1] != "fd42::5" {
		t.Fatal("approved target metadata differs")
	}
	first.Addresses[0] = "127.0.0.1"
	first.Hostname = "attacker.invalid"
	first.Port = 1
	second := target.Snapshot()
	if second.Hostname != "server.example" || second.Port != 22 || second.Addresses[0] != "10.20.30.40" {
		t.Fatal("metadata caller changed approval authority")
	}
	var missing *NamedTarget
	if value := missing.Snapshot(); value.Hostname != "" || value.Port != 0 || len(value.Addresses) != 0 {
		t.Fatal("nil target invented approval metadata")
	}
}
