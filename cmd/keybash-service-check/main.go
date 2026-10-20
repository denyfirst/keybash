// Fixed kernel/identity preflight for generated systemd units. No secrets.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/denyfirst/keybash/internal/servicepolicy"
)

func main() {
	c := servicepolicy.Default()
	var gu, gg, wu, wg uint64
	role := flag.String("role", "", "gateway or manager")
	flag.Uint64Var(&gu, "gateway-uid", 0, "gateway UID")
	flag.Uint64Var(&gg, "gateway-gid", 0, "gateway GID")
	flag.Uint64Var(&wu, "worker-uid", 0, "worker UID")
	flag.Uint64Var(&wg, "worker-gid", 0, "worker GID")
	flag.StringVar(&c.WorkerDigest, "worker-digest", "", "approved digest")
	flag.Uint64Var(&c.CPUPercent, "cpu-percent", c.CPUPercent, "expected aggregate CPU percent")
	flag.Uint64Var(&c.MemoryMiB, "memory-mib", c.MemoryMiB, "expected aggregate memory MiB")
	flag.Uint64Var(&c.Tasks, "tasks", c.Tasks, "expected aggregate tasks")
	flag.Parse()
	if flag.NArg() != 0 || gu > 2147483647 || gg > 2147483647 || wu > 2147483647 || wg > 2147483647 {
		fail()
	}
	c.GatewayUID, c.GatewayGID, c.WorkerUID, c.WorkerGID = uint32(gu), uint32(gg), uint32(wu), uint32(wg)
	if servicepolicy.Check(c, *role) != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "service identity or kernel resource boundary refused")
	os.Exit(1)
}
