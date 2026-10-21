// Offline source plan only: this command never installs or starts a service.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/denyfirst/keybash/internal/servicepolicy"
)

func main() {
	c := servicepolicy.Default()
	var gu, gg, wu, wg uint64
	flag.Uint64Var(&gu, "gateway-uid", 0, "unused dedicated gateway UID")
	flag.Uint64Var(&gg, "gateway-gid", 0, "unused dedicated gateway GID")
	flag.Uint64Var(&wu, "worker-uid", 0, "unused dedicated worker UID")
	flag.Uint64Var(&wg, "worker-gid", 0, "unused dedicated worker GID")
	flag.StringVar(&c.RDPWorkerDigest, "rdp-worker-digest", "", "optional fixed RDP worker digest; requires runtime digest")
	flag.StringVar(&c.RDPRuntimeDigest, "rdp-runtime-digest", "", "optional complete RDP runtime inventory digest")
	flag.StringVar(&c.WorkerDigest, "worker-digest", "", "approved static worker SHA256")
	flag.Uint64Var(&c.CPUPercent, "cpu-percent", c.CPUPercent, "aggregate CPU percent of one core")
	flag.Uint64Var(&c.MemoryMiB, "memory-mib", c.MemoryMiB, "aggregate memory MiB")
	flag.Uint64Var(&c.Tasks, "tasks", c.Tasks, "aggregate processes and threads")
	output := flag.String("output", "", "new staging directory; must not exist")
	flag.Parse()
	if flag.NArg() != 0 || gu > 2147483647 || gg > 2147483647 || wu > 2147483647 || wg > 2147483647 || !filepath.IsAbs(*output) || filepath.Clean(*output) != *output {
		fail()
	}
	c.GatewayUID, c.GatewayGID, c.WorkerUID, c.WorkerGID = uint32(gu), uint32(gg), uint32(wu), uint32(wg)
	files, err := servicepolicy.Render(c)
	if err != nil || os.Mkdir(*output, 0700) != nil {
		fail()
	}
	root, err := os.OpenRoot(*output)
	if err != nil {
		fail()
	}
	defer root.Close()
	for name, contents := range files {
		f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			fail()
		}
		_, err = f.WriteString(contents)
		ce := f.Close()
		if err != nil || ce != nil {
			fail()
		}
	}
	fmt.Println("Source service plan written. No service installed or started.")
}

func fail() { fmt.Fprintln(os.Stderr, "service plan refused"); os.Exit(1) }
