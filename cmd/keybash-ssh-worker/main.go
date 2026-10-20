// Internal one-session worker. It is only usable inside the constrained Linux
// launcher with inherited TCP and private control descriptors; no listener.
package main

import (
	"github.com/denyfirst/keybash/internal/sshtransport"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 4 {
		os.Exit(1)
	}
	uid, ue := strconv.ParseUint(os.Args[2], 10, 31)
	gid, ge := strconv.ParseUint(os.Args[3], 10, 31)
	if ue != nil || ge != nil || uid == 0 || gid == 0 || sshtransport.RunProcessWorker(os.Args[1], uint32(uid), uint32(gid), os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}
