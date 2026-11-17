package main

import (
	"github.com/denyfirst/keybash/internal/rdplab"
	"os"
)

// The manager starts this with the parent network namespace, the worker UID
// and GID, and, only for a desktop through Keybash's RDP proxy, the one word
// "proxy". Anything else exits.
func main() {
	if len(os.Args) != 4 && (len(os.Args) != 5 || os.Args[4] != "proxy") {
		os.Exit(1)
	}
	u, e := rdplab.ParseWorkerID(os.Args[2])
	g, ge := rdplab.ParseWorkerID(os.Args[3])
	if e != nil || ge != nil || rdplab.RunNativeWorker(os.Args[1], u, g, len(os.Args) == 5) != nil {
		os.Exit(1)
	}
}
