package main

import (
	"github.com/denyfirst/keybash/internal/rdplab"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		os.Exit(1)
	}
	u, e := rdplab.ParseWorkerID(os.Args[2])
	g, ge := rdplab.ParseWorkerID(os.Args[3])
	if e != nil || ge != nil || rdplab.RunNativeWorker(os.Args[1], u, g) != nil {
		os.Exit(1)
	}
}
