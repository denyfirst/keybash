// Internal one-session worker. It is only usable inside the constrained Linux
// launcher with inherited TCP and private control descriptors; no listener.
package main

import (
	"github.com/denyfirst/keybash/internal/sshtransport"
	"os"
)

func main() {
	if len(os.Args) != 2 || sshtransport.RunProcessWorker(os.Args[1], os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}
