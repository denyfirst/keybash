package main

import (
	"fmt"
	"github.com/denyfirst/keybash/internal/rdplab"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	d, e := rdplab.RuntimeInventory(os.Args[1])
	if e != nil {
		fmt.Fprintln(os.Stderr, "RDP runtime refused")
		os.Exit(1)
	}
	fmt.Printf("%x\n", d)
}
