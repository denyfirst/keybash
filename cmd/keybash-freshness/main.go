// Maintainer check: compares every version Keybash pins with the newest
// upstream release and prints a Markdown table. It exits 0 when every pin is
// current, 3 when one is behind and 1 when a pin or a lookup failed. Run it
// from the repository root: go run ./cmd/keybash-freshness. Not part of the
// product; the weekly freshness workflow runs it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/denyfirst/keybash/internal/freshness"
)

func main() { os.Exit(run()) }

func run() int {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	pins, err := freshness.Pins(os.DirFS(*root))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	results := freshness.Check(ctx, freshness.DefaultUpstream(os.Getenv("GH_TOKEN")), pins)
	if err := freshness.Report(os.Stdout, results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	failed, behind := false, false
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(os.Stderr, "%s: %v\n", r.Name, r.Err)
			failed = true
		case r.Behind():
			behind = true
		}
	}
	switch {
	case failed:
		return 1
	case behind:
		return 3
	}
	return 0
}
