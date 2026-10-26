//go:build linux && amd64

package rdplab

import "github.com/denyfirst/keybash/internal/sandboxfilter"

// Kept outside rdpSeccomp so scripts/rdp-sandbox-mutations.py can replace that
// function wholesale without leaving an unused import behind.
var kernelSurface = sandboxfilter.KernelSurface
