//go:build !linux

package identity

import "os"

// Production storage requires the tested Linux filesystem permission boundary.
// Portable tests use synthetic files through a package-private fixture only.
func privateDirectory(string) error { return errRefused }
func privateRoot(*os.Root) error    { return errRefused }
