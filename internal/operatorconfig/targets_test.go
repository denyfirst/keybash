package operatorconfig

import (
	"github.com/denyfirst/keybash/internal/identity"
	"io"
)

// Target-only adapters keep the original identity/network assertions focused.
// Runtime APIs return capacity and targets together, so policy cannot be dropped.
func Parse(input io.Reader) ([]identity.RemoteTarget, error) {
	catalog, err := ParseCatalog(input)
	return catalog.Targets, err
}
func Load(path string) ([]identity.RemoteTarget, error) {
	catalog, err := LoadCatalog(path)
	return catalog.Targets, err
}
