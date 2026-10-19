//go:build !linux

package operatorconfig

import "github.com/denyfirst/keybash/internal/identity"

func Load(string) ([]identity.RemoteTarget, error) { return nil, ErrConfiguration }
