//go:build !linux || !amd64

package servicepolicy

func Check(Config, string) error { return ErrPolicy }
