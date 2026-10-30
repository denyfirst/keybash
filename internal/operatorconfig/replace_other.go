//go:build !linux

package operatorconfig

func ReplaceCatalog(string, []byte, []byte) error { return ErrConfiguration }
