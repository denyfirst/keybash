//go:build !linux

package operatorconfig

func LoadCatalog(string) (Catalog, error) { return Catalog{}, ErrConfiguration }
