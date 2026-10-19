//go:build !linux

package operatorconfig

import "testing"

func TestOperatorCatalogUnsupportedHostRefuses(t *testing.T) {
	if targets, err := Load("targets.json"); targets != nil || err != ErrConfiguration {
		t.Fatal("unsupported host established file authority")
	}
}
