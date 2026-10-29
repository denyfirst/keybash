//go:build linux

package operatorconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A guided edit replaces the catalog only as root, only if nobody changed it
// meanwhile, only with a catalog that loads, and never through a link.
func TestOperatorCatalogReplaceIsCheckedAndAtomic(t *testing.T) {
	path, good := rootCatalogFixture(t)
	next := strings.Replace(good, `"name":"`, `"name":"Renamed `, 1)
	if next == good {
		t.Fatal("fixture has no name to change")
	}
	unchanged := func(want string) {
		t.Helper()
		raw, err := os.ReadFile(path) // #nosec G304 -- the test's own fixture path.
		if err != nil || string(raw) != want {
			t.Fatal("refused replacement changed the catalog")
		}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil || len(entries) != 1 {
			t.Fatal("a refused replacement left a file behind")
		}
	}
	for _, refusal := range []struct{ previous, next string }{
		{good + " ", next},                  // someone edited it since it was read
		{good, `{"version":1}`},             // not a catalog
		{good, strings.Repeat(" ", 300000)}, // oversized
	} {
		if ReplaceCatalog(path, []byte(refusal.previous), []byte(refusal.next)) == nil {
			t.Fatal("unsafe catalog replacement accepted")
		}
		unchanged(good)
	}
	link := path + "-symlink"
	if os.Symlink(path, link) != nil {
		t.Fatal("fixture symlink failed")
	}
	if ReplaceCatalog(link, []byte(good), []byte(next)) == nil {
		t.Fatal("unsafe catalog replacement accepted through a link")
	}
	if os.Remove(link) != nil || os.Chmod(path, 0664) != nil {
		t.Fatal("fixture change failed")
	}
	if ReplaceCatalog(path, []byte(good), []byte(next)) == nil {
		t.Fatal("unsafe catalog replacement accepted over a group-writable file")
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("fixture mode restore failed")
	}
	unchanged(good)

	if ReplaceCatalog(path, []byte(good), []byte(next)) != nil {
		t.Fatal("valid root-owned catalog refused")
	}
	unchanged(next)
	var stat unix.Stat_t
	if unix.Stat(path, &stat) != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&07777 != 0644 || stat.Nlink != 1 {
		t.Fatal("replaced catalog is not a root-owned 0644 file")
	}
	if targets, err := Load(path); err != nil || len(targets) != 1 || !strings.HasPrefix(targets[0].Name, "Renamed ") {
		t.Fatal("replaced catalog does not load as written")
	}
}
