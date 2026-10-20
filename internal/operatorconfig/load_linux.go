//go:build linux

package operatorconfig

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// LoadCatalog admits only an absolute, root-owned regular catalog under root-owned
// directories. Walked descriptors pin each parent; no symlink is followed.
// A sticky writable ancestor (e.g. /tmp in tests) may contain the protected
// root-owned directory, but the direct parent must never be shared-writable.
func LoadCatalog(path string) (Catalog, error) {
	var zero Catalog
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || path == "/" {
		return zero, ErrConfiguration
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, ErrConfiguration
	}
	defer func() { _ = unix.Close(fd) }()
	for i := 0; i < len(parts); i++ {
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || !safeDirectory(stat, i == len(parts)-1) {
			return zero, ErrConfiguration
		}
		if i == len(parts)-1 {
			break
		}
		next, e := unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return zero, ErrConfiguration
		}
		_ = unix.Close(fd)
		fd = next
	}
	fileFD, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, ErrConfiguration
	}
	f := os.NewFile(uintptr(fileFD), "operator-catalog")
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fileFD, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 ||
		before.Mode&0022 != 0 || before.Mode&07000 != 0 || before.Nlink != 1 || before.Size <= 0 || before.Size > MaxBytes {
		return zero, ErrConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fileFD, &after) != nil ||
		before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return zero, ErrConfiguration
	}
	return ParseCatalog(strings.NewReader(string(raw)))
}

func safeDirectory(stat unix.Stat_t, directParent bool) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Uid == 0 &&
		(stat.Mode&0022 == 0 || !directParent && stat.Mode&unix.S_ISVTX != 0)
}
