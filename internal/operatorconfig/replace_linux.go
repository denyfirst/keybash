//go:build linux

package operatorconfig

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ReplaceCatalog swaps the root-owned catalog at path for next, as root, only
// if the file still holds exactly previous and next loads as a catalog. The
// parents are walked by descriptor without following links, as LoadCatalog
// walks them; the new file is written beside the old one, synced, owned by
// root with mode 0644, and renamed over it, so a reader sees one or the other.
func ReplaceCatalog(path string, previous, next []byte) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || path == "/" {
		return ErrConfiguration
	}
	if _, err := ParseCatalog(bytes.NewReader(next)); err != nil || len(next) > MaxBytes {
		return ErrConfiguration
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrConfiguration
	}
	defer func() { _ = unix.Close(dir) }()
	for i, part := range parts {
		var stat unix.Stat_t
		if unix.Fstat(dir, &stat) != nil || !safeDirectory(stat, i == len(parts)-1) {
			return ErrConfiguration
		}
		if i == len(parts)-1 {
			break
		}
		child, e := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return ErrConfiguration
		}
		_ = unix.Close(dir)
		dir = child
	}
	name := parts[len(parts)-1]
	current, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrConfiguration
	}
	f := os.NewFile(uintptr(current), "operator-catalog")
	var stat unix.Stat_t
	ok := unix.Fstat(current, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == 0 &&
		stat.Mode&0022 == 0 && stat.Mode&07000 == 0 && stat.Nlink == 1 && stat.Size > 0 && stat.Size <= MaxBytes
	held, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	_ = f.Close()
	if !ok || err != nil || !bytes.Equal(held, previous) {
		return ErrConfiguration // changed since it was read, or not the catalog LoadCatalog admits
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return ErrConfiguration
	}
	temp := "." + name + ".keybash-" + hex.EncodeToString(suffix[:])
	fd, err := unix.Openat(dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrConfiguration
	}
	out := os.NewFile(uintptr(fd), "operator-catalog-next")
	written, err := out.Write(next)
	if err != nil || written != len(next) || unix.Fchown(fd, 0, 0) != nil || unix.Fchmod(fd, 0644) != nil || out.Sync() != nil {
		_ = out.Close()
		_ = unix.Unlinkat(dir, temp, 0)
		return ErrConfiguration
	}
	if out.Close() != nil || unix.Renameat(dir, temp, dir, name) != nil {
		_ = unix.Unlinkat(dir, temp, 0)
		return ErrConfiguration
	}
	if unix.Fsync(dir) != nil {
		return ErrConfiguration
	}
	return nil
}
