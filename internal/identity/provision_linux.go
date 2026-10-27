//go:build linux

package identity

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// keyRoot pins a private key directory separate from the pinned database path.
// Both locations must already exist, be owned by this UID, and have mode 0700.
func keyRoot(dir, path string) (*os.Root, string, error) {
	if privateDirectory(dir) != nil {
		return nil, "", errRefused
	}
	data, e := filepath.EvalSymlinks(dir)
	if e != nil {
		return nil, "", errRefused
	}
	data, e = filepath.Abs(data)
	if e != nil {
		return nil, "", errRefused
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return nil, "", errRefused
	}
	parent, e = filepath.Abs(parent)
	if e != nil {
		return nil, "", errRefused
	}
	rel, e := filepath.Rel(data, parent)
	if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil, "", errRefused
	}
	info, e := os.Stat(parent)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, "", errRefused
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(os.Geteuid()) {
		return nil, "", errRefused
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return nil, "", errRefused
	}
	pinned, e := root.Stat(".")
	if e != nil || !os.SameFile(info, pinned) {
		_ = root.Close()
		return nil, "", errRefused
	}
	name := filepath.Base(path)
	if name == "." || name == ".." {
		_ = root.Close()
		return nil, "", errRefused
	}
	return root, name, nil
}
func keyFile(root *os.Root, name string) ([]byte, error) {
	before, e := root.Lstat(name)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, errRefused
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(os.Geteuid()) {
		return nil, errRefused
	}
	f, e := root.Open(name)
	if e != nil {
		return nil, errRefused
	}
	defer f.Close()
	actual, e := f.Stat()
	now, ne := root.Lstat(name)
	if e != nil || ne != nil || !now.Mode().IsRegular() || !os.SameFile(before, actual) || !os.SameFile(now, actual) {
		return nil, errRefused
	}
	key, e := io.ReadAll(io.LimitReader(f, 33))
	if e != nil || len(key) != 32 {
		clear(key)
		return nil, errRefused
	}
	return key, nil
}

// InitializeFiles exclusively creates a new random instance key and database.
// Failure never removes or replaces existing files. Retain the key on failure.
func InitializeFiles(dir, keyPath string) (*Store, string, error) {
	root, name, e := keyRoot(dir, keyPath)
	if e != nil {
		return nil, "", errRefused
	}
	defer root.Close()
	var key [32]byte
	if _, e = rand.Read(key[:]); e != nil {
		return nil, "", errRefused
	}
	defer clear(key[:])
	if writeKeyFile(root, name, key[:]) != nil {
		return nil, "", errRefused
	}
	return InitializeStore(dir, key[:])
}

// writeKeyFile exclusively creates a durable 0600 key file; it never
// replaces one.
func writeKeyFile(root *os.Root, name string, key []byte) error {
	if len(key) != 32 {
		return errRefused
	}
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errRefused
	}
	n, we := f.Write(key)
	se := f.Sync()
	ce := f.Close()
	if we != nil || se != nil || ce != nil || n != 32 {
		return errRefused
	}
	parent, e := root.Open(".")
	if e != nil {
		return errRefused
	}
	e = parent.Sync()
	_ = parent.Close()
	if e != nil {
		return errRefused
	}
	return nil
}
func OpenFiles(dir, keyPath string) (*Store, error) {
	root, name, e := keyRoot(dir, keyPath)
	if e != nil {
		return nil, errRefused
	}
	defer root.Close()
	key, e := keyFile(root, name)
	if e != nil {
		return nil, errRefused
	}
	defer clear(key)
	return OpenStore(dir, key)
}
