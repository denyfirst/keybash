//go:build linux

package identity

import (
	"os"
	"syscall"
)

func privateDirectory(path string) error {
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errRefused
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(os.Geteuid()) {
		return errRefused
	}
	r, e := os.OpenRoot(path)
	if e != nil {
		return errRefused
	}
	defer r.Close()
	f, e := r.Lstat("custody.db")
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || !f.Mode().IsRegular() || f.Mode().Perm() != 0600 {
		return errRefused
	}
	fs, ok := f.Sys().(*syscall.Stat_t)
	if !ok || int64(fs.Uid) != int64(os.Geteuid()) {
		return errRefused
	}
	return nil
}

func privateRoot(root *os.Root) error {
	info, e := root.Stat(".")
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errRefused
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(os.Geteuid()) {
		return errRefused
	}
	file, e := root.Lstat("custody.db")
	if e != nil || !file.Mode().IsRegular() || file.Mode().Perm() != 0600 {
		return errRefused
	}
	fs, ok := file.Sys().(*syscall.Stat_t)
	if !ok || int64(fs.Uid) != int64(os.Geteuid()) {
		return errRefused
	}
	return nil
}
