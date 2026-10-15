//go:build linux

package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCustodyLinuxPrivateProvisioning(t *testing.T) {
	base := t.TempDir()
	data, keys := filepath.Join(base, "data"), filepath.Join(base, "keys")
	for _, dir := range []string{data, keys} {
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("fixture mkdir failed")
		}
	}
	keyPath := filepath.Join(keys, "instance.key")
	if _, _, e := InitializeFiles(data, filepath.Join(data, "instance.key")); e == nil {
		t.Fatal("instance key accepted inside DB backup directory")
	}
	if os.Chmod(keys, 0755) != nil {
		t.Fatal("fixture chmod failed")
	}
	if _, _, e := InitializeFiles(data, keyPath); e == nil {
		t.Fatal("public key directory accepted")
	}
	_ = os.Chmod(keys, 0700)
	store, code, e := InitializeFiles(data, keyPath)
	if e != nil || !store.bootstrapValid(code, time.Now()) {
		t.Fatal("private Linux provisioning refused")
	}
	_ = store.Close()
	key, e := os.ReadFile(keyPath)
	if e != nil || len(key) != 32 {
		t.Fatal("instance key missing")
	}
	if _, _, e = InitializeFiles(data, keyPath); e == nil {
		t.Fatal("existing installation overwritten")
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(key, after) {
		t.Fatal("existing key altered")
	}
	for _, mode := range []os.FileMode{0644, 0660} {
		_ = os.Chmod(keyPath, mode)
		if s, e := OpenFiles(data, keyPath); e == nil {
			_ = s.Close()
			t.Fatal("shared instance key accepted")
		}
	}
	_ = os.Chmod(keyPath, 0600)
	_ = os.Chmod(filepath.Join(data, "custody.db"), 0644)
	if s, e := OpenFiles(data, keyPath); e == nil {
		_ = s.Close()
		t.Fatal("shared DB accepted")
	}
	_ = os.Chmod(filepath.Join(data, "custody.db"), 0600)
	_ = os.Chmod(data, 0755)
	if s, e := OpenFiles(data, keyPath); e == nil {
		_ = s.Close()
		t.Fatal("shared data directory accepted")
	}
	_ = os.Chmod(data, 0700)
	link := filepath.Join(keys, "link.key")
	if os.Symlink(keyPath, link) != nil {
		t.Fatal("fixture symlink failed")
	}
	if s, e := OpenFiles(data, link); e == nil {
		_ = s.Close()
		t.Fatal("symlink instance key accepted")
	}
	s, e := OpenFiles(data, keyPath)
	if e != nil {
		t.Fatal("valid persisted installation refused")
	}
	defer s.Close()
	if _, e = OpenFiles(data, keyPath); e == nil {
		t.Fatal("exclusive writer lock bypassed")
	}
}
