//go:build linux

package operatorconfig

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func rootCatalogFixture(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("required root execution is in scripts/operator-config-lab.sh")
	}
	base := t.TempDir()
	for _, dir := range []string{base, filepath.Dir(base)} {
		if os.Chmod(dir, 0755) != nil {
			t.Fatal("fixture directory mode failed")
		}
	}
	path := filepath.Join(base, "targets.json")
	good := fixture(t)
	if os.WriteFile(path, []byte(good), 0644) != nil { // #nosec G306 -- public synthetic operator metadata; gateway is a separate UID.
		t.Fatal("fixture catalog write failed")
	}
	return path, good
}

func TestOperatorCatalogLinuxRootFiles(t *testing.T) {
	path, good := rootCatalogFixture(t)
	if targets, err := Load(path); err != nil || len(targets) != 1 {
		t.Fatal("valid root-owned catalog refused")
	}
	deny := func(path string) {
		t.Helper()
		if targets, err := Load(path); err != ErrConfiguration || targets != nil {
			t.Fatal("unsafe catalog file accepted")
		}
	}
	deny("targets.json")
	deny(filepath.Dir(path) + "/./targets.json")
	deny("/")
	deny(filepath.Dir(path))
	deny(path + "-missing")
	for _, mode := range []os.FileMode{0666, 0664, 0646, 0644 | os.ModeSetuid} {
		if os.Chmod(path, mode) != nil {
			t.Fatal("fixture mode failed")
		}
		deny(path)
	}
	if os.Chmod(path, 0644) != nil || os.Chown(path, 65533, 65533) != nil {
		t.Fatal("fixture ownership failed")
	}
	deny(path)
	if os.Chown(path, 0, 0) != nil {
		t.Fatal("fixture ownership restore failed")
	}
	link := path + "-symlink"
	if os.Symlink(path, link) != nil {
		t.Fatal("fixture symlink failed")
	}
	deny(link)
	link = path + "-hardlink"
	if os.Link(path, link) != nil {
		t.Fatal("fixture hardlink failed")
	}
	deny(path)
	deny(link)
	if os.Remove(link) != nil {
		t.Fatal("fixture hardlink restore failed")
	}
	fifo := path + "-fifo"
	if unix.Mkfifo(fifo, 0644) != nil {
		t.Fatal("fixture fifo failed")
	}
	deny(fifo) // O_NONBLOCK must refuse rather than waiting for a writer.
	parent := filepath.Dir(path)
	for _, mode := range []os.FileMode{0777, 0777 | os.ModeSticky} {
		if os.Chmod(parent, mode) != nil {
			t.Fatal("fixture shared parent failed")
		}
		deny(path)
	}
	if os.Chmod(parent, 0755) != nil || os.Chown(parent, 65533, 65533) != nil {
		t.Fatal("fixture parent ownership failed")
	}
	deny(path)
	if os.Chown(parent, 0, 0) != nil {
		t.Fatal("fixture parent restore failed")
	}
	alias := filepath.Join(filepath.Dir(parent), "alias")
	if os.Symlink(parent, alias) != nil {
		t.Fatal("fixture directory symlink failed")
	}
	deny(filepath.Join(alias, "targets.json"))
	if os.WriteFile(path, []byte(strings.Repeat(" ", MaxBytes+1)), 0644) != nil {
		t.Fatal("fixture excess write failed")
	}
	deny(path)
	if os.WriteFile(path, []byte(good), 0644) != nil {
		t.Fatal("fixture catalog restore failed")
	}
	if _, err := Load(path); err != nil {
		t.Fatal("restored valid root catalog refused")
	}
}

func TestOperatorCatalogLinuxUnprivilegedReader(t *testing.T) {
	path, _ := rootCatalogFixture(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("fixture executable missing")
	}
	// go test builds the binary in root's private build directory, which UID
	// 65533 cannot enter. Run a copy from the fixture's readable directory, as
	// scripts/operator-config-lab.sh does with its own build.
	program, err := os.ReadFile(binary) // #nosec G304 -- the current test executable.
	reader := filepath.Join(filepath.Dir(path), "reader.test")
	if err != nil || os.WriteFile(reader, program, 0555) != nil { // #nosec G306 -- a synthetic test binary the separate reader UID must execute.
		t.Fatal("fixture executable copy failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, reader, "-test.run=^TestOperatorCatalogLinuxReaderChild$", "-test.v") // #nosec G204 -- a copy of the current test executable, fixed child selector.
	child.Dir = filepath.Dir(path)
	child.Env = []string{"KEYBASH_CATALOG_READER_CHILD=1"}
	child.Stdin = strings.NewReader(path)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
	if raw, err := child.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged root-catalog reader failed: %s", raw)
	}
}

func TestOperatorCatalogLinuxReaderChild(t *testing.T) {
	if os.Getenv("KEYBASH_CATALOG_READER_CHILD") != "1" {
		return
	}
	if os.Geteuid() != 65533 || os.Getegid() != 65533 {
		t.Fatal("fixture privilege drop failed")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		t.Fatal("fixture path read failed")
	}
	path := string(raw)
	if targets, err := Load(path); err != nil || len(targets) != 1 {
		t.Fatal("unprivileged valid catalog refused")
	}
	if os.WriteFile(path, []byte("{}"), 0644) == nil { // #nosec G306 -- asserts that the separate gateway cannot change root metadata.
		t.Fatal("unprivileged reader changed operator catalog")
	}
}
