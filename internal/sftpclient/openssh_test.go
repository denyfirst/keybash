package sftpclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// TestOpenSSHServer runs the client against OpenSSH's own sftp-server over
// its standard input and output. CI installs it; elsewhere the test skips.
func TestOpenSSHServer(t *testing.T) {
	var bin string
	for _, p := range []string{"/usr/lib/openssh/sftp-server", "/usr/lib/sftp-server"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			bin = p
			break
		}
	}
	if bin == "" {
		t.Skip("OpenSSH sftp-server is not installed")
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin) // #nosec G204 -- one of two fixed system paths checked above.
	cmd.Dir = dir
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Wait()
	})
	c, err := New(ctx, struct {
		io.Reader
		io.Writer
	}{out, in})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	root, err := c.RealPath(".")
	if err != nil {
		t.Fatalf("RealPath: %v", err)
	}
	if want, _ := filepath.EvalSymlinks(dir); root != dir && root != want {
		t.Fatalf("RealPath(.) = %q, want %q", root, dir)
	}
	sub := root + "/files"
	if err := c.Mkdir(sub); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	data := pattern(1<<20 + 5)
	tmp := sub + "/upload.tmp"
	if err := c.Upload(ctx, tmp, int64(len(data)), int64(len(data)), chunker(data, ChunkSize, 1000, ChunkSize-1)); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if err := c.Upload(ctx, tmp, 1, 1, chunker([]byte{1})); !isStatus(err, StatusFailure) {
		t.Fatalf("exclusive Upload over an existing file: %v", err)
	}
	final := sub + "/data.bin"
	if err := c.Rename(tmp, final); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := os.Symlink("data.bin", filepath.Join(dir, "files", "link")); err != nil {
		t.Fatal(err)
	}

	var names []string
	kinds := map[string]Kind{}
	if err := c.List(sub, 100, func(e Entry) error {
		names = append(names, string(e.Name))
		kinds[string(e.Name)] = e.Attr.Kind
		if string(e.Name) == "data.bin" && (!e.Attr.HasSize || e.Attr.Size != uint64(len(data))) {
			t.Errorf("listed size %d", e.Attr.Size)
		}
		return nil
	}); err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "data.bin" || names[1] != "link" || kinds["data.bin"] != KindFile || kinds["link"] != KindLink {
		t.Fatalf("listing %q %v", names, kinds)
	}
	if a, err := c.Stat(sub + "/link"); err != nil || a.Kind != KindFile || a.Size != uint64(len(data)) || a.ModTime == 0 {
		t.Fatalf("Stat link: %+v, %v", a, err)
	}
	if a, err := c.Lstat(sub + "/link"); err != nil || a.Kind != KindLink {
		t.Fatalf("Lstat link: %+v, %v", a, err)
	}
	if a, err := c.Stat(sub); err != nil || a.Kind != KindDir {
		t.Fatalf("Stat folder: %+v, %v", a, err)
	}

	for _, p := range []string{final, sub + "/link"} {
		g := fetch(t, ctx, c, p, int64(len(data)))
		if g.err != nil || g.size != int64(len(data)) || g.n != int64(len(data)) || !bytes.Equal(g.data, data) {
			t.Fatalf("Download %s: n=%d size=%d err=%v", p, g.n, g.size, g.err)
		}
	}
	if g := fetch(t, ctx, c, final, int64(len(data))-1); !errors.Is(g.err, ErrTooLarge) {
		t.Fatalf("Download over the limit: %v", g.err)
	}

	other := sub + "/other"
	if err := c.Upload(ctx, other, 3, 3, chunker([]byte("abc"))); err != nil {
		t.Fatalf("Upload other: %v", err)
	}
	if err := c.Rename(other, final); !isStatus(err, StatusFailure) {
		t.Fatalf("Rename over an existing file: %v", err)
	}
	if err := c.Rmdir(sub); err == nil {
		t.Fatal("Rmdir of a full folder succeeded")
	}
	for _, p := range []string{sub + "/link", final, other} {
		if err := c.Remove(p); err != nil {
			t.Fatalf("Remove %s: %v", p, err)
		}
	}
	if err := c.Rmdir(sub); err != nil {
		t.Fatalf("Rmdir: %v", err)
	}
	if _, err := c.Stat(sub); !isStatus(err, StatusNoSuchFile) {
		t.Fatalf("Stat after Rmdir: %v", err)
	}
}
