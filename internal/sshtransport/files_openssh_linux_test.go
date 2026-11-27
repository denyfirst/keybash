//go:build linux

package sshtransport

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

// sftpServer is OpenSSH's own sftp-server, which CI installs. Elsewhere the
// test is skipped; on CI a missing server fails it.
func sftpServer(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/usr/lib/openssh/sftp-server", "/usr/lib/sftp-server", "/usr/libexec/openssh/sftp-server"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatal("CI has no sftp-server")
	}
	t.Skip("no sftp-server here")
	return ""
}

// workerFiles drives a Files worker over its frames, as the gateway does.
type workerFiles struct {
	t    *testing.T
	conn net.Conn
	id   uint32
}

func (w *workerFiles) send(r terminalweb.FileRequest) uint32 {
	w.t.Helper()
	w.id++
	r.ID = w.id
	data, ok := encodeFileRequest(r)
	if !ok || writeWorkerFrame(w.conn, frameFileRequest, data) != nil {
		w.t.Fatalf("request %+v not sent", r)
	}
	return r.ID
}

// end reads until the operation finishes: done (nil) or its failure.
func (w *workerFiles) end(id uint32, entries *[]terminalweb.FileEntry, data *[]byte) (string, terminalweb.FileFailure) {
	w.t.Helper()
	for {
		kind, frame := readFrameWithin(w.t, w.conn)
		switch kind {
		case frameFileEntries:
			got, list, ok := decodeEntries(frame)
			if !ok || got != id || entries == nil {
				w.t.Fatal("entries out of place")
			}
			*entries = append(*entries, list...)
		case frameFileAccept:
			if got, _, ok := decodeAccept(frame); !ok || got != id {
				w.t.Fatal("accept out of place")
			}
		case frameFileData:
			if data == nil {
				w.t.Fatal("data out of place")
			}
			*data = append(*data, frame...)
		case frameFileDone:
			got, _, where, ok := decodeDone(frame)
			if !ok || got != id {
				w.t.Fatal("done out of place")
			}
			return where, ""
		case frameFileFailed:
			got, failure, ok := decodeFailed(frame)
			if !ok || got != id {
				w.t.Fatal("failed out of place")
			}
			return "", failure
		default:
			w.t.Fatalf("frame %d", kind)
		}
	}
}

func (w *workerFiles) do(r terminalweb.FileRequest) terminalweb.FileFailure {
	w.t.Helper()
	_, failure := w.end(w.send(r), nil, nil)
	return failure
}

func (w *workerFiles) list(path string) (string, []terminalweb.FileEntry) {
	w.t.Helper()
	var entries []terminalweb.FileEntry
	where, failure := w.end(w.send(terminalweb.FileRequest{Op: terminalweb.OpList, Path: path}), &entries, nil)
	if failure != "" {
		w.t.Fatalf("list %s: %s", path, failure)
	}
	return where, entries
}

func (w *workerFiles) get(path string) ([]byte, terminalweb.FileFailure) {
	w.t.Helper()
	var data []byte
	_, failure := w.end(w.send(terminalweb.FileRequest{Op: terminalweb.OpGet, Path: path}), nil, &data)
	return data, failure
}

// put uploads body; cancelAfter > 0 cancels after that many bytes.
func (w *workerFiles) put(path string, body []byte, replace bool, cancelAfter int) terminalweb.FileFailure {
	w.t.Helper()
	op := terminalweb.OpPut
	if replace {
		op = terminalweb.OpReplace
	}
	id := w.send(terminalweb.FileRequest{Op: op, Path: path, Size: uint64(len(body))})
	if len(body) > 0 {
		kind, frame := readFrameWithin(w.t, w.conn)
		if kind == frameFileFailed {
			_, failure, _ := decodeFailed(frame)
			return failure
		}
		if got, _, ok := decodeAccept(frame); kind != frameFileAccept || !ok || got != id {
			w.t.Fatalf("no go-ahead: %d", kind)
		}
		sent := 0
		for sent < len(body) {
			if cancelAfter > 0 && sent >= cancelAfter {
				_ = writeWorkerFrame(w.conn, frameFileCancel, encodeID(id))
				break
			}
			n := min(len(body)-sent, terminalweb.FileChunk)
			if writeWorkerFrame(w.conn, frameFileData, body[sent:sent+n]) != nil {
				w.t.Fatal("data write failed")
			}
			sent += n
		}
	}
	_, failure := w.end(id, nil, nil)
	return failure
}

func noParts(t *testing.T, folder string) {
	t.Helper()
	list, _ := os.ReadDir(folder)
	for _, entry := range list {
		if strings.HasPrefix(entry.Name(), ".keybash-upload-") {
			t.Fatalf("a hidden upload part was left in %s", folder)
		}
	}
}

// The whole Files worker against OpenSSH's sftp-server over the worker core:
// every operation, the upload's hidden part, a replace, links, and refusals.
func TestFilesWorkerAgainstOpenSSH(t *testing.T) {
	server := sftpServer(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serve := func(channel ssh.Channel) {
		command := exec.Command(server)
		command.Dir, command.Stdin, command.Stdout, command.Stderr = home, channel, channel, io.Discard
		_ = command.Run()
		_ = channel.Close()
	}
	parent, _, done := filesWorkerFixture(t, kindFiles, "both", serve)
	if kind, _ := readFrameWithin(t, parent); kind != frameReady {
		t.Fatal("not ready")
	}
	w := &workerFiles{t: t, conn: parent}

	if where, entries := w.list(""); where != home || len(entries) != 0 {
		t.Fatalf("home = %q with %d entries, want %q", where, len(entries), home)
	}
	docs := home + "/docs"
	if failure := w.do(terminalweb.FileRequest{Op: terminalweb.OpMkdir, Path: docs}); failure != "" {
		t.Fatalf("mkdir: %s", failure)
	}
	if failure := w.do(terminalweb.FileRequest{Op: terminalweb.OpMkdir, Path: docs}); failure != terminalweb.FailExists {
		t.Fatalf("mkdir again: %q", failure)
	}

	first := make([]byte, 3*terminalweb.FileChunk+5)
	_, _ = rand.Read(first)
	if failure := w.put(docs+"/a.bin", first, false, 0); failure != "" {
		t.Fatalf("put: %s", failure)
	}
	if got, _ := os.ReadFile(docs + "/a.bin"); !bytes.Equal(got, first) {
		t.Fatal("the uploaded file differs")
	}
	noParts(t, docs)
	if failure := w.put(docs+"/a.bin", []byte("x"), false, 0); failure != terminalweb.FailExists {
		t.Fatalf("a new file over an old one: %q", failure)
	}
	if failure := w.put(docs+"/empty", nil, false, 0); failure != "" {
		t.Fatalf("an empty file: %s", failure)
	}
	if info, err := os.Stat(docs + "/empty"); err != nil || info.Size() != 0 {
		t.Fatal("the empty file is not there")
	}

	second := bytes.Repeat([]byte("second "), 9000)
	if failure := w.put(docs+"/a.bin", second, true, 0); failure != "" {
		t.Fatalf("replace: %s", failure)
	}
	if got, failure := w.get(docs + "/a.bin"); failure != "" || !bytes.Equal(got, second) {
		t.Fatalf("download after replace: %s, %d bytes", failure, len(got))
	}
	noParts(t, docs)

	// A cancelled replace leaves the old file whole and no part behind.
	big := make([]byte, 40*terminalweb.FileChunk)
	if failure := w.put(docs+"/a.bin", big, true, 4*terminalweb.FileChunk); failure != terminalweb.FailCancelled {
		t.Fatalf("cancelled replace: %q", failure)
	}
	if got, _ := os.ReadFile(docs + "/a.bin"); !bytes.Equal(got, second) {
		t.Fatal("a cancelled replace changed the file")
	}
	noParts(t, docs)

	if err := os.Symlink(docs, home+"/current"); err != nil {
		t.Fatal(err)
	}
	_, entries := w.list(home)
	found := map[string]terminalweb.FileEntry{}
	for _, e := range entries {
		found[string(e.Name)] = e
	}
	if found["docs"].Kind != terminalweb.KindDir || found["current"].Kind != terminalweb.KindLink || found["current"].Target != terminalweb.KindDir {
		t.Fatalf("listing: %+v", found)
	}
	if _, inside := w.list(docs); len(inside) != 2 {
		t.Fatalf("docs holds %d entries", len(inside))
	}

	if err := os.WriteFile(docs+"/c.bin", []byte("c"), 0o600); err != nil {
		t.Fatal(err)
	}
	if failure := w.do(terminalweb.FileRequest{Op: terminalweb.OpRename, Path: docs + "/a.bin", To: docs + "/c.bin"}); failure != terminalweb.FailExists {
		t.Fatalf("rename over a file: %q", failure)
	}
	if got, _ := os.ReadFile(docs + "/c.bin"); string(got) != "c" {
		t.Fatal("a refused rename replaced a file")
	}
	if failure := w.do(terminalweb.FileRequest{Op: terminalweb.OpRename, Path: docs + "/a.bin", To: docs + "/b.bin"}); failure != "" {
		t.Fatalf("rename: %s", failure)
	}
	if failure := w.do(terminalweb.FileRequest{Op: terminalweb.OpRmdir, Path: docs}); failure != terminalweb.FailNotEmpty {
		t.Fatalf("rmdir of a full folder: %q", failure)
	}
	if failure := w.do(terminalweb.FileRequest{Op: terminalweb.OpRemove, Path: docs}); failure == "" {
		t.Fatal("remove deleted a folder")
	}
	if _, failure := w.get(docs + "/missing"); failure != terminalweb.FailMissing {
		t.Fatalf("a missing file: %q", failure)
	}
	// Only a file is downloaded: a FIFO would hold the server's open forever.
	if err := syscall.Mkfifo(docs+"/pipe", 0o600); err != nil {
		t.Fatal(err)
	}
	if _, failure := w.get(docs + "/pipe"); failure == "" {
		t.Fatal("a FIFO was downloaded")
	}
	if _, failure := w.get(docs); failure == "" {
		t.Fatal("a folder was downloaded")
	}
	if err := os.Remove(docs + "/pipe"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"b.bin", "c.bin", "empty"} {
		if failure := w.do(terminalweb.FileRequest{Op: terminalweb.OpRemove, Path: docs + "/" + name}); failure != "" {
			t.Fatalf("remove %s: %s", name, failure)
		}
	}
	if failure := w.do(terminalweb.FileRequest{Op: terminalweb.OpRmdir, Path: docs}); failure != "" {
		t.Fatalf("rmdir: %s", failure)
	}
	if _, err := os.Stat(docs); !os.IsNotExist(err) {
		t.Fatal("the folder is still there")
	}
	_ = parent.Close()
	endsWithin(t, done)
}
