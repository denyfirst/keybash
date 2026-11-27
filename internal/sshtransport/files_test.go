package sshtransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

// sftpRecorder answers the SFTP greeting and records every packet type sent
// after it, without serving anything: enough to show what a worker never asks.
type sftpRecorder struct {
	mu    sync.Mutex
	after []byte
}

func (r *sftpRecorder) serve(channel ssh.Channel) {
	var header [5]byte
	greeted := false
	for {
		if _, err := io.ReadFull(channel, header[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(header[:4])
		if size < 1 || size > 1<<20 {
			return
		}
		if _, err := io.CopyN(io.Discard, channel, int64(size-1)); err != nil {
			return
		}
		if !greeted && header[4] == 1 {
			greeted = true
			_, _ = channel.Write([]byte{0, 0, 0, 5, 2, 0, 0, 0, 3})
			continue
		}
		r.mu.Lock()
		r.after = append(r.after, header[4])
		r.mu.Unlock()
	}
}

func (r *sftpRecorder) packets() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.after)
}

// filesWorkerFixture starts the worker core as a Files session in mode,
// against a synthetic server whose sftp subsystem sftp serves.
func filesWorkerFixture(t *testing.T, kind, mode string, sftp func(ssh.Channel)) (net.Conn, *sshFixture, <-chan error) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("entropy failed")
	}
	user, _ := ssh.NewSignerFromKey(private)
	host := syntheticSigner(t)
	fixture := newFixture(t, fixtureOptions{host: host, user: user, sftpFixture: sftp})
	parent, child := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveSSHWorker(ctx, child, child, fixture.client) }()
	t.Cleanup(func() { cancel(); _ = parent.Close() })
	key, err := sshkey.New(private)
	if err != nil {
		t.Fatal("key fixture failed")
	}
	material, err := key.Material()
	key.Close()
	if err != nil {
		t.Fatal("key handoff failed")
	}
	start := ssh.Marshal(&workerStart{Version: workerVersion, Kind: kind, Mode: mode, Host: "ssh.invalid", User: "lab-user", Pin: host.PublicKey().Marshal(), Method: methodKey, Secret: material})
	if writeWorkerFrame(parent, frameStart, start) != nil {
		t.Fatal("start write failed")
	}
	return parent, fixture, done
}

func readFrameWithin(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, data, err := readWorkerFrame(conn)
	if err != nil {
		t.Fatalf("no frame: %v", err)
	}
	return kind, data
}

func endsWithin(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not end")
	}
}

// A Files worker authenticates as a terminal does, then asks the server for
// the sftp subsystem and nothing else: no PTY, no shell, no exec.
func TestFilesWorkerAsksForSFTPOnly(t *testing.T) {
	recorder := &sftpRecorder{}
	parent, fixture, done := filesWorkerFixture(t, kindFiles, "both", recorder.serve)
	if kind, data := readFrameWithin(t, parent); kind != frameReady || len(data) != 0 {
		t.Fatalf("ready = %d %q", kind, data)
	}
	var requests []string
	for {
		select {
		case event := <-fixture.events:
			requests = append(requests, event.kind+":"+string(event.payload))
			continue
		case <-time.After(300 * time.Millisecond):
		}
		break
	}
	if len(requests) != 1 || !strings.HasPrefix(requests[0], "subsystem:") || !strings.HasSuffix(requests[0], "sftp") {
		t.Fatalf("the Files worker asked for %q", requests)
	}
	_ = parent.Close()
	endsWithin(t, done)
}

// Download only: the worker refuses every write itself, before any SFTP
// request, whatever the gateway sends.
func TestFilesWorkerRefusesWritesWhenDownloadOnly(t *testing.T) {
	recorder := &sftpRecorder{}
	parent, _, done := filesWorkerFixture(t, kindFiles, "download", recorder.serve)
	readFrameWithin(t, parent)
	for i, r := range []terminalweb.FileRequest{
		{Op: terminalweb.OpMkdir, Path: "/home/kb/new"},
		{Op: terminalweb.OpRename, Path: "/home/kb/a", To: "/home/kb/b"},
		{Op: terminalweb.OpRemove, Path: "/home/kb/a"},
		{Op: terminalweb.OpRmdir, Path: "/home/kb/a"},
		{Op: terminalweb.OpPut, Path: "/home/kb/a", Size: 3},
		{Op: terminalweb.OpReplace, Path: "/home/kb/a", Size: 3},
	} {
		r.ID = uint32(i + 1)
		data, ok := encodeFileRequest(r)
		if !ok || writeWorkerFrame(parent, frameFileRequest, data) != nil {
			t.Fatal("request write failed")
		}
		kind, reply := readFrameWithin(t, parent)
		id, failure, ok := decodeFailed(reply)
		if kind != frameFileFailed || !ok || id != r.ID || failure != terminalweb.FailNotAllowed {
			t.Fatalf("%s: %d %q", r.Op, kind, reply)
		}
	}
	if got := recorder.packets(); len(got) != 0 {
		t.Fatalf("a refused write reached the server as SFTP packets %v", got)
	}
	_ = parent.Close()
	endsWithin(t, done)
}

// Each kind of session refuses the other's frames, and a start frame that
// does not name its kind and mode correctly starts nothing.
func TestWorkerKindsKeepTheirOwnFrames(t *testing.T) {
	parent, _, done := filesWorkerFixture(t, kindFiles, "both", (&sftpRecorder{}).serve)
	readFrameWithin(t, parent)
	_ = writeWorkerFrame(parent, frameInput, []byte("ls\n"))
	endsWithin(t, done)

	parent, _, done = filesWorkerFixture(t, kindFiles, "both", (&sftpRecorder{}).serve)
	readFrameWithin(t, parent)
	_ = writeWorkerFrame(parent, frameFileData, []byte("stray"))
	endsWithin(t, done)

	parent, fixture, done := filesWorkerFixture(t, kindTerminal, "", nil)
	readFrameWithin(t, parent)
	data, _ := encodeFileRequest(terminalweb.FileRequest{ID: 1, Op: terminalweb.OpList})
	_ = writeWorkerFrame(parent, frameFileRequest, data)
	endsWithin(t, done)
	for {
		select {
		case event := <-fixture.events:
			if event.kind == "subsystem" {
				t.Fatal("a terminal worker asked for a subsystem")
			}
			continue
		default:
		}
		break
	}

	for name, start := range map[string][2]string{
		"files without a mode":   {kindFiles, ""},
		"files with an odd mode": {kindFiles, "all"},
		"a terminal with a mode": {kindTerminal, "both"},
		"no kind":                {"", ""},
		"an unknown kind":        {"shell", ""},
	} {
		if _, ok := startKind(workerStart{Kind: start[0], Mode: start[1]}); ok {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, start := range [][2]string{{kindTerminal, ""}, {kindFiles, "download"}, {kindFiles, "both"}} {
		if _, ok := startKind(workerStart{Kind: start[0], Mode: start[1]}); !ok {
			t.Errorf("%v was refused", start)
		}
	}
}

func TestFilesFramesRoundTripAndRefuseMalformed(t *testing.T) {
	request := terminalweb.FileRequest{ID: 7, Op: terminalweb.OpRename, Path: "/home/kb/a", To: "/home/kb/b"}
	data, ok := encodeFileRequest(request)
	if back, ok2 := decodeFileRequest(data); !ok || !ok2 || back != request {
		t.Fatalf("request round trip: %+v", back)
	}
	if _, ok := encodeFileRequest(terminalweb.FileRequest{ID: 1, Op: "exec", Path: "/bin/sh"}); ok {
		t.Fatal("an unknown operation was encoded")
	}
	forged := ssh.Marshal(&fileRequestWire{ID: 1, Op: "list", Path: "/home/../etc"})
	if _, ok := decodeFileRequest(forged); ok {
		t.Fatal("the worker took a path the gateway never sends")
	}

	batch := newEntryBatch(9)
	entries := []terminalweb.FileEntry{{Name: []byte("a"), Kind: terminalweb.KindFile, Size: 5, Time: 9}, {Name: []byte{0xff}, Kind: terminalweb.KindLink, Target: terminalweb.KindDir}}
	for _, e := range entries {
		if !batch.add(e) {
			t.Fatal("a small batch was full")
		}
	}
	if id, got, ok := decodeEntries(batch.data); !ok || id != 9 || len(got) != 2 || !bytes.Equal(got[1].Name, []byte{0xff}) || got[1].Target != terminalweb.KindDir {
		t.Fatalf("entries round trip: %d %+v", id, got)
	}
	full := newEntryBatch(1)
	count := 0
	for full.add(terminalweb.FileEntry{Name: bytes.Repeat([]byte("n"), 255), Kind: terminalweb.KindFile}) {
		count++
	}
	if len(full.data) > terminalweb.FileChunk || count == 0 {
		t.Fatalf("a batch of %d bytes", len(full.data))
	}
	for name, bad := range map[string][]byte{
		"no ID":            {0, 0, 0, 0, 1, 'a', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"empty name":       append(encodeID(1), 0),
		"cut short":        append(encodeID(1), 5, 'a'),
		"unknown kind":     append(append(encodeID(1), 1, 'a', 9, 0), make([]byte, 12)...),
		"target on a file": append(append(encodeID(1), 1, 'a', 1, 2), make([]byte, 12)...),
		"only an ID":       encodeID(1),
	} {
		if _, _, ok := decodeEntries(bad); ok {
			t.Errorf("%s decoded", name)
		}
	}
	if done, ok := encodeDone(3, 10, "/home/kb"); !ok {
		t.Fatal("done refused")
	} else if id, size, where, ok := decodeDone(done); !ok || id != 3 || size != 10 || where != "/home/kb" {
		t.Fatal("done round trip")
	}
	if _, ok := encodeDone(3, 0, "/home/../etc"); ok {
		t.Fatal("done took a path that is not canonical")
	}
	if _, _, _, ok := decodeDone(append(binary.BigEndian.AppendUint64(encodeID(1), terminalweb.MaxFileSize+1), 0, 0)); ok {
		t.Fatal("done over the size limit decoded")
	}
	if _, _, ok := decodeAccept(binary.BigEndian.AppendUint64(encodeID(1), terminalweb.MaxFileSize+1)); ok {
		t.Fatal("accept over the size limit decoded")
	}
	for _, failure := range []terminalweb.FileFailure{terminalweb.FailExists, terminalweb.FailMissing, terminalweb.FailDenied, terminalweb.FailNotEmpty, terminalweb.FailTooLarge, terminalweb.FailNotAllowed, terminalweb.FailFailed, terminalweb.FailCancelled} {
		if id, got, ok := decodeFailed(encodeFailed(4, failure)); !ok || id != 4 || got != failure {
			t.Errorf("failure %q round trip gave %q", failure, got)
		}
	}
	for _, bad := range [][]byte{append(encodeID(1), 0), append(encodeID(1), 9), append(encodeID(0), 1), {1, 2}} {
		if _, _, ok := decodeFailed(bad); ok {
			t.Errorf("failed frame %v decoded", bad)
		}
	}
}

// The gateway decodes whatever a worker sends without panicking, and keeps
// only what fits each frame's rules.
func FuzzFilesFrames(f *testing.F) {
	batch := newEntryBatch(2)
	batch.add(terminalweb.FileEntry{Name: []byte("notes"), Kind: terminalweb.KindFile, Size: 3})
	done, _ := encodeDone(2, 3, "/home/kb")
	f.Add(byte(frameFileEntries), batch.data)
	f.Add(byte(frameFileDone), done)
	f.Add(byte(frameFileAccept), encodeAccept(2, 9))
	f.Add(byte(frameFileFailed), encodeFailed(2, terminalweb.FailDenied))
	f.Add(byte(frameFileRequest), ssh.Marshal(&fileRequestWire{ID: 1, Op: "list", Path: "/"}))
	f.Fuzz(func(t *testing.T, kind byte, data []byte) {
		switch kind % 5 {
		case 0:
			if id, entries, ok := decodeEntries(data); ok {
				if id == 0 || len(entries) == 0 {
					t.Fatal("an empty or unnamed batch decoded")
				}
				for _, e := range entries {
					if len(e.Name) == 0 || len(e.Name) > terminalweb.MaxFileName || e.Kind > terminalweb.KindLink {
						t.Fatalf("entry %+v", e)
					}
				}
			}
		case 1:
			if _, size, where, ok := decodeDone(data); ok && (size > terminalweb.MaxFileSize || where != "" && !terminalweb.ValidFilePath(where)) {
				t.Fatal("done outside its rules")
			}
		case 2:
			if _, size, ok := decodeAccept(data); ok && size > terminalweb.MaxFileSize {
				t.Fatal("accept over the limit")
			}
		case 3:
			if _, failure, ok := decodeFailed(data); ok && !terminalweb.ValidFailure(failure) {
				t.Fatal("an unknown failure")
			}
		case 4:
			if r, ok := decodeFileRequest(data); ok && !terminalweb.ValidFileRequest(r) {
				t.Fatal("an invalid request")
			}
		}
	})
}

// The gateway's side of a Files worker: each frame it reads is decoded and
// passed on in order, a frame a Files worker never sends ends the session,
// and what the relay asks for leaves as exactly one checked frame.
func TestFilesProcessStreamPassesOnlyWhatDecodes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	defer outR.Close()
	defer outW.Close()
	s := &processStream{ctx: ctx, cancel: cancel, in: inW, out: outR, replies: make(chan terminalweb.FileReply, 8)}

	// What is never valid is refused before anything is written.
	if s.Upload(nil) == nil || s.Upload(make([]byte, terminalweb.FileChunk+1)) == nil || s.Cancel(0) == nil || s.Send(terminalweb.FileRequest{ID: 1, Op: "exec"}) == nil {
		t.Fatal("an invalid frame was sent")
	}
	// Sending sets a write deadline, which only Linux pipes support; the
	// gateway runs there.
	if runtime.GOOS == "linux" {
		request := terminalweb.FileRequest{ID: 3, Op: terminalweb.OpGet, Path: "/home/kb/a"}
		if s.Send(request) != nil || s.Upload([]byte("chunk")) != nil || s.Cancel(3) != nil {
			t.Fatal("a valid frame was not sent")
		}
		for _, want := range []byte{frameFileRequest, frameFileData, frameFileCancel} {
			kind, data, err := readWorkerFrame(inR)
			if err != nil || kind != want {
				t.Fatalf("sent frame %d, want %d", kind, want)
			}
			if kind == frameFileRequest {
				if got, ok := decodeFileRequest(data); !ok || got != request {
					t.Fatalf("request arrived as %+v", got)
				}
			}
		}
	}

	batch := newEntryBatch(3)
	batch.add(terminalweb.FileEntry{Name: []byte("a"), Kind: terminalweb.KindFile, Size: 1})
	done, _ := encodeDone(3, 1, "")
	for _, frame := range []struct {
		kind byte
		data []byte
	}{{frameFileEntries, batch.data}, {frameFileAccept, encodeAccept(3, 1)}, {frameFileData, []byte("x")}, {frameFileDone, done}, {frameFileFailed, encodeFailed(3, terminalweb.FailDenied)}, {frameOutput, []byte("a terminal's output")}} {
		if writeWorkerFrame(outW, frame.kind, frame.data) != nil {
			t.Fatal("fixture frame failed")
		}
	}
	go s.filesDemux()
	var kinds []terminalweb.FileReplyKind
	for reply := range s.replies {
		kinds = append(kinds, reply.Kind)
	}
	want := []terminalweb.FileReplyKind{terminalweb.ReplyEntries, terminalweb.ReplyAccept, terminalweb.ReplyData, terminalweb.ReplyDone, terminalweb.ReplyFailed}
	if !slices.Equal(kinds, want) {
		t.Fatalf("replies %v, want %v", kinds, want)
	}
	if ctx.Err() == nil {
		t.Fatal("a terminal's frame on a Files stream did not end it")
	}
}

// Each kind of session survives its trip through the start frame.
func TestWorkerKindsRoundTrip(t *testing.T) {
	for _, kind := range []workerKind{{}, {files: true, mode: terminalweb.FilesDownload}, {files: true, mode: terminalweb.FilesBoth}} {
		name, mode := kind.wire()
		if got, ok := startKind(workerStart{Kind: name, Mode: mode}); !ok || got != kind {
			t.Fatalf("%+v came back as %+v", kind, got)
		}
	}
}
