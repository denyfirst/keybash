package terminalweb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeFiles answers like a Files worker over a tiny in-memory folder. It
// records what reached it, so a test can show that a refused operation
// never did.
type fakeFiles struct {
	mu       sync.Mutex
	replies  chan FileReply
	got      []FileRequest
	uploaded bytes.Buffer
	upload   *FileRequest
	file     []byte
	// failUpload fails an upload after it was accepted and this many bytes arrived.
	failUpload int
	// script, when set, answers every request instead of the folder.
	script func(FileRequest, chan<- FileReply)
	closed bool
}

func newFakeFiles() *fakeFiles {
	return &fakeFiles{replies: make(chan FileReply, 64), file: bytes.Repeat([]byte("k"), 3*FileChunk+7), failUpload: -1}
}

func (f *fakeFiles) Send(r FileRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, r)
	if f.script != nil {
		f.script(r, f.replies)
		return nil
	}
	switch r.Op {
	case OpList:
		f.replies <- FileReply{Kind: ReplyEntries, ID: r.ID, Entries: []FileEntry{{Name: []byte("notes.txt"), Kind: KindFile, Size: 5}, {Name: []byte{0xff, 0xfe}, Kind: KindFile}}}
		f.replies <- FileReply{Kind: ReplyDone, ID: r.ID, Path: "/srv/kb"}
	case OpGet:
		f.replies <- FileReply{Kind: ReplyAccept, ID: r.ID, Size: uint64(len(f.file))}
		for rest := f.file; len(rest) > 0; {
			n := min(len(rest), FileChunk)
			f.replies <- FileReply{Kind: ReplyData, Data: rest[:n]}
			rest = rest[n:]
		}
		f.replies <- FileReply{Kind: ReplyDone, ID: r.ID, Size: uint64(len(f.file))}
	case OpPut, OpReplace:
		f.upload = &r
		f.uploaded.Reset()
		f.replies <- FileReply{Kind: ReplyAccept, ID: r.ID}
	default:
		f.replies <- FileReply{Kind: ReplyDone, ID: r.ID}
	}
	return nil
}

func (f *fakeFiles) Upload(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upload == nil {
		return errors.New("no upload")
	}
	f.uploaded.Write(data)
	if f.failUpload >= 0 && f.uploaded.Len() >= f.failUpload {
		f.replies <- FileReply{Kind: ReplyFailed, ID: f.upload.ID, Failure: FailDenied}
		f.upload = nil
		return nil
	}
	if uint64(f.uploaded.Len()) == f.upload.Size {
		f.replies <- FileReply{Kind: ReplyDone, ID: f.upload.ID, Size: f.upload.Size}
		f.upload = nil
	}
	return nil
}
func (f *fakeFiles) Cancel(uint32) error       { return nil }
func (f *fakeFiles) Replies() <-chan FileReply { return f.replies }
func (f *fakeFiles) Close() error              { f.mu.Lock(); f.closed = true; f.mu.Unlock(); return nil }
func (f *fakeFiles) requests() []FileRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FileRequest(nil), f.got...)
}
func (f *fakeFiles) received() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Clone(f.uploaded.Bytes())
}
func (f *fakeFiles) setScript(s func(FileRequest, chan<- FileReply)) {
	f.mu.Lock()
	f.script = s
	f.mu.Unlock()
}

func filesClient(t *testing.T, stream FilesStream, mode FilesMode, activity func() error) *websocket.Conn {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		FilesRelay(r.Context(), conn, stream, mode, activity, nil)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadLimit(1 << 20)
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

func live() error { return nil }

func sendJSON(t *testing.T, conn *websocket.Conn, message string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte(message)); err != nil {
		t.Fatal(err)
	}
}

type pageMessage struct {
	Type    string      `json:"type"`
	ID      uint32      `json:"id"`
	Path    string      `json:"path"`
	Size    uint64      `json:"size"`
	Reason  string      `json:"reason"`
	Entries []wireEntry `json:"entries"`
}

// next reads the page's next message; binary frames come back as data.
func next(t *testing.T, conn *websocket.Conn) (pageMessage, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	kind, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if kind == websocket.MessageBinary {
		return pageMessage{}, data
	}
	var m pageMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("not JSON: %q", data)
	}
	return m, nil
}

// ended waits for the session's end and returns the word it gave.
func ended(t *testing.T, conn *websocket.Conn) string {
	t.Helper()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		kind, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			return ""
		}
		var m pageMessage
		if kind == websocket.MessageText && json.Unmarshal(data, &m) == nil && m.Type == "ended" {
			return m.Reason
		}
	}
}

func TestFilesRelayListsDownloadsAndUploads(t *testing.T) {
	stream := newFakeFiles()
	conn := filesClient(t, stream, FilesBoth, live)

	sendJSON(t, conn, `{"type":"list","id":1,"path":""}`)
	m, _ := next(t, conn)
	if m.Type != "entries" || len(m.Entries) != 2 || m.Entries[0].Name != "notes.txt" || !m.Entries[0].Readable {
		t.Fatalf("entries = %+v", m)
	}
	if m.Entries[1].Readable || m.Entries[1].Name != "" {
		t.Fatalf("a name that is not text reached the page: %+v", m.Entries[1])
	}
	if m, _ = next(t, conn); m.Type != "done" || m.Path != "/srv/kb" {
		t.Fatalf("done = %+v", m)
	}

	sendJSON(t, conn, `{"type":"get","id":2,"path":"/srv/kb/notes.txt"}`)
	if m, _ = next(t, conn); m.Type != "file" || m.Size != uint64(len(stream.file)) {
		t.Fatalf("file = %+v", m)
	}
	var got []byte
	for sequence := uint32(1); ; sequence++ {
		m, data := next(t, conn)
		if data == nil {
			if m.Type != "done" || m.Size != uint64(len(stream.file)) {
				t.Fatalf("download end = %+v", m)
			}
			break
		}
		if binary.BigEndian.Uint32(data) != sequence {
			t.Fatalf("frame %d came as %d", sequence, binary.BigEndian.Uint32(data))
		}
		got = append(got, data[4:]...)
		sendJSON(t, conn, `{"type":"ack","sequence":`+itoa(sequence)+`}`)
	}
	if !bytes.Equal(got, stream.file) {
		t.Fatal("the download's bytes differ")
	}

	body := bytes.Repeat([]byte("u"), FileChunk+10)
	sendJSON(t, conn, `{"type":"put","id":3,"path":"/srv/kb/new.bin","size":`+itoa(uint32(len(body)))+`}`)
	if m, _ = next(t, conn); m.Type != "accept" || m.ID != 3 {
		t.Fatalf("accept = %+v", m)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for rest := body; len(rest) > 0; {
		n := min(len(rest), FileChunk)
		if err := conn.Write(ctx, websocket.MessageBinary, rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if m, _ = next(t, conn); m.Type != "done" || m.Size != uint64(len(body)) {
		t.Fatalf("upload done = %+v", m)
	}
	if !bytes.Equal(stream.received(), body) {
		t.Fatal("the upload's bytes differ")
	}
}

func itoa(n uint32) string {
	return strings.TrimSpace(strings.Replace(string(rune('0')), "0", "", 1)) + uintString(n)
}
func uintString(n uint32) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for ; n > 0; n /= 10 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
	}
	return string(digits)
}

// Download only: every write is refused here, and never reaches the worker.
func TestFilesRelayRefusesWritesWhenDownloadOnly(t *testing.T) {
	for _, request := range []string{
		`{"type":"mkdir","id":1,"path":"/srv/kb/new"}`,
		`{"type":"rename","id":1,"path":"/srv/kb/a","to":"/srv/kb/b"}`,
		`{"type":"remove","id":1,"path":"/srv/kb/a"}`,
		`{"type":"rmdir","id":1,"path":"/srv/kb/a"}`,
		`{"type":"put","id":1,"path":"/srv/kb/a","size":1}`,
		`{"type":"replace","id":1,"path":"/srv/kb/a","size":1}`,
	} {
		stream := newFakeFiles()
		conn := filesClient(t, stream, FilesDownload, live)
		sendJSON(t, conn, request)
		if m, _ := next(t, conn); m.Type != "failed" || m.Reason != string(FailNotAllowed) || m.ID != 1 {
			t.Fatalf("%s: %+v", request, m)
		}
		if got := stream.requests(); len(got) != 0 {
			t.Fatalf("%s reached the worker: %+v", request, got)
		}
		// The session goes on: a listing still works.
		sendJSON(t, conn, `{"type":"list","id":2,"path":"/srv/kb"}`)
		if m, _ := next(t, conn); m.Type != "entries" {
			t.Fatalf("%s: the session did not go on: %+v", request, m)
		}
	}
}

// Anything the page never sends ends the session with "refused".
func TestFilesRelayEndsOnWhatThePageNeverSends(t *testing.T) {
	for _, message := range []string{
		`{"type":"exec","id":1,"path":"/bin/sh"}`,
		`{"type":"list","id":1,"path":"/srv/../etc"}`,
		`{"type":"list","id":1,"path":"relative"}`,
		`{"type":"list","id":0,"path":"/"}`,
		`{"type":"list","id":1,"path":"/","path":"/etc"}`,
		`{"type":"list","id":1,"path":"/","extra":1}`,
		`{"type":"get","id":1,"path":"/"}`,
		`{"type":"mkdir","id":1,"path":"/srv/kb/a\u202ebc"}`,
		`{"type":"rename","id":1,"path":"/srv/kb/a","to":"/tmp/a"}`,
		`{"type":"put","id":1,"path":"/srv/kb/a"}`,
		`{"type":"put","id":1,"path":"/srv/kb/a","size":2147483649}`,
		`{"type":"ack","sequence":1}`,
		`not json`,
	} {
		stream := newFakeFiles()
		conn := filesClient(t, stream, FilesBoth, live)
		sendJSON(t, conn, message)
		if word := ended(t, conn); word != string(ReasonRefused) {
			t.Fatalf("%s ended with %q", message, word)
		}
		if got := stream.requests(); len(got) != 0 {
			t.Fatalf("%s reached the worker: %+v", message, got)
		}
	}
	// Upload bytes with no accepted upload.
	conn := filesClient(t, newFakeFiles(), FilesBoth, live)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = conn.Write(ctx, websocket.MessageBinary, []byte("x"))
	if word := ended(t, conn); word != string(ReasonRefused) {
		t.Fatalf("stray bytes ended with %q", word)
	}
}

// A worker reply that does not fit the operation in flight ends the session.
func TestFilesRelayRefusesWorkerRepliesOutOfPlace(t *testing.T) {
	for name, script := range map[string]func(FileRequest, chan<- FileReply){
		"data before accept": func(r FileRequest, out chan<- FileReply) { out <- FileReply{Kind: ReplyData, Data: []byte("x")} },
		"another ID":         func(r FileRequest, out chan<- FileReply) { out <- FileReply{Kind: ReplyDone, ID: r.ID + 1, Path: "/"} },
		"entries for a get": func(r FileRequest, out chan<- FileReply) {
			out <- FileReply{Kind: ReplyEntries, ID: r.ID, Entries: []FileEntry{{Name: []byte("a")}}}
		},
		"unknown failure": func(r FileRequest, out chan<- FileReply) {
			out <- FileReply{Kind: ReplyFailed, ID: r.ID, Failure: "rm -rf"}
		},
		"oversized accept": func(r FileRequest, out chan<- FileReply) {
			out <- FileReply{Kind: ReplyAccept, ID: r.ID, Size: MaxFileSize + 1}
		},
		"two accepts": func(r FileRequest, out chan<- FileReply) {
			out <- FileReply{Kind: ReplyAccept, ID: r.ID}
			out <- FileReply{Kind: ReplyAccept, ID: r.ID}
		},
		"a path for a get": func(r FileRequest, out chan<- FileReply) { out <- FileReply{Kind: ReplyDone, ID: r.ID, Path: "/x"} },
		"data with an ID": func(r FileRequest, out chan<- FileReply) {
			out <- FileReply{Kind: ReplyAccept, ID: r.ID}
			out <- FileReply{Kind: ReplyData, ID: r.ID, Data: []byte("x")}
		},
	} {
		stream := newFakeFiles()
		stream.setScript(script)
		conn := filesClient(t, stream, FilesBoth, live)
		sendJSON(t, conn, `{"type":"get","id":1,"path":"/srv/kb/a"}`)
		if word := ended(t, conn); word != string(ReasonRefused) {
			t.Fatalf("%s ended with %q", name, word)
		}
	}
}

// A failed upload's bytes already on their way are dropped, up to what the
// upload announced; one byte more ends the session.
func TestFilesRelayDropsAFailedUploadsBytes(t *testing.T) {
	stream := newFakeFiles()
	stream.failUpload = 10
	conn := filesClient(t, stream, FilesBoth, live)
	sendJSON(t, conn, `{"type":"put","id":1,"path":"/srv/kb/a","size":30}`)
	if m, _ := next(t, conn); m.Type != "accept" {
		t.Fatalf("accept = %+v", m)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = conn.Write(ctx, websocket.MessageBinary, bytes.Repeat([]byte("a"), 10))
	if m, _ := next(t, conn); m.Type != "failed" || m.Reason != string(FailDenied) {
		t.Fatalf("failed = %+v", m)
	}
	_ = conn.Write(ctx, websocket.MessageBinary, bytes.Repeat([]byte("b"), 20))
	sendJSON(t, conn, `{"type":"list","id":2,"path":"/srv/kb"}`)
	if m, _ := next(t, conn); m.Type != "entries" {
		t.Fatalf("the session did not go on after the dropped bytes: %+v", m)
	}
	if got := stream.received(); len(got) != 10 {
		t.Fatalf("the worker got %d bytes, want the 10 before it failed", len(got))
	}

	stream = newFakeFiles()
	stream.failUpload = 10
	conn = filesClient(t, stream, FilesBoth, live)
	sendJSON(t, conn, `{"type":"put","id":1,"path":"/srv/kb/a","size":30}`)
	next(t, conn)
	_ = conn.Write(ctx, websocket.MessageBinary, bytes.Repeat([]byte("a"), 10))
	next(t, conn)
	_ = conn.Write(ctx, websocket.MessageBinary, bytes.Repeat([]byte("b"), 21))
	if word := ended(t, conn); word != string(ReasonRefused) {
		t.Fatalf("more than announced ended with %q", word)
	}
}

// A download acknowledged out of order ends the session.
func TestFilesRelayRefusesCreditOutOfOrder(t *testing.T) {
	stream := newFakeFiles()
	conn := filesClient(t, stream, FilesBoth, live)
	sendJSON(t, conn, `{"type":"get","id":1,"path":"/srv/kb/a"}`)
	next(t, conn)
	next(t, conn)
	sendJSON(t, conn, `{"type":"ack","sequence":2}`)
	if word := ended(t, conn); word != string(ReasonRefused) {
		t.Fatalf("ended with %q", word)
	}
}

// A sign-in that is no longer ready ends the session at the next operation.
func TestFilesRelayEndsWhenActivityFails(t *testing.T) {
	stream := newFakeFiles()
	conn := filesClient(t, stream, FilesBoth, func() error { return errors.New("signed out") })
	sendJSON(t, conn, `{"type":"list","id":1,"path":""}`)
	if word := ended(t, conn); word != string(ReasonRefused) {
		t.Fatalf("ended with %q", word)
	}
	if got := stream.requests(); len(got) != 0 {
		t.Fatalf("an operation reached the worker after the sign-in ended: %+v", got)
	}
}

func TestFileNamesAndPaths(t *testing.T) {
	for _, name := range []string{"a", "report 2026.pdf", "ünïcödé", "日本語", strings.Repeat("a", 255)} {
		if !ValidFileName(name) {
			t.Errorf("%q refused", name)
		}
	}
	for _, name := range []string{"", ".", "..", "a/b", strings.Repeat("a", 256), "a\x00b", "a\nb", "invoice\u202etxt.exe", "a\u200bb", "\ufeffa", "a\u2066b", "\xff"} {
		if ValidFileName(name) {
			t.Errorf("%q accepted", name)
		}
	}
	for _, p := range []string{"/", "/home", "/srv/kb/a b"} {
		if !ValidFilePath(p) {
			t.Errorf("%q refused", p)
		}
	}
	for _, p := range []string{"", "home", "/srv/", "/srv//kb", "/srv/./kb", "/srv/../etc", "/a\x00", "/" + strings.Repeat("a", MaxFilePath)} {
		if ValidFilePath(p) {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestFilePageEntries(t *testing.T) {
	for name, entry := range map[string]FileEntry{
		"not UTF-8": {Name: []byte{0xc3, 0x28}, Kind: KindFile},
		"a slash":   {Name: []byte("a/b"), Kind: KindFile},
		"NUL":       {Name: []byte("a\x00"), Kind: KindFile},
		"dot":       {Name: []byte(".."), Kind: KindDir},
	} {
		if out := pageEntry(entry); out.Readable || out.Name != "" {
			t.Errorf("%s reached the page as %+v", name, out)
		}
	}
	if out := pageEntry(FileEntry{Name: []byte("current"), Kind: KindLink, Target: KindDir}); !out.Readable || out.Kind != "link" || out.Target != "dir" {
		t.Errorf("link = %+v", out)
	}
	if out := pageEntry(FileEntry{Name: []byte("x"), Kind: KindFile, Target: KindDir}); out.Target != "" {
		t.Errorf("a file took a link's target: %+v", out)
	}
}

// Whatever a page sends, the parser never panics, and anything it accepts as
// an operation passes the same checks the worker applies.
func FuzzFilesRequest(f *testing.F) {
	for _, seed := range []string{
		`{"type":"list","id":1,"path":""}`, `{"type":"get","id":2,"path":"/srv/kb/a"}`,
		`{"type":"put","id":3,"path":"/srv/kb/a","size":10}`, `{"type":"rename","id":4,"path":"/a/b","to":"/a/c"}`,
		`{"type":"ack","sequence":1}`, `{"type":"cancel","id":9}`, `{"type":"list","id":1,"path":"/a","path":"/b"}`, `[]`, `{}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		request, control, ok := parseFileRequest(data)
		if !ok || control.ack || control.cancel {
			return
		}
		if !ValidFileRequest(request) || !request.Op.known() {
			t.Fatalf("accepted an invalid request: %+v", request)
		}
		if request.Op == OpRename && path.Dir(request.To) != path.Dir(request.Path) {
			t.Fatalf("a rename left its folder: %+v", request)
		}
		if (request.Op == OpPut || request.Op == OpReplace) && request.Size > MaxFileSize {
			t.Fatalf("an upload over the limit: %+v", request)
		}
	})
}
