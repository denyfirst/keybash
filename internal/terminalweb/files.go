package terminalweb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

// Files moves files between the browser and a server's account over SFTP
// (ADR 0011). The browser asks for one operation at a time in strict JSON;
// file bytes travel as binary frames of at most FileChunk bytes. A download
// keeps the terminal's window of unacknowledged frames; an upload is paced by
// the socket itself, because the relay reads the next chunk only after the
// worker took the last one.
const (
	FileChunk   = 32 * 1024
	MaxFileSize = 2 << 30 // 2 GiB each way
	MaxFilePath = 4096
	MaxFileName = 255
	MaxEntries  = 10000
	// A request holds at most two paths and a few small fields.
	fileRequestLimit = 16 * 1024
)

// FilesMode is what an administrator allows on a server.
type FilesMode string

const (
	FilesDownload FilesMode = "download" // list folders and download files
	FilesBoth     FilesMode = "both"     // also upload, make folders, rename and delete
)

func ValidFilesMode(mode FilesMode) bool { return mode == FilesDownload || mode == FilesBoth }

// FileOp is one operation a Files session can ask for. Nothing else reaches
// the worker, which builds the SFTP packets itself.
type FileOp string

const (
	OpList    FileOp = "list"
	OpMkdir   FileOp = "mkdir"
	OpRename  FileOp = "rename"
	OpRemove  FileOp = "remove"
	OpRmdir   FileOp = "rmdir"
	OpGet     FileOp = "get"
	OpPut     FileOp = "put"     // a new file; refused when the name is taken
	OpReplace FileOp = "replace" // replaces a file the person confirmed
)

// Writes says whether an operation changes the server, which only
// FilesBoth allows.
func (op FileOp) Writes() bool {
	switch op {
	case OpMkdir, OpRename, OpRemove, OpRmdir, OpPut, OpReplace:
		return true
	}
	return false
}

func (op FileOp) known() bool { return op == OpList || op == OpGet || op.Writes() }

// FileRequest is one operation, already checked by ParseFileRequest.
type FileRequest struct {
	ID       uint32
	Op       FileOp
	Path, To string
	Size     uint64
}

// FileKind is what an entry is, from the server's attributes.
type FileKind uint8

const (
	KindOther FileKind = iota
	KindFile
	KindDir
	KindLink
)

// FileEntry is one name in a folder, as the worker read it. Name is the
// server's raw bytes: it may not be text, and the page is told so.
type FileEntry struct {
	Name         []byte
	Kind, Target FileKind // Target only for a link: what it points at, if known
	Size         uint64
	Time         uint32
}

// FileFailure is the one word the page gets when an operation failed.
// Nothing the server says reaches the page.
type FileFailure string

const (
	FailExists     FileFailure = "exists"
	FailMissing    FileFailure = "missing"
	FailDenied     FileFailure = "denied"
	FailNotEmpty   FileFailure = "not-empty"
	FailTooLarge   FileFailure = "too-large"
	FailNotAllowed FileFailure = "not-allowed"
	FailFailed     FileFailure = "failed"
	FailCancelled  FileFailure = "cancelled"
)

// A FileFailure is also the error the worker returns for it.
func (f FileFailure) Error() string { return "file operation failed: " + string(f) }

var failures = map[FileFailure]bool{FailExists: true, FailMissing: true, FailDenied: true, FailNotEmpty: true,
	FailTooLarge: true, FailNotAllowed: true, FailFailed: true, FailCancelled: true}

func ValidFailure(failure FileFailure) bool { return failures[failure] }

// FileReplyKind is what the worker said about the current operation.
type FileReplyKind uint8

const (
	ReplyEntries FileReplyKind = iota + 1 // a batch of a folder's names
	ReplyAccept                           // a download starts (Size), or an upload may send its bytes
	ReplyData                             // a download's next bytes
	ReplyDone                             // the operation finished; a listing names its folder in Path
	ReplyFailed                           // the operation failed, for Failure
)

type FileReply struct {
	Kind    FileReplyKind
	ID      uint32
	Entries []FileEntry
	Data    []byte
	Size    uint64
	Path    string
	Failure FileFailure
}

// FilesStream is one Files session's worker. Replies is closed when the
// worker ends; its Reason (a Reasoned stream) says why, if it knows.
type FilesStream interface {
	Send(FileRequest) error
	Upload([]byte) error
	Cancel(id uint32) error
	Replies() <-chan FileReply
	Close() error
}

// ValidFilePath is an absolute, canonical UTF-8 path without NUL. The
// account's own rights on the server decide everything else.
func ValidFilePath(p string) bool {
	return len(p) > 0 && len(p) <= MaxFilePath && p[0] == '/' && utf8.ValidString(p) &&
		!strings.ContainsRune(p, 0) && path.Clean(p) == p
}

// ValidFileName is a name a person may give a new folder or file here. It
// refuses control and direction characters, which a person never means to
// type and which can make one name look like another.
func ValidFileName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > MaxFileName || !utf8.ValidString(name) || strings.ContainsRune(name, '/') {
		return false
	}
	for _, r := range name {
		if HiddenRune(r) {
			return false
		}
	}
	return true
}

// HiddenRune is a control or direction character: the same list the page
// shows as visible marks (web/files.mjs).
func HiddenRune(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x061c || r == 0x180e ||
		(r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) ||
		(r >= 0x2060 && r <= 0x2064) || (r >= 0x2066 && r <= 0x2069) || r == 0xfeff
}

type fileMessage struct {
	Type     string  `json:"type"`
	ID       uint32  `json:"id,omitempty"`
	Path     *string `json:"path,omitempty"`
	To       string  `json:"to,omitempty"`
	Size     *uint64 `json:"size,omitempty"`
	Sequence uint32  `json:"sequence,omitempty"`
}

// strictJSON decodes one object with no unknown, repeated or trailing keys.
func strictJSON(data []byte, limit int, into any) bool {
	if len(data) == 0 || len(data) > limit {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(into) != nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	keys := json.NewDecoder(bytes.NewReader(data))
	opening, err := keys.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, 6)
	for keys.More() {
		key, err := keys.Token()
		name, isString := key.(string)
		if err != nil || !isString || seen[name] || keys.Decode(new(json.RawMessage)) != nil {
			return false
		}
		seen[name] = true
	}
	return true
}

// fileControl is what a page may send besides an operation.
type fileControl struct {
	ack, cancel bool
	value       uint32
}

// parseFileRequest accepts one operation the page may ask for, with every
// path and name checked, or one ack or cancel. Anything else refuses, and the
// relay ends the session: the page never sends it.
func parseFileRequest(data []byte) (FileRequest, fileControl, bool) {
	var m fileMessage
	if !strictJSON(data, fileRequestLimit, &m) {
		return FileRequest{}, fileControl{}, false
	}
	switch m.Type {
	case "ack":
		ok := m.Sequence != 0 && m.ID == 0 && m.Path == nil && m.To == "" && m.Size == nil
		return FileRequest{}, fileControl{ack: true, value: m.Sequence}, ok
	case "cancel":
		ok := m.ID != 0 && m.Sequence == 0 && m.Path == nil && m.To == "" && m.Size == nil
		return FileRequest{}, fileControl{cancel: true, value: m.ID}, ok
	}
	op := FileOp(m.Type)
	if !op.known() || m.ID == 0 || m.Sequence != 0 || m.Path == nil {
		return FileRequest{}, fileControl{}, false
	}
	r := FileRequest{ID: m.ID, Op: op, Path: *m.Path, To: m.To}
	sized := op == OpPut || op == OpReplace
	if sized != (m.Size != nil) {
		return FileRequest{}, fileControl{}, false
	}
	if sized {
		r.Size = *m.Size
	}
	if !ValidFileRequest(r) {
		return FileRequest{}, fileControl{}, false
	}
	return r, fileControl{}, true
}

// ValidFileRequest checks one operation's paths and names. The relay checks
// what the page sends, and the worker checks what the gateway sends, with
// this same function.
func ValidFileRequest(r FileRequest) bool {
	if r.ID == 0 || !r.Op.known() || (r.Op == OpRename) != (r.To != "") || (r.Op != OpPut && r.Op != OpReplace && r.Size != 0) {
		return false
	}
	// A listing may ask for the account's home folder by leaving the path empty.
	if r.Op == OpList && r.Path == "" {
		return true
	}
	if !ValidFilePath(r.Path) || r.Path == "/" {
		return false
	}
	name := path.Base(r.Path)
	switch r.Op {
	case OpMkdir:
		return ValidFileName(name)
	case OpPut, OpReplace:
		return ValidFileName(name) && r.Size <= MaxFileSize
	case OpRename:
		// A rename stays in its folder and never takes a name with hidden characters.
		return ValidFilePath(r.To) && path.Dir(r.To) == path.Dir(r.Path) && ValidFileName(path.Base(r.To)) && r.To != r.Path
	}
	return true
}

type wireEntry struct {
	Name     string `json:"name"`
	Readable bool   `json:"readable"`
	Kind     string `json:"kind"`
	Target   string `json:"target,omitempty"`
	Size     uint64 `json:"size"`
	Time     uint32 `json:"time"`
}

var kindWords = map[FileKind]string{KindOther: "other", KindFile: "file", KindDir: "dir", KindLink: "link"}

// pageEntry turns a raw entry into what the page shows. A name that is not
// text, or that could not name a file (a slash, NUL), is sent as unreadable
// with no name: the page offers no action on it.
func pageEntry(entry FileEntry) wireEntry {
	out := wireEntry{Kind: kindWords[entry.Kind], Size: entry.Size, Time: entry.Time}
	if out.Kind == "" {
		out.Kind = "other"
	}
	if entry.Kind == KindLink && (entry.Target == KindDir || entry.Target == KindFile) {
		out.Target = kindWords[entry.Target]
	}
	name := string(entry.Name)
	if len(entry.Name) > 0 && len(entry.Name) <= MaxFileName && utf8.ValidString(name) && !strings.ContainsAny(name, "/\x00") && name != "." && name != ".." {
		out.Name, out.Readable = name, true
	}
	return out
}

// fileOperation is the one operation in flight, shared by the two halves of
// the relay.
type fileOperation struct {
	mu       sync.Mutex
	id       uint32
	op       FileOp
	accepted bool
	left     uint64 // bytes an accepted upload may still send
	received uint64 // bytes a download has sent
	// A failed upload's bytes still on their way from the page, which are
	// dropped rather than ending the session.
	discard uint64
	request FileRequest // the operation as asked, for the observer
}

// finish ends the operation id and returns what was asked.
func (f *fileOperation) finish(id uint32) (FileRequest, bool) {
	f.mu.Lock()
	request := f.request
	f.mu.Unlock()
	return request, f.end(id)
}

// FileObserver is told how each operation that moves or changes a file
// ended: its request, the failure word ("" when done) and the bytes it moved.
// An error ends the session, as one whose record cannot be written.
type FileObserver func(r FileRequest, failure FileFailure, size uint64) error

func (f *fileOperation) begin(r FileRequest) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.id != 0 {
		return false
	}
	f.id, f.op, f.accepted, f.left, f.received, f.discard, f.request = r.ID, r.Op, false, r.Size, 0, 0, r
	return true
}
func (f *fileOperation) end(id uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.id == 0 || f.id != id {
		return false
	}
	f.id = 0
	return true
}
func (f *fileOperation) current() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.id
}

// FilesRelay carries one ALREADY authorized Files session. The caller owns
// origin, MFA, CSRF, the lease and the mode check at admission; activity
// runs before each operation and upload chunk and ends the session when it
// fails (a sign-in that is no longer ready). Mode is enforced here again for
// every operation, and the worker enforces it a third time.
func FilesRelay(ctx context.Context, conn *websocket.Conn, stream FilesStream, mode FilesMode, activity func() error, observe FileObserver) {
	if ctx == nil || conn == nil || stream == nil || activity == nil || !ValidFilesMode(mode) {
		if conn != nil {
			_ = conn.CloseNow()
		}
		if stream != nil {
			_ = stream.Close()
		}
		return
	}
	session := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	defer conn.CloseNow()
	defer stream.Close()
	conn.SetReadLimit(fileRequestLimit + FileChunk)
	closed := make(chan struct{})
	context.AfterFunc(ctx, func() {
		defer close(closed)
		_ = stream.Close()
		reason := endReason(session, nil)
		if reason == "" {
			if own, ok := context.Cause(ctx).(Reason); ok && reasons[own] {
				reason = own
			} else if r, ok := stream.(Reasoned); ok && reasons[r.Reason()] {
				reason = r.Reason()
			}
		}
		if reason != "" {
			say, done := context.WithTimeout(context.Background(), time.Second)
			_ = conn.Write(say, websocket.MessageText, []byte(`{"type":"ended","reason":"`+string(reason)+`"}`))
			done()
		}
		_ = conn.CloseNow()
	})
	runFiles(ctx, cancel, conn, stream, mode, activity, observe, creditTimeout)
	cancel(nil)
	<-closed
}

// runFiles relays until either half stops. Ending goes through end, whose
// cause says why; the ending then tells the page and closes the socket,
// which is what stops a read or write in progress. The socket is never read
// or written with a context the ending cancels: that would close it before
// the page heard why.
func runFiles(ctx context.Context, end context.CancelCauseFunc, conn *websocket.Conn, stream FilesStream, mode FilesMode, activity func() error, observe FileObserver, wait time.Duration) {
	var op fileOperation
	// record tells the observer how an operation ended; a record that cannot
	// be written ends the session with its own word.
	record := func(r FileRequest, failure FileFailure, size uint64) bool {
		if observe == nil || r.Op == OpList || observe(r, failure, size) == nil {
			return true
		}
		end(ReasonUnrecorded)
		return false
	}
	window := &flow{credit: make(chan struct{}, 1)}
	socket := context.WithoutCancel(ctx)
	refuse := func() { end(ReasonRefused) }
	// Replies the relay makes itself (a mode refusal) go through the writer,
	// so the socket has one writer.
	local := make(chan []byte, 1)
	var workers sync.WaitGroup
	send := func(message any) bool {
		data, err := json.Marshal(message)
		if err != nil {
			return false
		}
		return conn.Write(socket, websocket.MessageText, data) == nil
	}
	// The writer: every reply from the worker, in order.
	workers.Go(func() {
		defer end(nil)
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-local:
				if conn.Write(socket, websocket.MessageText, data) != nil {
					return
				}
			case reply, open := <-stream.Replies():
				if !open {
					return
				}
				if !forwardReply(ctx, socket, conn, &op, window, reply, send, record, wait) {
					refuse()
					return
				}
			}
		}
	})
	// The reader: operations, acks, cancels and upload chunks from the page.
	workers.Go(func() {
		defer end(nil)
		for {
			kind, data, err := conn.Read(socket)
			if err != nil || ctx.Err() != nil {
				return
			}
			if kind == websocket.MessageBinary {
				forward, ok := acceptChunk(&op, data)
				if !ok || activity() != nil {
					refuse()
					return
				}
				if forward && stream.Upload(data) != nil {
					return
				}
				continue
			}
			request, control, ok := parseFileRequest(data)
			switch {
			case !ok:
				refuse()
				return
			case control.ack:
				if !window.acknowledge(control.value) {
					refuse()
					return
				}
			case control.cancel:
				if op.current() == control.value && stream.Cancel(control.value) != nil {
					return
				}
			default:
				if activity() != nil || !op.begin(request) {
					refuse()
					return
				}
				if request.Op.Writes() && mode != FilesBoth {
					op.end(request.ID)
					if !record(request, FailNotAllowed, 0) {
						return
					}
					reply, _ := json.Marshal(map[string]any{"type": "failed", "id": request.ID, "reason": FailNotAllowed})
					select {
					case local <- reply:
					case <-ctx.Done():
						return
					}
					continue
				}
				if stream.Send(request) != nil {
					return
				}
			}
		}
	})
	workers.Wait()
}

// acceptChunk takes upload bytes only for an accepted upload, never more
// than it announced. After an upload failed, the bytes the page had already
// sent are dropped, up to what it announced.
func acceptChunk(op *fileOperation, data []byte) (forward, ok bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	size := uint64(len(data))
	if size == 0 || size > FileChunk {
		return false, false
	}
	if op.id == 0 {
		if size > op.discard {
			return false, false
		}
		op.discard -= size
		return false, true
	}
	if !op.accepted || (op.op != OpPut && op.op != OpReplace) || size > op.left {
		return false, false
	}
	op.left -= size
	return true, true
}

// forwardReply checks a worker reply against the operation in flight and
// passes it to the page. A reply that does not fit ends the session.
func forwardReply(ctx, socket context.Context, conn *websocket.Conn, op *fileOperation, window *flow, reply FileReply, send func(any) bool, record func(FileRequest, FileFailure, uint64) bool, wait time.Duration) bool {
	op.mu.Lock()
	id, kind, accepted := op.id, op.op, op.accepted
	op.mu.Unlock()
	// Data belongs to the operation in flight; everything else names it.
	if id == 0 || (reply.Kind != ReplyData && reply.ID != id) || (reply.Kind == ReplyData && reply.ID != 0) {
		return false
	}
	switch reply.Kind {
	case ReplyEntries:
		if kind != OpList || len(reply.Entries) == 0 {
			return false
		}
		entries := make([]wireEntry, len(reply.Entries))
		for i, entry := range reply.Entries {
			entries[i] = pageEntry(entry)
		}
		return send(map[string]any{"type": "entries", "id": id, "entries": entries})
	case ReplyAccept:
		if accepted || (kind != OpGet && kind != OpPut && kind != OpReplace) || reply.Size > MaxFileSize {
			return false
		}
		op.mu.Lock()
		op.accepted = true
		op.mu.Unlock()
		if kind == OpGet {
			return send(map[string]any{"type": "file", "id": id, "size": reply.Size})
		}
		return send(map[string]any{"type": "accept", "id": id})
	case ReplyData:
		op.mu.Lock()
		op.received += uint64(len(reply.Data))
		over := op.received > MaxFileSize
		op.mu.Unlock()
		if kind != OpGet || !accepted || len(reply.Data) == 0 || len(reply.Data) > FileChunk || over {
			return false
		}
		sequence, ok := reserveCredit(ctx, window, wait)
		if !ok {
			return false
		}
		frame := make([]byte, 4+len(reply.Data))
		binary.BigEndian.PutUint32(frame, sequence)
		copy(frame[4:], reply.Data)
		return conn.Write(socket, websocket.MessageBinary, frame) == nil
	case ReplyDone:
		if reply.Path != "" && (kind != OpList || !ValidFilePath(reply.Path)) {
			return false
		}
		message := map[string]any{"type": "done", "id": id}
		if kind == OpList {
			if reply.Path == "" {
				return false
			}
			message["path"] = reply.Path
		}
		if kind == OpGet || kind == OpPut || kind == OpReplace {
			message["size"] = reply.Size
		}
		request, ok := op.finish(id)
		return ok && record(request, "", reply.Size) && send(message)
	case ReplyFailed:
		if !ValidFailure(reply.Failure) {
			return false
		}
		op.mu.Lock()
		if op.accepted && (op.op == OpPut || op.op == OpReplace) {
			op.discard = op.left
		}
		op.mu.Unlock()
		request, ok := op.finish(id)
		return ok && record(request, reply.Failure, 0) && send(map[string]any{"type": "failed", "id": id, "reason": reply.Failure})
	}
	return false
}

// reserveCredit waits for room in the download window, as the terminal's
// output does, and gives up when the page stops acknowledging.
func reserveCredit(ctx context.Context, window *flow, wait time.Duration) (uint32, bool) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		if sequence, ok := window.reserve(); ok {
			return sequence, true
		}
		select {
		case <-ctx.Done():
			return 0, false
		case <-timer.C:
			return 0, false
		case <-window.credit:
		}
	}
}
