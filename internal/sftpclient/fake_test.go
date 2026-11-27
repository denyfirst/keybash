package sftpclient

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// allowedRequests is every request type the client may ever send after INIT.
var allowedRequests = map[byte]bool{
	typeOpen: true, typeClose: true, typeRead: true, typeWrite: true,
	typeLstat: true, typeFstat: true, typeOpendir: true, typeReaddir: true,
	typeRemove: true, typeMkdir: true, typeRmdir: true, typeRealpath: true,
	typeStat: true, typeRename: true,
}

// raw is packet bytes added without a length prefix.
type raw []byte

// pkt builds one packet from uint32, uint64, string, []byte (both with a
// length prefix) and raw fields.
func pkt(typ byte, fields ...any) []byte {
	b := []byte{0, 0, 0, 0, typ}
	for _, f := range fields {
		switch v := f.(type) {
		case uint32:
			b = binary.BigEndian.AppendUint32(b, v)
		case uint64:
			b = binary.BigEndian.AppendUint64(b, v)
		case string:
			b = binary.BigEndian.AppendUint32(b, u32(len(v)))
			b = append(b, v...)
		case []byte:
			b = binary.BigEndian.AppendUint32(b, u32(len(v)))
			b = append(b, v...)
		case raw:
			b = append(b, v...)
		default:
			panic(fmt.Sprintf("pkt: field of type %T", f))
		}
	}
	binary.BigEndian.PutUint32(b, u32(len(b)-4))
	return b
}

func status(id, code uint32) []byte { return pkt(typeStatus, id, code, "message", "en") }

// noAttrs is an ATTRS block with no flags.
var noAttrs = raw{0, 0, 0, 0}

type fakeNode struct {
	dir   bool
	link  string // target of a link
	mode  uint32 // overrides the type bits, for sockets and the like
	data  []byte
	mtime uint32
}

func (n *fakeNode) perm() uint32 {
	switch {
	case n.mode != 0:
		return n.mode
	case n.dir:
		return 0o040755
	case n.link != "":
		return 0o120777
	}
	return 0o100644
}

func attrsOf(n *fakeNode) raw {
	b := binary.BigEndian.AppendUint32(nil, attrSize|attrUIDGID|attrPerms|attrACModTime)
	b = binary.BigEndian.AppendUint64(b, uint64(len(n.data)))
	b = binary.BigEndian.AppendUint32(b, 1000)
	b = binary.BigEndian.AppendUint32(b, 1000)
	b = binary.BigEndian.AppendUint32(b, n.perm())
	b = binary.BigEndian.AppendUint32(b, 1700000000)
	b = binary.BigEndian.AppendUint32(b, n.mtime)
	return raw(b)
}

type fakeHandle struct {
	node    *fakeNode
	write   bool
	written uint64
	dir     bool
	names   []string
	nodes   []*fakeNode
	pos     int
}

// fakeReq is what a hook learns about a request: its type, its id and how
// many requests of that type came before it, plus one.
type fakeReq struct {
	typ byte
	id  uint32
	n   int
}

// fakeServer is an SFTP version 3 server over net.Pipe with an in-memory
// tree. It fails the test on any request type the client must never send
// and on malformed requests. Hooks replace, drop or add replies.
type fakeServer struct {
	t *testing.T

	// Settings, fixed before start.
	version    []byte        // whole packet sent instead of the usual VERSION
	short      bool          // answer READs with fewer bytes than asked, now and then
	hold       time.Duration // hold READ and WRITE replies until the client is quiet, then send them newest first
	batch      int           // names per READDIR reply
	handleName func(n int) string
	longname   func(name string) string
	hook       func(q fakeReq, replies [][]byte) [][]byte

	conn net.Conn // the client's end
	out  chan []byte
	wg   sync.WaitGroup

	mu        sync.Mutex
	inited    bool
	tree      map[string]*fakeNode
	handles   map[string]*fakeHandle
	opened    int
	requests  int
	seen      map[byte]int
	openFlags []uint32
	maxHeld   int
	shorts    int
}

func newFake(t *testing.T) *fakeServer {
	t.Helper()
	return &fakeServer{
		t:     t,
		batch: 64,
		tree: map[string]*fakeNode{
			"/":       {dir: true},
			"/home":   {dir: true},
			"/home/u": {dir: true},
		},
		handles: map[string]*fakeHandle{},
		seen:    map[byte]int{},
	}
}

// start connects a pipe and runs the server; the caller speaks on the
// returned end.
func (f *fakeServer) start() net.Conn {
	cli, srv := net.Pipe()
	f.conn = cli
	f.out = make(chan []byte, 1<<14)
	reqs := make(chan []byte, 16)
	f.wg.Add(3)
	go f.readLoop(srv, reqs)
	go f.serve(reqs)
	go f.writeLoop(srv)
	f.t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
		f.wg.Wait()
	})
	return cli
}

// client starts the server and completes INIT and VERSION.
func (f *fakeServer) client() *Client {
	f.t.Helper()
	conn := f.start()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := New(ctx, conn)
	if err != nil {
		f.t.Fatalf("New: %v", err)
	}
	return c
}

// ctx ends the session when it expires, as the worker closes its channel,
// so a stuck transfer fails the test instead of hanging it.
func (f *fakeServer) ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	stop := context.AfterFunc(ctx, func() { _ = f.conn.Close() })
	f.t.Cleanup(func() {
		stop()
		cancel()
	})
	return ctx
}

func (f *fakeServer) readLoop(conn net.Conn, reqs chan<- []byte) {
	defer f.wg.Done()
	defer close(reqs)
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		// The largest request is a WRITE of one chunk with a 256-byte handle.
		if n < 5 || n > 4+1+4+4+maxHandle+8+4+ChunkSize {
			f.t.Errorf("client sent a packet of %d bytes", n)
			_ = conn.Close()
			return
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(conn, p); err != nil {
			return
		}
		reqs <- p
	}
}

func (f *fakeServer) writeLoop(conn net.Conn) {
	defer f.wg.Done()
	for p := range f.out {
		if _, err := conn.Write(p); err != nil {
			for range f.out {
			}
			return
		}
	}
}

func (f *fakeServer) serve(reqs <-chan []byte) {
	defer f.wg.Done()
	defer close(f.out)
	var held [][]byte
	heldReqs := 0
	for {
		var p []byte
		ok := true
		if heldReqs > 0 {
			timer := time.NewTimer(f.hold)
			select {
			case p, ok = <-reqs:
				timer.Stop()
			case <-timer.C:
				for i := len(held) - 1; i >= 0; i-- {
					f.out <- held[i]
				}
				held, heldReqs = held[:0], 0
				continue
			}
		} else {
			p, ok = <-reqs
		}
		if !ok {
			return
		}
		typ, replies := f.handle(p)
		if f.hold > 0 && (typ == typeRead || typ == typeWrite) {
			held = append(held, replies...)
			heldReqs++
			f.mu.Lock()
			f.maxHeld = max(f.maxHeld, heldReqs)
			f.mu.Unlock()
			continue
		}
		for _, r := range replies {
			f.out <- r
		}
	}
}

func (f *fakeServer) handle(p []byte) (byte, [][]byte) {
	typ := p[0]
	f.mu.Lock()
	if typ == typeInit {
		r := reader{b: p[1:]}
		if v := r.u32(); f.inited || r.bad || v != 3 || len(r.b) != 0 {
			f.t.Errorf("bad INIT %x", p)
		}
		f.inited = true
		f.mu.Unlock()
		if f.version != nil {
			return typ, [][]byte{f.version}
		}
		// Extensions are offered so a test can see they are never used.
		return typ, [][]byte{pkt(typeVersion, uint32(3),
			"posix-rename@openssh.com", "1", "statvfs@openssh.com", "2", "hardlink@openssh.com", "1")}
	}
	if !f.inited || len(p) < 5 {
		f.t.Errorf("request %d before INIT or without an id", typ)
	}
	id := binary.BigEndian.Uint32(p[1:])
	f.requests++
	f.seen[typ]++
	q := fakeReq{typ: typ, id: id, n: f.seen[typ]}
	var reply []byte
	if !allowedRequests[typ] {
		f.t.Errorf("client sent forbidden request type %d", typ)
		reply = status(id, StatusOpUnsupported)
	} else {
		reply = f.do(typ, id, &reader{b: p[5:]})
	}
	f.mu.Unlock()
	replies := [][]byte{reply}
	if f.hook != nil {
		replies = f.hook(q, replies)
	}
	return typ, replies
}

// path reads a path argument and checks the client's own rules.
func (f *fakeServer) path(r *reader, dotOK bool) string {
	p := string(r.str(1 << 16))
	if r.bad {
		return ""
	}
	if (p != "." || !dotOK) && (len(p) == 0 || len(p) > maxPath || p[0] != '/' || !utf8.ValidString(p) || strings.IndexByte(p, 0) >= 0) {
		f.t.Errorf("client sent path %q", p)
	}
	return p
}

func (f *fakeServer) ended(r *reader) bool {
	if r.bad || len(r.b) != 0 {
		f.t.Errorf("malformed request")
		return false
	}
	return true
}

func parentOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func (f *fakeServer) parentIsDir(p string) bool {
	n := f.tree[parentOf(p)]
	return n != nil && n.dir
}

func (f *fakeServer) children(dir string) []string {
	var out []string
	for k := range f.tree {
		if k != "/" && parentOf(k) == dir {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (f *fakeServer) newHandle(id uint32, h *fakeHandle) []byte {
	f.opened++
	name := fmt.Sprintf("h%d", f.opened)
	if f.handleName != nil {
		name = f.handleName(f.opened)
	}
	f.handles[name] = h
	return pkt(typeHandle, id, name)
}

func (f *fakeServer) long(name string) string {
	if f.longname != nil {
		return f.longname(name)
	}
	return "-rw-r--r--    1 u        u               0 Jan  1 00:00 " + name
}

func (f *fakeServer) do(typ byte, id uint32, r *reader) []byte {
	switch typ {
	case typeRealpath:
		p := f.path(r, true)
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		if p == "." {
			p = "/home/u"
		}
		return pkt(typeName, id, uint32(1), p, "", noAttrs)

	case typeStat, typeLstat:
		p := f.path(r, false)
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		n := f.tree[p]
		if n != nil && typ == typeStat && n.link != "" {
			n = f.tree[n.link]
		}
		if n == nil {
			return status(id, StatusNoSuchFile)
		}
		return pkt(typeAttrs, id, attrsOf(n))

	case typeOpen:
		p := f.path(r, false)
		flags := r.u32()
		if attrFlags := r.u32(); attrFlags != 0 {
			f.t.Errorf("OPEN sent attributes %#x", attrFlags)
		}
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		f.openFlags = append(f.openFlags, flags)
		n := f.tree[p]
		switch flags {
		case openRead:
			if n == nil {
				return status(id, StatusNoSuchFile)
			}
			if n.dir {
				return status(id, StatusFailure)
			}
			return f.newHandle(id, &fakeHandle{node: n})
		case openWrite | openCreat | openExcl:
			if n != nil {
				return status(id, StatusFailure)
			}
			if !f.parentIsDir(p) {
				return status(id, StatusNoSuchFile)
			}
			n = &fakeNode{}
			f.tree[p] = n
			return f.newHandle(id, &fakeHandle{node: n, write: true})
		}
		f.t.Errorf("OPEN with flags %#x", flags)
		return status(id, StatusOpUnsupported)

	case typeClose:
		h := string(r.str(1 << 16))
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		if f.handles[h] == nil {
			f.t.Errorf("CLOSE of unknown handle %q", h)
			return status(id, StatusFailure)
		}
		delete(f.handles, h)
		return status(id, statusOK)

	case typeRead:
		h := f.handles[string(r.str(1<<16))]
		off := r.u64()
		n := r.u32()
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		if n == 0 || n > ChunkSize {
			f.t.Errorf("READ of %d bytes", n)
		}
		if h == nil || h.dir || h.write {
			f.t.Errorf("READ on a handle not open for reading")
			return status(id, StatusFailure)
		}
		data := h.node.data
		if off >= uint64(len(data)) {
			return status(id, StatusEOF)
		}
		chunk := data[off:min(off+uint64(n), uint64(len(data)))]
		if f.short && len(chunk) > 1 && f.seen[typeRead]%3 != 0 {
			chunk = chunk[:1+(f.seen[typeRead]*7919)%(len(chunk)-1)]
			f.shorts++
		}
		return pkt(typeData, id, chunk)

	case typeWrite:
		h := f.handles[string(r.str(1<<16))]
		off := r.u64()
		data := r.str(1 << 20)
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		if len(data) == 0 || len(data) > ChunkSize {
			f.t.Errorf("WRITE of %d bytes", len(data))
		}
		if h == nil || !h.write {
			f.t.Errorf("WRITE on a handle not open for writing")
			return status(id, StatusFailure)
		}
		// The client sends WRITEs in file order, so each starts where the
		// last ended: no gap and no overlap.
		if off != h.written {
			f.t.Errorf("WRITE at %d, want %d", off, h.written)
			return status(id, StatusFailure)
		}
		h.node.data = append(h.node.data, data...)
		h.written += uint64(len(data))
		return status(id, statusOK)

	case typeFstat:
		h := f.handles[string(r.str(1<<16))]
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		if h == nil {
			f.t.Errorf("FSTAT of unknown handle")
			return status(id, StatusFailure)
		}
		return pkt(typeAttrs, id, attrsOf(h.node))

	case typeOpendir:
		p := f.path(r, false)
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		n := f.tree[p]
		if n == nil {
			return status(id, StatusNoSuchFile)
		}
		if !n.dir {
			return status(id, StatusFailure)
		}
		h := &fakeHandle{dir: true, names: []string{".", ".."}, nodes: []*fakeNode{n, n}}
		for _, k := range f.children(p) {
			h.names = append(h.names, k[strings.LastIndexByte(k, '/')+1:])
			h.nodes = append(h.nodes, f.tree[k])
		}
		return f.newHandle(id, h)

	case typeReaddir:
		h := f.handles[string(r.str(1<<16))]
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		if h == nil || !h.dir {
			f.t.Errorf("READDIR on a handle not open as a folder")
			return status(id, StatusFailure)
		}
		if h.pos >= len(h.names) {
			return status(id, StatusEOF)
		}
		end := min(h.pos+f.batch, len(h.names))
		fields := []any{id, u32(end - h.pos)}
		for i := h.pos; i < end; i++ {
			fields = append(fields, h.names[i], f.long(h.names[i]), attrsOf(h.nodes[i]))
		}
		h.pos = end
		return pkt(typeName, fields...)

	case typeRemove:
		p := f.path(r, false)
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		n := f.tree[p]
		switch {
		case n == nil:
			return status(id, StatusNoSuchFile)
		case n.dir:
			return status(id, StatusFailure)
		}
		delete(f.tree, p)
		return status(id, statusOK)

	case typeMkdir:
		p := f.path(r, false)
		if attrFlags := r.u32(); attrFlags != 0 {
			f.t.Errorf("MKDIR sent attributes %#x", attrFlags)
		}
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		switch {
		case f.tree[p] != nil:
			return status(id, StatusFailure)
		case !f.parentIsDir(p):
			return status(id, StatusNoSuchFile)
		}
		f.tree[p] = &fakeNode{dir: true}
		return status(id, statusOK)

	case typeRmdir:
		p := f.path(r, false)
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		n := f.tree[p]
		switch {
		case n == nil:
			return status(id, StatusNoSuchFile)
		case !n.dir || len(f.children(p)) > 0:
			return status(id, StatusFailure)
		}
		delete(f.tree, p)
		return status(id, statusOK)

	case typeRename:
		from := f.path(r, false)
		to := f.path(r, false)
		if !f.ended(r) {
			return status(id, StatusBadMessage)
		}
		switch {
		case f.tree[from] == nil:
			return status(id, StatusNoSuchFile)
		case f.tree[to] != nil:
			return status(id, StatusFailure)
		case !f.parentIsDir(to):
			return status(id, StatusNoSuchFile)
		}
		for k, n := range f.tree {
			if k == from || strings.HasPrefix(k, from+"/") {
				delete(f.tree, k)
				f.tree[to+k[len(from):]] = n
			}
		}
		return status(id, statusOK)
	}
	f.t.Errorf("unhandled request type %d", typ)
	return status(id, StatusOpUnsupported)
}

// Accessors for tests; each takes the lock the server holds while serving.

func (f *fakeServer) put(p string, n *fakeNode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tree[p] = n
}

func (f *fakeServer) file(p string, data []byte) { f.put(p, &fakeNode{data: data, mtime: 1234}) }

func (f *fakeServer) content(p string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.tree[p]
	if n == nil {
		return nil, false
	}
	return append([]byte(nil), n.data...), true
}

func (f *fakeServer) openHandles() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.handles)
}

func (f *fakeServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *fakeServer) seenType(typ byte) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[typ]
}

func (f *fakeServer) flags() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint32(nil), f.openFlags...)
}

func (f *fakeServer) held() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxHeld
}

func (f *fakeServer) shortReplies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.shorts
}
