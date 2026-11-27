// Package sftpclient is a small SFTP version 3 client
// (draft-ietf-secsh-filexfer-02) for the sandboxed SSH worker. It speaks
// over one already authenticated session channel and keeps memory and work
// bounded whatever the server sends.
//
// Only these requests are ever sent: INIT, OPEN, CLOSE, READ, WRITE, LSTAT,
// FSTAT, OPENDIR, READDIR, REMOVE, MKDIR, RMDIR, REALPATH, STAT and RENAME.
// Attributes are never changed, links are never read or made, and no
// extension is used, even when the server offers one.
//
// Every length from the server is checked before memory is set aside:
//   - a packet is 5 to MaxPacket bytes;
//   - VERSION must say 3 and carries at most 32 extensions of at most
//     1024 bytes per string, which are read and ignored;
//   - a handle is 1 to 256 bytes, a resolved path or a long name at most
//     4096 bytes, and a NAME reply holds at most 1024 entries;
//   - a listed name longer than 255 bytes is skipped, as are "." and "..";
//   - a DATA reply never carries more than its READ asked for;
//   - attributes carry only the flags version 3 defines.
//
// Anything else is a protocol error. Replies can then no longer be matched
// to requests, so the Client refuses every later call with ErrProtocol and
// the session has to end. Transfers keep at most 8 READ or 8 WRITE requests
// of ChunkSize bytes in flight.
//
// Paths sent to the server must be absolute, valid UTF-8, without NUL and
// at most 4096 bytes, so nothing depends on the server's working folder.
// The one exception is RealPath("."), which finds the account's home.
package sftpclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"
)

// MaxPacket is the largest packet accepted from the server: 256 KiB of
// payload plus room for headers.
const MaxPacket = 262144 + 1024

// ChunkSize is the most file data one READ asks for or one WRITE carries.
const ChunkSize = 32768

const (
	maxInFlight  = 8
	maxPath      = 4096
	maxName      = 255
	maxHandle    = 256
	maxNames     = 1024
	maxExtPairs  = 32
	maxExtString = 1024
)

const (
	typeInit     = 1
	typeVersion  = 2
	typeOpen     = 3
	typeClose    = 4
	typeRead     = 5
	typeWrite    = 6
	typeLstat    = 7
	typeFstat    = 8
	typeOpendir  = 11
	typeReaddir  = 12
	typeRemove   = 13
	typeMkdir    = 14
	typeRmdir    = 15
	typeRealpath = 16
	typeStat     = 17
	typeRename   = 18
	typeStatus   = 101
	typeHandle   = 102
	typeData     = 103
	typeName     = 104
	typeAttrs    = 105
)

const (
	attrSize      = 0x00000001
	attrUIDGID    = 0x00000002
	attrPerms     = 0x00000004
	attrACModTime = 0x00000008
	attrExtended  = 0x80000000
	attrKnown     = attrSize | attrUIDGID | attrPerms | attrACModTime | attrExtended
)

const (
	openRead  = 0x01
	openWrite = 0x02
	openCreat = 0x08
	openExcl  = 0x20
)

var (
	// ErrProtocol means the server broke the protocol or the stream failed.
	// The session must end: every later call returns ErrProtocol.
	ErrProtocol = errors.New("sftp: protocol error")
	// ErrTooMany means a listing went past its entry limit.
	ErrTooMany = errors.New("sftp: too many entries")
	// ErrTooLarge means a transfer went past its size limit.
	ErrTooLarge = errors.New("sftp: file too large")
	// ErrPath means a path was refused before anything was sent.
	ErrPath = errors.New("sftp: invalid path")

	errBusy  = errors.New("sftp: client already in use")
	errChunk = errors.New("sftp: upload chunk empty, over ChunkSize or past the declared size")
	errSize  = errors.New("sftp: negative size")
	errState = errors.New("sftp: transfer lost track of its chunks")
)

// Status codes a server may answer with.
const (
	statusOK               uint32 = 0
	StatusEOF              uint32 = 1
	StatusNoSuchFile       uint32 = 2
	StatusPermissionDenied uint32 = 3
	StatusFailure          uint32 = 4
	StatusBadMessage       uint32 = 5
	StatusNoConnection     uint32 = 6
	StatusConnectionLost   uint32 = 7
	StatusOpUnsupported    uint32 = 8
)

// StatusError is a server STATUS reply other than OK (and other than EOF
// where EOF is expected). The server's message text is never kept.
type StatusError struct{ Code uint32 }

func (e *StatusError) Error() string {
	switch e.Code {
	case StatusEOF:
		return "sftp: end of file"
	case StatusNoSuchFile:
		return "sftp: no such file"
	case StatusPermissionDenied:
		return "sftp: permission denied"
	case StatusFailure:
		return "sftp: failure"
	case StatusBadMessage:
		return "sftp: bad message"
	case StatusNoConnection:
		return "sftp: no connection"
	case StatusConnectionLost:
		return "sftp: connection lost"
	case StatusOpUnsupported:
		return "sftp: operation unsupported"
	}
	return fmt.Sprintf("sftp: server status %d", e.Code)
}

// Kind is the type of a file, from the S_IFMT bits of its permissions.
type Kind uint8

const (
	KindOther Kind = iota
	KindFile
	KindDir
	KindLink
)

// Attr is the part of a file's attributes Keybash uses.
type Attr struct {
	Kind    Kind   // KindOther when the server sent no permissions
	Size    uint64 // 0 when absent
	ModTime uint32 // 0 when absent
	HasSize bool
}

// Entry is one listed name. Name is a copy the caller may keep; it holds the
// server's bytes unchanged and may not be valid UTF-8.
type Entry struct {
	Name []byte
	Attr Attr // lstat-like, as READDIR returns
}

// Client is an SFTP session over one stream. It is not safe for concurrent
// use; a call made from inside a callback of another call is refused.
type Client struct {
	rw     io.ReadWriter
	lastID uint32
	broken bool
	busy   bool
	hdr    [4]byte
	handle [maxHandle]byte
	rbuf   []byte // reused for every reply, at most MaxPacket bytes
	wbuf   []byte // reused for every request
}

// New sends INIT and reads VERSION. rw has no deadlines of its own, so a
// read that never completes ends only when the caller closes rw; the caller
// closes it when ctx ends.
func New(ctx context.Context, rw io.ReadWriter) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &Client{rw: rw}
	c.wbuf = append(c.wbuf, 0, 0, 0, 5, typeInit, 0, 0, 0, 3)
	if _, err := rw.Write(c.wbuf); err != nil {
		return nil, ctxErr(ctx, c.ioFail(err))
	}
	typ, body, err := c.readPacket()
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if typ != typeVersion {
		return nil, c.fail("expected VERSION")
	}
	r := reader{b: body}
	if v := r.u32(); r.bad || v != 3 {
		return nil, c.fail("server version is not 3")
	}
	// Extensions are read only to check their bounds; none is ever used.
	for pairs := 0; len(r.b) > 0; pairs++ {
		if pairs == maxExtPairs {
			return nil, c.fail("too many extensions")
		}
		r.str(maxExtString)
		r.str(maxExtString)
		if r.bad {
			return nil, c.fail("malformed extension")
		}
	}
	return c, nil
}

// RealPath asks the server for the absolute form of path. "." is accepted
// here, and only here, to find the account's home folder.
func (c *Client) RealPath(path string) (string, error) {
	if path != "." {
		if err := checkPath(path); err != nil {
			return "", err
		}
	}
	if err := c.enter(); err != nil {
		return "", err
	}
	defer c.leave()
	id := c.begin(typeRealpath)
	c.putString(path)
	typ, body, err := c.call(id)
	if err != nil {
		return "", err
	}
	switch typ {
	case typeStatus:
		return "", c.statusFailure(body)
	case typeName:
	default:
		return "", c.fail("unexpected reply to REALPATH")
	}
	r := reader{b: body}
	if n := r.u32(); r.bad || n != 1 {
		return "", c.fail("REALPATH must name exactly one path")
	}
	name := r.str(maxPath)
	r.str(maxPath)
	r.attrs()
	if r.bad || len(r.b) != 0 || len(name) == 0 || name[0] != '/' || !utf8.Valid(name) || bytes.IndexByte(name, 0) >= 0 {
		return "", c.fail("malformed REALPATH reply")
	}
	return string(name), nil
}

// Stat returns the attributes of path, following a final link.
func (c *Client) Stat(path string) (Attr, error) { return c.stat(typeStat, path) }

// Lstat returns the attributes of path itself, without following a link.
func (c *Client) Lstat(path string) (Attr, error) { return c.stat(typeLstat, path) }

func (c *Client) stat(typ byte, path string) (Attr, error) {
	if err := checkPath(path); err != nil {
		return Attr{}, err
	}
	if err := c.enter(); err != nil {
		return Attr{}, err
	}
	defer c.leave()
	id := c.begin(typ)
	c.putString(path)
	rt, body, err := c.call(id)
	if err != nil {
		return Attr{}, err
	}
	return c.attrsReply(rt, body)
}

// List calls each for every entry of the folder at path, except "." and
// "..", in the server's order. More than maxEntries entries end the listing
// with ErrTooMany. Names that cannot be one path element (empty, over 255
// bytes, or holding '/' or NUL) are skipped and not counted. So that a
// server cannot keep a listing going forever, more than maxEntries+2
// skipped names (or empty replies) also end it with ErrTooMany. An error
// from each ends the listing and is returned. The folder handle is closed
// on every path where the stream is still sound.
func (c *Client) List(path string, maxEntries int, each func(Entry) error) error {
	if err := checkPath(path); err != nil {
		return err
	}
	if err := c.enter(); err != nil {
		return err
	}
	defer c.leave()
	id := c.begin(typeOpendir)
	c.putString(path)
	h, err := c.openReply(id)
	if err != nil {
		return err
	}
	err = c.list(h, max(maxEntries, 0), each)
	if !c.broken {
		if cerr := c.closeHandle(h); err == nil {
			err = cerr
		}
	}
	return err
}

func (c *Client) list(h []byte, maxEntries int, each func(Entry) error) error {
	kept, skipped := 0, 0
	tooManySkipped := func() bool { return skipped > 2 && skipped-2 > maxEntries }
	for {
		id := c.begin(typeReaddir)
		c.putBytes(h)
		typ, body, err := c.call(id)
		if err != nil {
			return err
		}
		switch typ {
		case typeStatus:
			code, err := c.statusOf(body)
			switch {
			case err != nil:
				return err
			case code == StatusEOF:
				return nil
			case code == statusOK:
				return c.fail("status OK where names were expected")
			}
			return &StatusError{Code: code}
		case typeName:
		default:
			return c.fail("unexpected reply to READDIR")
		}
		// The whole reply is checked before any entry of it is used.
		count, ok := checkNames(body)
		if !ok {
			return c.fail("malformed NAME reply")
		}
		if count == 0 {
			// An empty reply makes no progress; count it like a skipped name.
			if skipped++; tooManySkipped() {
				return ErrTooMany
			}
			continue
		}
		r := reader{b: body[4:]}
		for range count {
			name := r.str(len(r.b))
			r.str(maxPath)
			a := r.attrs()
			if !usableName(name) {
				if skipped++; tooManySkipped() {
					return ErrTooMany
				}
				continue
			}
			if kept == maxEntries {
				return ErrTooMany
			}
			kept++
			if err := each(Entry{Name: bytes.Clone(name), Attr: a}); err != nil {
				return err
			}
		}
	}
}

// Mkdir makes a folder. No attributes are sent, so the server's defaults
// and umask apply.
func (c *Client) Mkdir(path string) error {
	if err := checkPath(path); err != nil {
		return err
	}
	return c.simple(typeMkdir, path, "", true)
}

// Rmdir removes an empty folder.
func (c *Client) Rmdir(path string) error {
	if err := checkPath(path); err != nil {
		return err
	}
	return c.simple(typeRmdir, path, "", false)
}

// Remove removes a file or a link.
func (c *Client) Remove(path string) error {
	if err := checkPath(path); err != nil {
		return err
	}
	return c.simple(typeRemove, path, "", false)
}

// Rename moves from to to. Version 3 rename never replaces an existing name.
func (c *Client) Rename(from, to string) error {
	if err := checkPath(from); err != nil {
		return err
	}
	if err := checkPath(to); err != nil {
		return err
	}
	return c.simple(typeRename, from, to, false)
}

func (c *Client) simple(typ byte, path, to string, attrs bool) error {
	if err := c.enter(); err != nil {
		return err
	}
	defer c.leave()
	id := c.begin(typ)
	c.putString(path)
	if typ == typeRename {
		c.putString(to)
	}
	if attrs {
		c.putU32(0)
	}
	return c.statusCall(id)
}

func checkPath(p string) error {
	if len(p) == 0 || len(p) > maxPath || p[0] != '/' || !utf8.ValidString(p) || strings.IndexByte(p, 0) >= 0 {
		return ErrPath
	}
	return nil
}

func usableName(name []byte) bool {
	switch {
	case len(name) == 0 || len(name) > maxName:
		return false
	case string(name) == "." || string(name) == "..":
		return false
	}
	return bytes.IndexByte(name, '/') < 0 && bytes.IndexByte(name, 0) < 0
}

// checkNames reports the entry count of a NAME reply and whether the whole
// reply is well formed. It allocates nothing.
func checkNames(body []byte) (int, bool) {
	r := reader{b: body}
	n := r.u32()
	if r.bad || n > maxNames {
		return 0, false
	}
	for i := uint32(0); i < n && !r.bad; i++ {
		r.str(len(r.b))
		r.str(maxPath)
		r.attrs()
	}
	return int(n), !r.bad && len(r.b) == 0
}

func (c *Client) enter() error {
	if c.broken {
		return ErrProtocol
	}
	if c.busy {
		return errBusy
	}
	c.busy = true
	return nil
}

func (c *Client) leave() { c.busy = false }

func (c *Client) fail(reason string) error {
	c.broken = true
	return fmt.Errorf("%w: %s", ErrProtocol, reason)
}

func (c *Client) ioFail(err error) error {
	c.broken = true
	return fmt.Errorf("%w: %w", ErrProtocol, err)
}

// ctxErr prefers the context's error: when the context ends, the caller
// closes the stream, and the read error that follows is only a symptom.
func ctxErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return err
}

func (c *Client) begin(typ byte) uint32 {
	c.lastID++
	c.wbuf = append(c.wbuf[:0], 0, 0, 0, 0, typ)
	c.wbuf = binary.BigEndian.AppendUint32(c.wbuf, c.lastID)
	return c.lastID
}

func (c *Client) putU32(v uint32) { c.wbuf = binary.BigEndian.AppendUint32(c.wbuf, v) }

func (c *Client) putU64(v uint64) { c.wbuf = binary.BigEndian.AppendUint64(c.wbuf, v) }

func (c *Client) putString(s string) {
	c.putLen(len(s))
	c.wbuf = append(c.wbuf, s...)
}

func (c *Client) putBytes(b []byte) {
	c.putLen(len(b))
	c.wbuf = append(c.wbuf, b...)
}

// putLen writes a string length. Every string sent is a checked path, a
// handle or one chunk, so it is far below 4 GiB.
func (c *Client) putLen(n int) { c.putU32(u32(n)) }

// u32 converts a length this package has already bounded. A value out of
// range is a bug here, not something a server can cause.
func u32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic("sftpclient: length out of range")
	}
	return uint32(n)
}

func (c *Client) send() error {
	binary.BigEndian.PutUint32(c.wbuf, u32(len(c.wbuf)-4))
	if _, err := c.rw.Write(c.wbuf); err != nil {
		return c.ioFail(err)
	}
	return nil
}

// readPacket reads one packet into the reused buffer and returns its type
// and the bytes after it. The length is checked before the buffer grows.
func (c *Client) readPacket() (byte, []byte, error) {
	if _, err := io.ReadFull(c.rw, c.hdr[:]); err != nil {
		return 0, nil, c.ioFail(err)
	}
	n := binary.BigEndian.Uint32(c.hdr[:])
	if n < 5 || n > MaxPacket {
		return 0, nil, c.fail("packet length out of bounds")
	}
	if cap(c.rbuf) < int(n) {
		// Small replies share one modest buffer; it grows only for a reply
		// that needs it, and never past MaxPacket.
		c.rbuf = make([]byte, max(int(n), 4096))
	}
	b := c.rbuf[:n]
	if _, err := io.ReadFull(c.rw, b); err != nil {
		return 0, nil, c.ioFail(err)
	}
	return b[0], b[1:], nil
}

// reply reads one reply and splits off its id. Matching the id to a
// request in flight is the caller's job.
func (c *Client) reply() (byte, uint32, []byte, error) {
	typ, body, err := c.readPacket()
	if err != nil {
		return 0, 0, nil, err
	}
	if typ < typeStatus || typ > typeAttrs {
		return 0, 0, nil, c.fail("unexpected packet type")
	}
	// readPacket guarantees at least four bytes after the type.
	return typ, binary.BigEndian.Uint32(body), body[4:], nil
}

// call sends the request in wbuf and reads its reply. Only one request is
// in flight, so any other id is a reply to nothing.
func (c *Client) call(id uint32) (byte, []byte, error) {
	if err := c.send(); err != nil {
		return 0, nil, err
	}
	typ, rid, body, err := c.reply()
	if err != nil {
		return 0, nil, err
	}
	if rid != id {
		return 0, nil, c.fail("reply to a request not in flight")
	}
	return typ, body, nil
}

// statusCall is for requests answered by STATUS alone.
func (c *Client) statusCall(id uint32) error {
	typ, body, err := c.call(id)
	if err != nil {
		return err
	}
	if typ != typeStatus {
		return c.fail("expected STATUS")
	}
	code, err := c.statusOf(body)
	if err != nil {
		return err
	}
	if code != statusOK {
		return &StatusError{Code: code}
	}
	return nil
}

// statusOf parses a STATUS body. The message and language tag are checked
// for framing and dropped; a server that leaves both out is accepted.
func (c *Client) statusOf(body []byte) (uint32, error) {
	r := reader{b: body}
	code := r.u32()
	if len(r.b) > 0 {
		r.str(len(r.b))
		r.str(len(r.b))
	}
	if r.bad || len(r.b) != 0 {
		return 0, c.fail("malformed STATUS")
	}
	return code, nil
}

// statusFailure turns a STATUS that came instead of data into an error.
// OK there is a protocol error, since the request asked for data.
func (c *Client) statusFailure(body []byte) error {
	code, err := c.statusOf(body)
	if err != nil {
		return err
	}
	if code == statusOK {
		return c.fail("status OK where data was expected")
	}
	return &StatusError{Code: code}
}

func (c *Client) attrsReply(typ byte, body []byte) (Attr, error) {
	switch typ {
	case typeStatus:
		return Attr{}, c.statusFailure(body)
	case typeAttrs:
		r := reader{b: body}
		a := r.attrs()
		if r.bad || len(r.b) != 0 {
			return Attr{}, c.fail("malformed ATTRS")
		}
		return a, nil
	}
	return Attr{}, c.fail("expected ATTRS")
}

// openReply reads the reply to OPEN or OPENDIR. The handle is copied out of
// the read buffer, which the next reply overwrites.
func (c *Client) openReply(id uint32) ([]byte, error) {
	typ, body, err := c.call(id)
	if err != nil {
		return nil, err
	}
	switch typ {
	case typeStatus:
		return nil, c.statusFailure(body)
	case typeHandle:
		r := reader{b: body}
		h := r.str(maxHandle)
		if r.bad || len(r.b) != 0 || len(h) == 0 {
			return nil, c.fail("malformed HANDLE")
		}
		return c.handle[:copy(c.handle[:], h)], nil
	}
	return nil, c.fail("expected HANDLE")
}

func (c *Client) closeHandle(h []byte) error {
	id := c.begin(typeClose)
	c.putBytes(h)
	return c.statusCall(id)
}

// reader takes fields off a reply. After the first short or oversized field
// it stays bad and returns zero values, so callers check once at the end.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) u32() uint32 {
	if r.bad || len(r.b) < 4 {
		r.bad, r.b = true, nil
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) u64() uint64 {
	if r.bad || len(r.b) < 8 {
		r.bad, r.b = true, nil
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

// str returns a string of at most limit bytes, aliasing the reply.
func (r *reader) str(limit int) []byte {
	n := r.u32()
	if r.bad || int64(n) > int64(limit) || int64(n) > int64(len(r.b)) {
		r.bad, r.b = true, nil
		return nil
	}
	s := r.b[:n:n]
	r.b = r.b[n:]
	return s
}

func (r *reader) attrs() Attr {
	flags := r.u32()
	if flags&^attrKnown != 0 {
		r.bad, r.b = true, nil
	}
	var a Attr
	if flags&attrSize != 0 {
		a.Size = r.u64()
		a.HasSize = true
	}
	if flags&attrUIDGID != 0 {
		r.u32()
		r.u32()
	}
	if flags&attrPerms != 0 {
		a.Kind = kindOf(r.u32())
	}
	if flags&attrACModTime != 0 {
		r.u32()
		a.ModTime = r.u32()
	}
	if flags&attrExtended != 0 {
		n := r.u32()
		if n > maxExtPairs {
			r.bad, r.b = true, nil
		}
		for i := uint32(0); i < n && !r.bad; i++ {
			r.str(maxExtString)
			r.str(maxExtString)
		}
	}
	if r.bad {
		return Attr{}
	}
	return a
}

func kindOf(perm uint32) Kind {
	switch perm & 0o170000 {
	case 0o100000:
		return KindFile
	case 0o040000:
		return KindDir
	case 0o120000:
		return KindLink
	}
	return KindOther
}
