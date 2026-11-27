package sftpclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// pattern is file content in which a gap or a repeated range shows.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i) ^ byte(i>>8)*7 ^ byte(i>>16)*13
	}
	return b
}

// chunker hands out data in pieces of the given sizes, in turn, from one
// reused buffer, so a client that kept a chunk past the next call would
// send damaged data.
func chunker(data []byte, sizes ...int) func() ([]byte, error) {
	if len(sizes) == 0 {
		sizes = []int{ChunkSize}
	}
	buf := make([]byte, ChunkSize)
	k := 0
	return func() ([]byte, error) {
		if len(data) == 0 {
			return nil, io.EOF
		}
		n := min(sizes[k%len(sizes)], len(data))
		k++
		for i := range buf {
			buf[i] = 0xAA
		}
		copy(buf, data[:n])
		data = data[n:]
		return buf[:n], nil
	}
}

type fetched struct {
	data    []byte
	size    int64
	starts  int
	n       int64
	err     error
	maxSeen int
}

func fetch(t *testing.T, ctx context.Context, c *Client, path string, limit int64) fetched {
	t.Helper()
	g := fetched{size: -1}
	g.n, g.err = c.Download(ctx, path, limit, func(size int64) error {
		g.starts++
		g.size = size
		return nil
	}, func(p []byte) error {
		if g.starts != 1 {
			t.Errorf("write before start")
		}
		if len(p) == 0 || len(p) > ChunkSize {
			t.Errorf("write of %d bytes", len(p))
		}
		g.maxSeen = max(g.maxSeen, len(p))
		g.data = append(g.data, p...)
		return nil
	})
	return g
}

func listAll(c *Client, path string, maxEntries int) ([]Entry, error) {
	var out []Entry
	err := c.List(path, maxEntries, func(e Entry) error {
		out = append(out, e)
		return nil
	})
	return out, err
}

func isStatus(err error, code uint32) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

func TestRoundTripSizes(t *testing.T) {
	f := newFake(t)
	c := f.client()
	ctx := f.ctx()
	sizes := []int{0, 1, 32767, 32768, 32769, 8*32768 + 5, 3<<20 + 7}
	for _, size := range sizes {
		data := pattern(size)
		p := fmt.Sprintf("/srv/u/f%d", size)
		if err := c.Upload(ctx, p, int64(size), int64(size), chunker(data)); err != nil {
			t.Fatalf("upload %d: %v", size, err)
		}
		if stored, _ := f.content(p); !bytes.Equal(stored, data) {
			t.Fatalf("upload %d stored %d different bytes", size, len(stored))
		}
		g := fetch(t, ctx, c, p, int64(size))
		if g.err != nil || g.n != int64(size) || g.size != int64(size) || g.starts != 1 || !bytes.Equal(g.data, data) {
			t.Fatalf("download %d: n=%d size=%d starts=%d equal=%v err=%v", size, g.n, g.size, g.starts, bytes.Equal(g.data, data), g.err)
		}
	}
	if n := f.openHandles(); n != 0 {
		t.Fatalf("%d handles left open", n)
	}
	exclusive := 0
	for _, fl := range f.flags() {
		switch fl {
		case openWrite | openCreat | openExcl:
			exclusive++
		case openRead:
		default:
			t.Fatalf("OPEN with flags %#x", fl)
		}
	}
	if exclusive != len(sizes) {
		t.Fatalf("%d exclusive opens for %d uploads", exclusive, len(sizes))
	}
}

func TestUploadUnevenChunks(t *testing.T) {
	f := newFake(t)
	c := f.client()
	data := pattern(200_000)
	if err := c.Upload(f.ctx(), "/srv/u/u", int64(len(data)), 1<<20, chunker(data, 1, 1000, ChunkSize, 7, 32767)); err != nil {
		t.Fatal(err)
	}
	if stored, _ := f.content("/srv/u/u"); !bytes.Equal(stored, data) {
		t.Fatal("uneven chunks stored different bytes")
	}
}

func TestShortAndReorderedReplies(t *testing.T) {
	for _, mode := range []struct {
		name  string
		short bool
		hold  time.Duration
	}{
		{"short", true, 0},
		{"reordered", false, 5 * time.Millisecond},
		{"short-reordered", true, 5 * time.Millisecond},
	} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFake(t)
			f.short, f.hold = mode.short, mode.hold
			c := f.client()
			ctx := f.ctx()
			for _, size := range []int{1, 32769, 8*32768 + 5, 1<<20 + 3} {
				data := pattern(size)
				p := fmt.Sprintf("/srv/u/s%d", size)
				f.file(p, data)
				g := fetch(t, ctx, c, p, 1<<30)
				if g.err != nil || g.n != int64(size) || !bytes.Equal(g.data, data) {
					t.Fatalf("download %d: n=%d equal=%v err=%v", size, g.n, bytes.Equal(g.data, data), g.err)
				}
				up := p + ".up"
				if err := c.Upload(ctx, up, int64(size), int64(size), chunker(data)); err != nil {
					t.Fatalf("upload %d: %v", size, err)
				}
				if stored, _ := f.content(up); !bytes.Equal(stored, data) {
					t.Fatalf("upload %d stored different bytes", size)
				}
			}
			if mode.short && f.shortReplies() == 0 {
				t.Fatal("the server sent no short DATA")
			}
			if n := f.openHandles(); n != 0 {
				t.Fatalf("%d handles left open", n)
			}
		})
	}
}

// TestInFlightBound holds every READ and WRITE reply until the client goes
// quiet, so the server sees exactly how many requests the client risks
// without an answer. The bound is written out, not taken from the package.
func TestInFlightBound(t *testing.T) {
	const wantInFlight = 8
	data := pattern(1 << 20)
	t.Run("download", func(t *testing.T) {
		f := newFake(t)
		f.hold = 100 * time.Millisecond
		f.file("/srv/u/big", data)
		c := f.client()
		g := fetch(t, f.ctx(), c, "/srv/u/big", 1<<30)
		if g.err != nil || !bytes.Equal(g.data, data) {
			t.Fatalf("download: %v", g.err)
		}
		if h := f.held(); h != wantInFlight {
			t.Fatalf("%d READs in flight; want %d", h, wantInFlight)
		}
	})
	t.Run("upload", func(t *testing.T) {
		f := newFake(t)
		f.hold = 100 * time.Millisecond
		c := f.client()
		if err := c.Upload(f.ctx(), "/srv/u/big", int64(len(data)), 1<<30, chunker(data)); err != nil {
			t.Fatal(err)
		}
		if h := f.held(); h != wantInFlight {
			t.Fatalf("%d WRITEs in flight; want %d", h, wantInFlight)
		}
	})
}

func TestDownloadLimit(t *testing.T) {
	data := pattern(100_000)
	noSize := func(q fakeReq, r [][]byte) [][]byte {
		if q.typ == typeFstat {
			return [][]byte{pkt(typeAttrs, q.id, noAttrs)}
		}
		return r
	}

	t.Run("exact", func(t *testing.T) {
		f := newFake(t)
		f.file("/f", data)
		c := f.client()
		if g := fetch(t, f.ctx(), c, "/f", int64(len(data))); g.err != nil || !bytes.Equal(g.data, data) {
			t.Fatalf("download at the limit: %v", g.err)
		}
	})

	t.Run("fstat-over", func(t *testing.T) {
		f := newFake(t)
		f.file("/f", data)
		c := f.client()
		g := fetch(t, f.ctx(), c, "/f", int64(len(data)-1))
		if !errors.Is(g.err, ErrTooLarge) || g.starts != 0 || g.n != 0 {
			t.Fatalf("err=%v starts=%d n=%d", g.err, g.starts, g.n)
		}
		if f.seenType(typeRead) != 0 || f.openHandles() != 0 {
			t.Fatal("READ sent or handle left open after the size check")
		}
	})

	t.Run("stream-over", func(t *testing.T) {
		f := newFake(t)
		f.hook = noSize
		f.file("/f", data)
		c := f.client()
		const limit = 50_000
		g := fetch(t, f.ctx(), c, "/f", limit)
		if !errors.Is(g.err, ErrTooLarge) || g.size != 0 || g.n > limit || g.n != int64(len(g.data)) || !bytes.Equal(g.data, data[:g.n]) {
			t.Fatalf("err=%v size=%d n=%d written=%d", g.err, g.size, g.n, len(g.data))
		}
		if f.openHandles() != 0 {
			t.Fatal("handle left open")
		}
		if _, err := c.Stat("/f"); err != nil {
			t.Fatalf("session not usable after ErrTooLarge: %v", err)
		}
	})

	t.Run("fstat-lies", func(t *testing.T) {
		f := newFake(t)
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeFstat {
				a := binary.BigEndian.AppendUint32(nil, attrSize)
				return [][]byte{pkt(typeAttrs, q.id, raw(binary.BigEndian.AppendUint64(a, 10)))}
			}
			return r
		}
		f.file("/f", data)
		c := f.client()
		// The first READ asks for 11 bytes; the whole reply is refused.
		g := fetch(t, f.ctx(), c, "/f", 10)
		if !errors.Is(g.err, ErrTooLarge) || g.size != 10 || g.n != 0 {
			t.Fatalf("err=%v size=%d n=%d", g.err, g.size, g.n)
		}
	})

	t.Run("zero", func(t *testing.T) {
		f := newFake(t)
		f.hook = noSize
		f.file("/empty", nil)
		f.file("/one", []byte{1})
		c := f.client()
		if g := fetch(t, f.ctx(), c, "/empty", 0); g.err != nil || g.n != 0 {
			t.Fatalf("empty file at limit 0: %v", g.err)
		}
		if g := fetch(t, f.ctx(), c, "/one", 0); !errors.Is(g.err, ErrTooLarge) || g.n != 0 {
			t.Fatalf("one byte at limit 0: n=%d err=%v", g.n, g.err)
		}
		if g := fetch(t, f.ctx(), c, "/one", -1); !errors.Is(g.err, ErrTooLarge) {
			t.Fatalf("negative limit: %v", g.err)
		}
	})
}

func TestDownloadCallbackErrors(t *testing.T) {
	f := newFake(t)
	data := pattern(5 * ChunkSize)
	f.file("/f", data)
	c := f.client()
	ctx := f.ctx()
	boom := errors.New("boom")

	_, err := c.Download(ctx, "/f", 1<<30, func(int64) error { return boom }, func([]byte) error { return nil })
	if !errors.Is(err, boom) || f.seenType(typeRead) != 0 || f.openHandles() != 0 {
		t.Fatalf("start error: %v, reads %d", err, f.seenType(typeRead))
	}

	writes := 0
	n, err := c.Download(ctx, "/f", 1<<30, func(int64) error { return nil }, func(p []byte) error {
		if writes++; writes == 2 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) || n != ChunkSize || writes != 2 || f.openHandles() != 0 {
		t.Fatalf("write error: err=%v n=%d writes=%d", err, n, writes)
	}

	if _, err := c.Download(ctx, "/missing", 1, func(int64) error { return nil }, func([]byte) error { return nil }); !isStatus(err, StatusNoSuchFile) {
		t.Fatalf("missing file: %v", err)
	}
	if g := fetch(t, ctx, c, "/f", 1<<30); g.err != nil || !bytes.Equal(g.data, data) {
		t.Fatalf("session not usable after callback errors: %v", g.err)
	}
}

func TestDownloadReadFailure(t *testing.T) {
	f := newFake(t)
	f.hook = func(q fakeReq, r [][]byte) [][]byte {
		if q.typ == typeRead && q.n == 3 {
			return [][]byte{status(q.id, StatusPermissionDenied)}
		}
		return r
	}
	f.file("/f", pattern(10*ChunkSize))
	c := f.client()
	g := fetch(t, f.ctx(), c, "/f", 1<<30)
	if !isStatus(g.err, StatusPermissionDenied) || g.n != 2*ChunkSize || f.openHandles() != 0 {
		t.Fatalf("err=%v n=%d", g.err, g.n)
	}
	if _, err := c.Stat("/f"); err != nil {
		t.Fatalf("session not usable after a READ failure: %v", err)
	}
}

func TestUploadLimitAndExclusive(t *testing.T) {
	f := newFake(t)
	f.file("/srv/u/exists", []byte("keep"))
	c := f.client()
	ctx := f.ctx()
	never := func() ([]byte, error) {
		t.Error("next called")
		return nil, io.EOF
	}

	if err := c.Upload(ctx, "/srv/u/x", 11, 10, never); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size over limit: %v", err)
	}
	if err := c.Upload(ctx, "/srv/u/x", -1, 10, never); err == nil {
		t.Fatal("negative size accepted")
	}
	if f.count() != 0 {
		t.Fatal("refused uploads sent requests")
	}
	if err := c.Upload(ctx, "/srv/u/x", 10, 10, chunker(pattern(10))); err != nil {
		t.Fatalf("size at limit: %v", err)
	}

	err := c.Upload(ctx, "/srv/u/exists", 3, 10, never)
	if !isStatus(err, StatusFailure) {
		t.Fatalf("exclusive create over an existing file: %v", err)
	}
	if stored, _ := f.content("/srv/u/exists"); string(stored) != "keep" {
		t.Fatal("existing file changed")
	}
	for _, fl := range f.flags() {
		if fl != openWrite|openCreat|openExcl {
			t.Fatalf("upload OPEN flags %#x", fl)
		}
	}
	if err := c.Upload(ctx, "/srv/u/nodir/x", 1, 10, never); !isStatus(err, StatusNoSuchFile) {
		t.Fatalf("missing folder: %v", err)
	}
}

func TestUploadSourceErrors(t *testing.T) {
	f := newFake(t)
	c := f.client()
	ctx := f.ctx()
	data := pattern(3 * ChunkSize)
	boom := errors.New("boom")

	cases := []struct {
		name string
		next func() ([]byte, error)
		want error
	}{
		{"early-eof", chunker(data[:ChunkSize+5]), io.ErrUnexpectedEOF},
		{"source-error", func() func() ([]byte, error) {
			n := 0
			return func() ([]byte, error) {
				if n++; n == 2 {
					return nil, boom
				}
				return data[:ChunkSize], nil
			}
		}(), boom},
		{"chunk-too-big", func() ([]byte, error) { return make([]byte, ChunkSize+1), nil }, errChunk},
		{"chunk-empty", func() ([]byte, error) { return nil, nil }, errChunk},
		{"past-size", chunker(append(data, 1)), errChunk},
	}
	for i, tc := range cases {
		p := fmt.Sprintf("/srv/u/src%d", i)
		size := int64(len(data))
		if tc.name == "past-size" {
			size = int64(len(data)) - 1
		}
		if err := c.Upload(ctx, p, size, 1<<30, tc.next); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if f.openHandles() != 0 {
			t.Fatalf("%s: handle left open", tc.name)
		}
		// The partial file stays for the caller to remove.
		if _, ok := f.content(p); !ok {
			t.Fatalf("%s: partial file removed", tc.name)
		}
	}
	if err := c.Upload(ctx, "/srv/u/after", 5, 5, chunker(pattern(5))); err != nil {
		t.Fatalf("session not usable after source errors: %v", err)
	}
}

func TestUploadWriteFailure(t *testing.T) {
	f := newFake(t)
	f.hook = func(q fakeReq, r [][]byte) [][]byte {
		if q.typ == typeWrite && q.n == 3 {
			return [][]byte{status(q.id, StatusPermissionDenied)}
		}
		return r
	}
	c := f.client()
	data := pattern(10 * ChunkSize)
	if err := c.Upload(f.ctx(), "/srv/u/w", int64(len(data)), 1<<30, chunker(data)); !isStatus(err, StatusPermissionDenied) {
		t.Fatalf("WRITE failure: %v", err)
	}
	if f.openHandles() != 0 {
		t.Fatal("handle left open")
	}
	if _, err := c.Stat("/srv/u/w"); err != nil {
		t.Fatalf("session not usable after a WRITE failure: %v", err)
	}
}

func TestCancelKeepsSession(t *testing.T) {
	data := pattern(2 << 20)
	for _, hold := range []time.Duration{0, 5 * time.Millisecond} {
		t.Run(fmt.Sprintf("download-hold-%v", hold), func(t *testing.T) {
			f := newFake(t)
			f.hold = hold
			f.file("/big", data)
			c := f.client()
			ctx, cancel := context.WithCancel(f.ctx())
			defer cancel()
			writes, late := 0, 0
			n, err := c.Download(ctx, "/big", 1<<30, func(int64) error { return nil }, func(p []byte) error {
				if ctx.Err() != nil {
					late++
				}
				if writes++; writes == 3 {
					cancel()
				}
				return nil
			})
			if !errors.Is(err, context.Canceled) || late != 0 || n != 3*ChunkSize {
				t.Fatalf("err=%v late writes=%d n=%d", err, late, n)
			}
			if reads := f.seenType(typeRead); reads > 3+8 {
				t.Fatalf("%d READs after cancel", reads)
			}
			if f.openHandles() != 0 {
				t.Fatal("handle left open")
			}
			if _, err := c.Stat("/big"); err != nil {
				t.Fatalf("session not usable after cancel: %v", err)
			}
		})
	}
	t.Run("upload", func(t *testing.T) {
		f := newFake(t)
		c := f.client()
		ctx, cancel := context.WithCancel(f.ctx())
		defer cancel()
		src := chunker(data)
		calls := 0
		err := c.Upload(ctx, "/srv/u/up", int64(len(data)), 1<<30, func() ([]byte, error) {
			if calls++; calls == 4 {
				cancel()
			}
			return src()
		})
		// The chunk returned with the cancel is not sent.
		if !errors.Is(err, context.Canceled) || calls != 4 || f.seenType(typeWrite) != 3 || f.openHandles() != 0 {
			t.Fatalf("err=%v calls=%d writes=%d", err, calls, f.seenType(typeWrite))
		}
		if _, err := c.Stat("/srv/u/up"); err != nil {
			t.Fatalf("session not usable after cancel: %v", err)
		}
	})
}

// TestCancelStalledServer is the worker's path when the server stops
// answering: cancel closes the channel and the call returns at once.
func TestCancelStalledServer(t *testing.T) {
	f := newFake(t)
	f.hook = func(q fakeReq, r [][]byte) [][]byte {
		if (q.typ == typeRead && q.n > 1) || q.typ == typeWrite {
			return nil
		}
		return r
	}
	f.file("/big", pattern(1<<20))
	c := f.client()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = f.conn.Close() })
	defer stop()
	began := time.Now()
	_, err := c.Download(ctx, "/big", 1<<30, func(int64) error { return nil }, func([]byte) error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || time.Since(began) > 5*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(began))
	}
	if _, err := c.Stat("/big"); !errors.Is(err, ErrProtocol) {
		t.Fatalf("client usable after its stream closed: %v", err)
	}
}

func TestNewVersion(t *testing.T) {
	ext := strings.Repeat("e", maxExtString)
	pairs := func(n int, name, data string) []byte {
		fields := []any{uint32(3)}
		for range n {
			fields = append(fields, name, data)
		}
		return pkt(typeVersion, fields...)
	}
	cases := []struct {
		name    string
		version []byte
		ok      bool
	}{
		{"plain", pkt(typeVersion, uint32(3)), true},
		{"32-extensions", pairs(32, ext, ext), true},
		{"33-extensions", pairs(33, "a", "b"), false},
		{"long-name", pairs(1, ext+"e", "b"), false},
		{"long-data", pairs(1, "a", ext+"e"), false},
		{"half-pair", pkt(typeVersion, uint32(3), "a"), false},
		{"version-2", pkt(typeVersion, uint32(2)), false},
		{"version-4", pkt(typeVersion, uint32(4)), false},
		{"not-version", pkt(typeStatus, uint32(0), uint32(0), "", ""), false},
		{"length-4", []byte{0, 0, 0, 4, typeVersion, 0, 0, 0}, false},
		{"length-0", []byte{0, 0, 0, 0}, false},
		{"oversize", binary.BigEndian.AppendUint32(nil, MaxPacket+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.version = tc.version
			conn := f.start()
			// Waiting for the body of a refused VERSION would block; the
			// deadline closes the stream and the error then says so.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			c, err := New(ctx, conn)
			if tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, ErrProtocol)) {
				t.Fatalf("New: %v", err)
			}
			if tc.ok {
				if _, err := c.RealPath("."); err != nil {
					t.Fatalf("RealPath: %v", err)
				}
			}
		})
	}

	t.Run("closed", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer cli.Close()
		go func() {
			_, _ = io.ReadFull(srv, make([]byte, 9))
			_ = srv.Close()
		}()
		if _, err := New(context.Background(), cli); !errors.Is(err, ErrProtocol) || !errors.Is(err, io.EOF) {
			t.Fatalf("New on a closed stream: %v", err)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer srv.Close()
		go func() { _, _ = io.Copy(io.Discard, srv) }()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { _ = cli.Close() })
		defer stop()
		if _, err := New(ctx, cli); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("New past its deadline: %v", err)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := New(ctx, struct {
			io.Reader
			io.Writer
		}{strings.NewReader(""), io.Discard}); !errors.Is(err, context.Canceled) {
			t.Fatalf("New with a cancelled context: %v", err)
		}
	})
}

// replaceStat answers the first STAT with the given packets.
func replaceStat(f *fakeServer, build func(id uint32) [][]byte) {
	f.hook = func(q fakeReq, r [][]byte) [][]byte {
		if q.typ == typeStat && q.n == 1 {
			return build(q.id)
		}
		return r
	}
}

func TestPacketBounds(t *testing.T) {
	cases := []struct {
		name  string
		build func(id uint32) [][]byte
		ok    bool
	}{
		{"max", func(id uint32) [][]byte {
			// type, id, code and two string lengths take 17 bytes.
			return [][]byte{pkt(typeStatus, id, StatusNoSuchFile, strings.Repeat("m", MaxPacket-17), "")}
		}, true},
		{"over-max", func(id uint32) [][]byte {
			// A complete, well-formed STATUS one byte too long.
			return [][]byte{pkt(typeStatus, id, StatusNoSuchFile, strings.Repeat("m", MaxPacket-16), "")}
		}, false},
		{"large", func(uint32) [][]byte { return [][]byte{binary.BigEndian.AppendUint32(nil, 64<<20)} }, false},
		{"length-4", func(uint32) [][]byte { return [][]byte{{0, 0, 0, 4, typeStatus, 0, 0, 0}} }, false},
		{"length-0", func(uint32) [][]byte { return [][]byte{{0, 0, 0, 0}} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.file("/f", []byte("x"))
			replaceStat(f, tc.build)
			c := f.client()
			// A client that waited for the body of a refused packet would
			// block; closing the stream turns that into an I/O error, which
			// the checks below tell apart from a refusal.
			watchdog := time.AfterFunc(3*time.Second, func() { _ = f.conn.Close() })
			defer watchdog.Stop()
			_, err := c.Stat("/f")
			if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
				t.Fatalf("client read past a refused length: %v", err)
			}
			if tc.ok {
				if !isStatus(err, StatusNoSuchFile) {
					t.Fatalf("packet of MaxPacket bytes: %v", err)
				}
				if _, err := c.Stat("/f"); err != nil {
					t.Fatalf("session not usable: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("out-of-bounds packet: %v", err)
			}
			sent := f.count()
			if _, err := c.Stat("/f"); err != ErrProtocol || f.count() != sent {
				t.Fatalf("client not spent after a protocol error: %v", err)
			}
		})
	}
}

func TestReplyMatching(t *testing.T) {
	stat := func(t *testing.T, build func(id uint32) [][]byte) error {
		f := newFake(t)
		f.file("/f", []byte("x"))
		replaceStat(f, build)
		c := f.client()
		_, err := c.Stat("/f")
		return err
	}
	protocol := map[string]func(id uint32) [][]byte{
		"wrong-id":      func(id uint32) [][]byte { return [][]byte{pkt(typeAttrs, id+1, noAttrs)} },
		"data-for-stat": func(id uint32) [][]byte { return [][]byte{pkt(typeData, id, "x")} },
		"version-again": func(id uint32) [][]byte { return [][]byte{pkt(typeVersion, uint32(3))} },
		"init-type":     func(id uint32) [][]byte { return [][]byte{pkt(typeInit, id)} },
		"type-200":      func(id uint32) [][]byte { return [][]byte{pkt(200, id, noAttrs)} },
		"status-ok":     func(id uint32) [][]byte { return [][]byte{status(id, statusOK)} },
		"attrs-short":   func(id uint32) [][]byte { return [][]byte{pkt(typeAttrs, id, raw{0, 0, 0, 1, 0})} },
		"status-short":  func(id uint32) [][]byte { return [][]byte{pkt(typeStatus, id, raw{0, 0})} },
		"status-half":   func(id uint32) [][]byte { return [][]byte{pkt(typeStatus, id, StatusFailure, "msg")} },
		"status-extra":  func(id uint32) [][]byte { return [][]byte{pkt(typeStatus, id, StatusFailure, "", "", raw{1})} },
		"id-only":       func(id uint32) [][]byte { return [][]byte{pkt(typeAttrs, id)} },
	}
	for name, build := range protocol {
		t.Run(name, func(t *testing.T) {
			if err := stat(t, build); !errors.Is(err, ErrProtocol) {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
	t.Run("status-bare", func(t *testing.T) {
		if err := stat(t, func(id uint32) [][]byte { return [][]byte{pkt(typeStatus, id, StatusFailure)} }); !isStatus(err, StatusFailure) {
			t.Fatalf("STATUS without message: %v", err)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		f := newFake(t)
		f.file("/f", []byte("x"))
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeStat {
				return append(r, r...)
			}
			return r
		}
		c := f.client()
		if _, err := c.Stat("/f"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Lstat("/f"); !errors.Is(err, ErrProtocol) {
			t.Fatalf("duplicate reply accepted: %v", err)
		}
	})
	transfers := map[string]func(q fakeReq, r [][]byte) [][]byte{
		"duplicate-read": func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeRead && q.n == 2 {
				return append(r, r...)
			}
			return r
		},
		"unknown-read-id": func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeRead && q.n == 2 {
				return [][]byte{pkt(typeData, q.id+1000, "x")}
			}
			return r
		},
		"attrs-for-read": func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeRead {
				return [][]byte{pkt(typeAttrs, q.id, noAttrs)}
			}
			return r
		},
		"ok-for-read": func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeRead {
				return [][]byte{status(q.id, statusOK)}
			}
			return r
		},
		"ok-for-open": func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeOpen {
				return [][]byte{status(q.id, statusOK)}
			}
			return r
		},
		"handle-for-close": func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeClose {
				return [][]byte{pkt(typeHandle, q.id, "h")}
			}
			return r
		},
	}
	for name, hook := range transfers {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.hook = hook
			f.file("/f", pattern(4*ChunkSize))
			c := f.client()
			if g := fetch(t, f.ctx(), c, "/f", 1<<30); !errors.Is(g.err, ErrProtocol) {
				t.Fatalf("%s: %v", name, g.err)
			}
		})
	}
	t.Run("duplicate-write-ack", func(t *testing.T) {
		f := newFake(t)
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeWrite && q.n == 1 {
				return append(r, r...)
			}
			return r
		}
		c := f.client()
		data := pattern(3 * ChunkSize)
		if err := c.Upload(f.ctx(), "/srv/u/d", int64(len(data)), 1<<30, chunker(data)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("duplicate WRITE ack accepted: %v", err)
		}
	})
}

// attrBlock builds an ATTRS block from raw fields.
func attrBlock(flags uint32, fields ...any) raw {
	p := pkt(0, append([]any{flags}, fields...)...)
	return raw(p[5:])
}

func TestAttrs(t *testing.T) {
	ext := strings.Repeat("x", maxExtString)
	extPairs := func(n int, name, data string) []any {
		fields := []any{u32(n)}
		for range n {
			fields = append(fields, name, data)
		}
		return fields
	}
	all := attrSize | attrUIDGID | attrPerms | attrACModTime
	cases := []struct {
		name  string
		attrs raw
		want  Attr
		ok    bool
	}{
		{"none", attrBlock(0), Attr{}, true},
		{"size", attrBlock(attrSize, uint64(1<<40)), Attr{Size: 1 << 40, HasSize: true}, true},
		{"file", attrBlock(uint32(all), uint64(5), uint32(1), uint32(2), uint32(0o100600), uint32(3), uint32(4)), Attr{Kind: KindFile, Size: 5, HasSize: true, ModTime: 4}, true},
		{"dir", attrBlock(attrPerms, uint32(0o040700)), Attr{Kind: KindDir}, true},
		{"link", attrBlock(attrPerms, uint32(0o120777)), Attr{Kind: KindLink}, true},
		{"socket", attrBlock(attrPerms, uint32(0o140777)), Attr{Kind: KindOther}, true},
		{"fifo", attrBlock(attrPerms, uint32(0o010644)), Attr{Kind: KindOther}, true},
		{"modtime", attrBlock(attrACModTime, uint32(7), uint32(9)), Attr{ModTime: 9}, true},
		{"ext-32", attrBlock(attrExtended, extPairs(32, ext, ext)...), Attr{}, true},
		{"ext-33", attrBlock(attrExtended, extPairs(33, "a", "b")...), Attr{}, false},
		{"ext-long-type", attrBlock(attrExtended, extPairs(1, ext+"x", "b")...), Attr{}, false},
		{"ext-long-data", attrBlock(attrExtended, extPairs(1, "a", ext+"x")...), Attr{}, false},
		{"unknown-0x10", attrBlock(0x10), Attr{}, false},
		{"unknown-0x40000000", attrBlock(0x40000000), Attr{}, false},
		{"truncated-size", attrBlock(attrSize, uint32(5)), Attr{}, false},
		{"truncated-uidgid", attrBlock(attrUIDGID, uint32(5)), Attr{}, false},
		{"trailing", attrBlock(attrPerms, uint32(0o100600), raw{0}), Attr{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.file("/f", nil)
			replaceStat(f, func(id uint32) [][]byte { return [][]byte{pkt(typeAttrs, id, tc.attrs)} })
			c := f.client()
			a, err := c.Stat("/f")
			if tc.ok && (err != nil || a != tc.want) {
				t.Fatalf("got %+v, %v; want %+v", a, err, tc.want)
			}
			if !tc.ok && !errors.Is(err, ErrProtocol) {
				t.Fatalf("bad attributes accepted: %+v, %v", a, err)
			}
		})
	}
}

func TestHandleBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		ok   bool
	}{{"256", 256, true}, {"257", 257, false}, {"empty", 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.handleName = func(n int) string {
				s := fmt.Sprintf("h%d", n)
				return s + strings.Repeat("-", max(tc.size-len(s), 0))
			}
			if tc.size == 0 {
				f.handleName = func(int) string { return "" }
			}
			f.put("/d", &fakeNode{dir: true})
			f.file("/d/a", []byte("hello"))
			c := f.client()
			_, err := listAll(c, "/d", 10)
			g := fetch(t, f.ctx(), c, "/d/a", 10)
			if tc.ok && (err != nil || g.err != nil || string(g.data) != "hello") {
				t.Fatalf("handle of %d bytes: %v, %v", tc.size, err, g.err)
			}
			if !tc.ok && !errors.Is(err, ErrProtocol) {
				t.Fatalf("handle of %d bytes accepted: %v", tc.size, err)
			}
		})
	}
}

func TestDataBounds(t *testing.T) {
	// The limit of 5 makes the client ask for 6 bytes: one past the limit.
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"asked", pattern(6), ErrTooLarge},
		{"over-asked", pattern(7), ErrProtocol},
		{"empty", nil, ErrProtocol},
		{"chunk-plus-one", pattern(ChunkSize + 1), ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.hook = func(q fakeReq, r [][]byte) [][]byte {
				switch q.typ {
				case typeFstat:
					return [][]byte{pkt(typeAttrs, q.id, noAttrs)}
				case typeRead:
					return [][]byte{pkt(typeData, q.id, tc.data)}
				}
				return r
			}
			f.file("/f", pattern(100))
			c := f.client()
			if g := fetch(t, f.ctx(), c, "/f", 5); !errors.Is(g.err, tc.want) || g.n != 0 {
				t.Fatalf("n=%d err=%v; want %v", g.n, g.err, tc.want)
			}
		})
	}
	t.Run("trailing", func(t *testing.T) {
		f := newFake(t)
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeRead {
				return [][]byte{pkt(typeData, q.id, "abc", raw{0})}
			}
			return r
		}
		f.file("/f", pattern(100))
		c := f.client()
		if g := fetch(t, f.ctx(), c, "/f", 1<<20); !errors.Is(g.err, ErrProtocol) {
			t.Fatalf("DATA with trailing bytes: %v", g.err)
		}
	})
}

// nameReply builds a NAME reply from names, each a plain file.
func nameReply(id uint32, names ...string) []byte {
	fields := []any{id, u32(len(names))}
	for _, n := range names {
		fields = append(fields, n, "", attrsOf(&fakeNode{data: []byte("x")}))
	}
	return pkt(typeName, fields...)
}

func TestListBounds(t *testing.T) {
	makeDir := func(f *fakeServer, n int) []string {
		f.put("/d", &fakeNode{dir: true})
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("f%05d", i)
			f.file("/d/"+names[i], nil)
		}
		return names
	}
	namesOf := func(es []Entry) []string {
		out := make([]string, len(es))
		for i, e := range es {
			out[i] = string(e.Name)
		}
		return out
	}

	t.Run("limit", func(t *testing.T) {
		f := newFake(t)
		names := makeDir(f, 10)
		c := f.client()
		es, err := listAll(c, "/d", 10)
		if err != nil || strings.Join(namesOf(es), ",") != strings.Join(names, ",") {
			t.Fatalf("list of 10 at limit 10: %v %v", namesOf(es), err)
		}
		es, err = listAll(c, "/d", 9)
		if !errors.Is(err, ErrTooMany) || len(es) != 9 {
			t.Fatalf("list of 10 at limit 9: %d, %v", len(es), err)
		}
		if f.openHandles() != 0 {
			t.Fatal("handle left open")
		}
		if _, err := listAll(c, "/d", 10); err != nil {
			t.Fatalf("session not usable after ErrTooMany: %v", err)
		}
	})

	t.Run("ten-thousand", func(t *testing.T) {
		f := newFake(t)
		f.batch = 100
		makeDir(f, 10000)
		c := f.client()
		if es, err := listAll(c, "/d", 10000); err != nil || len(es) != 10000 {
			t.Fatalf("10000 entries: %d, %v", len(es), err)
		}
		f.file("/d/one-more", nil)
		if es, err := listAll(c, "/d", 10000); !errors.Is(err, ErrTooMany) || len(es) != 10000 {
			t.Fatalf("10001 entries: %d, %v", len(es), err)
		}
	})

	t.Run("names", func(t *testing.T) {
		f := newFake(t)
		f.put("/d", &fakeNode{dir: true})
		long255, long256 := strings.Repeat("a", 255), strings.Repeat("b", 256)
		for _, n := range []string{long255, long256, "ok", "\xff\xfe"} {
			f.file("/d/"+n, nil)
		}
		c := f.client()
		es, err := listAll(c, "/d", 3)
		if err != nil || strings.Join(namesOf(es), ",") != long255+",ok,\xff\xfe" {
			t.Fatalf("names: %q, %v", namesOf(es), err)
		}
	})

	t.Run("not-one-element", func(t *testing.T) {
		f := newFake(t)
		f.put("/d", &fakeNode{dir: true})
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeReaddir && q.n == 1 {
				return [][]byte{nameReply(q.id, ".", "..", "a/b", "x\x00y", "", "/", "good")}
			}
			return r
		}
		c := f.client()
		es, err := listAll(c, "/d", 10)
		if err != nil || strings.Join(namesOf(es), ",") != "good" {
			t.Fatalf("names: %q, %v", namesOf(es), err)
		}
	})

	for _, tc := range []struct {
		batch int
		ok    bool
	}{{1024, true}, {1025, false}} {
		t.Run(fmt.Sprintf("count-%d", tc.batch), func(t *testing.T) {
			f := newFake(t)
			f.batch = tc.batch
			makeDir(f, 1100)
			c := f.client()
			es, err := listAll(c, "/d", 10000)
			if tc.ok && (err != nil || len(es) != 1100) {
				t.Fatalf("NAME of %d: %d, %v", tc.batch, len(es), err)
			}
			if !tc.ok && (!errors.Is(err, ErrProtocol) || len(es) != 0) {
				t.Fatalf("NAME of %d accepted: %d, %v", tc.batch, len(es), err)
			}
		})
	}

	for _, tc := range []struct {
		size int
		ok   bool
	}{{4096, true}, {4097, false}} {
		t.Run(fmt.Sprintf("longname-%d", tc.size), func(t *testing.T) {
			f := newFake(t)
			f.longname = func(string) string { return strings.Repeat("L", tc.size) }
			makeDir(f, 3)
			c := f.client()
			if _, err := listAll(c, "/d", 10); tc.ok != (err == nil) || (!tc.ok && !errors.Is(err, ErrProtocol)) {
				t.Fatalf("long name of %d: %v", tc.size, err)
			}
		})
	}

	t.Run("whole-reply-checked-first", func(t *testing.T) {
		f := newFake(t)
		f.put("/d", &fakeNode{dir: true})
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeReaddir {
				good := nameReply(q.id, "a", "b")
				// Claim three entries but carry two.
				binary.BigEndian.PutUint32(good[9:], 3)
				return [][]byte{good}
			}
			return r
		}
		c := f.client()
		if es, err := listAll(c, "/d", 10); !errors.Is(err, ErrProtocol) || len(es) != 0 {
			t.Fatalf("truncated NAME: %d entries, %v", len(es), err)
		}
	})

	t.Run("bad-attrs", func(t *testing.T) {
		f := newFake(t)
		f.put("/d", &fakeNode{dir: true})
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeReaddir {
				return [][]byte{pkt(typeName, q.id, uint32(1), "a", "", attrBlock(0x10))}
			}
			return r
		}
		c := f.client()
		if _, err := listAll(c, "/d", 10); !errors.Is(err, ErrProtocol) {
			t.Fatalf("bad attributes in NAME: %v", err)
		}
	})

	t.Run("each-error", func(t *testing.T) {
		f := newFake(t)
		makeDir(f, 10)
		c := f.client()
		stop := errors.New("stop")
		calls := 0
		err := c.List("/d", 100, func(Entry) error {
			if calls++; calls == 3 {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) || calls != 3 || f.openHandles() != 0 {
			t.Fatalf("each error: %v after %d calls", err, calls)
		}
	})

	for name, build := range map[string]func(id uint32) []byte{
		"endless-dots":  func(id uint32) []byte { return nameReply(id, strings.Split(strings.Repeat(".,", 99)+".", ",")...) },
		"endless-empty": func(id uint32) []byte { return pkt(typeName, id, uint32(0)) },
		"endless-long":  func(id uint32) []byte { return nameReply(id, strings.Repeat("z", 300)) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.put("/d", &fakeNode{dir: true})
			f.hook = func(q fakeReq, r [][]byte) [][]byte {
				if q.typ == typeReaddir {
					return [][]byte{build(q.id)}
				}
				return r
			}
			c := f.client()
			if _, err := listAll(c, "/d", 10); !errors.Is(err, ErrTooMany) {
				t.Fatalf("endless listing: %v", err)
			}
			if n := f.seenType(typeReaddir); n > 13 {
				t.Fatalf("%d READDIRs for a limit of 10", n)
			}
			if f.openHandles() != 0 {
				t.Fatal("handle left open")
			}
		})
	}

	t.Run("status", func(t *testing.T) {
		f := newFake(t)
		makeDir(f, 3)
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			if q.typ == typeReaddir {
				return [][]byte{status(q.id, StatusPermissionDenied)}
			}
			return r
		}
		c := f.client()
		if _, err := listAll(c, "/d", 10); !isStatus(err, StatusPermissionDenied) || f.openHandles() != 0 {
			t.Fatalf("READDIR failure: %v", err)
		}
		if _, err := listAll(c, "/missing", 10); !isStatus(err, StatusNoSuchFile) {
			t.Fatalf("missing folder: %v", err)
		}
	})

	t.Run("kinds-and-copies", func(t *testing.T) {
		f := newFake(t)
		f.put("/d", &fakeNode{dir: true})
		f.file("/d/file", []byte("hello"))
		f.put("/d/sub", &fakeNode{dir: true})
		f.put("/d/link", &fakeNode{link: "/d/file"})
		f.put("/d/sock", &fakeNode{mode: 0o140755})
		c := f.client()
		es, err := listAll(c, "/d", 10)
		if err != nil || len(es) != 4 {
			t.Fatalf("list: %d, %v", len(es), err)
		}
		want := map[string]Attr{
			"file": {Kind: KindFile, Size: 5, HasSize: true, ModTime: 1234},
			"sub":  {Kind: KindDir, HasSize: true},
			"link": {Kind: KindLink, HasSize: true},
			"sock": {Kind: KindOther, HasSize: true},
		}
		for _, e := range es {
			if w, ok := want[string(e.Name)]; !ok || e.Attr != w {
				t.Fatalf("%s: %+v, want %+v", e.Name, e.Attr, w)
			}
		}
		// Names are copies: more traffic must not change them.
		if _, err := listAll(c, "/d", 10); err != nil {
			t.Fatal(err)
		}
		if strings.Join(namesOf(es), ",") != "file,link,sock,sub" {
			t.Fatalf("kept names changed: %q", namesOf(es))
		}
	})
}

func TestPathChecks(t *testing.T) {
	f := newFake(t)
	c := f.client()
	ctx := f.ctx()
	noStart := func(int64) error { return nil }
	noWrite := func([]byte) error { return nil }
	noNext := func() ([]byte, error) { return nil, io.EOF }
	bad := []string{"", "a", ".", "./a", "..", "/a\x00b", "/\xff", "/" + strings.Repeat("a", maxPath)}
	for _, p := range bad {
		calls := map[string]error{}
		if p != "." {
			_, calls["RealPath"] = c.RealPath(p)
		}
		_, calls["Stat"] = c.Stat(p)
		_, calls["Lstat"] = c.Lstat(p)
		calls["List"] = c.List(p, 10, func(Entry) error { return nil })
		calls["Mkdir"] = c.Mkdir(p)
		calls["Rmdir"] = c.Rmdir(p)
		calls["Remove"] = c.Remove(p)
		calls["Rename-from"] = c.Rename(p, "/ok")
		calls["Rename-to"] = c.Rename("/ok", p)
		_, calls["Download"] = c.Download(ctx, p, 10, noStart, noWrite)
		calls["Upload"] = c.Upload(ctx, p, 0, 10, noNext)
		for name, err := range calls {
			if !errors.Is(err, ErrPath) {
				t.Errorf("%s(%q): %v", name, p, err)
			}
		}
	}
	if n := f.count(); n != 0 {
		t.Fatalf("%d requests sent for refused paths", n)
	}
	longest := "/" + strings.Repeat("a", maxPath-1)
	if _, err := c.Stat(longest); !isStatus(err, StatusNoSuchFile) {
		t.Fatalf("path of 4096 bytes: %v", err)
	}
}

func TestRealPath(t *testing.T) {
	t.Run("home", func(t *testing.T) {
		f := newFake(t)
		c := f.client()
		if p, err := c.RealPath("."); err != nil || p != "/srv/u" {
			t.Fatalf("RealPath(.) = %q, %v", p, err)
		}
		if p, err := c.RealPath("/srv/u/x"); err != nil || p != "/srv/u/x" {
			t.Fatalf("RealPath(absolute) = %q, %v", p, err)
		}
	})
	longest := "/" + strings.Repeat("p", maxPath-1)
	cases := []struct {
		name  string
		reply func(id uint32) []byte
		want  string
	}{
		{"4096", func(id uint32) []byte { return pkt(typeName, id, uint32(1), longest, "", noAttrs) }, longest},
		{"4097", func(id uint32) []byte { return pkt(typeName, id, uint32(1), longest+"p", "", noAttrs) }, ""},
		{"relative", func(id uint32) []byte { return pkt(typeName, id, uint32(1), "home/u", "", noAttrs) }, ""},
		{"empty", func(id uint32) []byte { return pkt(typeName, id, uint32(1), "", "", noAttrs) }, ""},
		{"not-utf8", func(id uint32) []byte { return pkt(typeName, id, uint32(1), "/\xff", "", noAttrs) }, ""},
		{"nul", func(id uint32) []byte { return pkt(typeName, id, uint32(1), "/a\x00", "", noAttrs) }, ""},
		{"two", func(id uint32) []byte { return pkt(typeName, id, uint32(2), "/a", "", noAttrs, "/b", "", noAttrs) }, ""},
		{"none", func(id uint32) []byte { return pkt(typeName, id, uint32(0)) }, ""},
		{"attrs", func(id uint32) []byte { return pkt(typeName, id, uint32(1), "/a", "", attrBlock(0x10)) }, ""},
		{"long-longname", func(id uint32) []byte {
			return pkt(typeName, id, uint32(1), "/a", strings.Repeat("l", maxPath+1), noAttrs)
		}, ""},
		{"handle", func(id uint32) []byte { return pkt(typeHandle, id, "h") }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.hook = func(q fakeReq, r [][]byte) [][]byte {
				if q.typ == typeRealpath {
					return [][]byte{tc.reply(q.id)}
				}
				return r
			}
			c := f.client()
			p, err := c.RealPath(".")
			if tc.want != "" && (err != nil || p != tc.want) {
				t.Fatalf("got %d bytes, %v", len(p), err)
			}
			if tc.want == "" && !errors.Is(err, ErrProtocol) {
				t.Fatalf("bad REALPATH reply accepted: %q, %v", p, err)
			}
		})
	}
	t.Run("status", func(t *testing.T) {
		f := newFake(t)
		f.hook = func(q fakeReq, r [][]byte) [][]byte {
			return [][]byte{status(q.id, StatusNoSuchFile)}
		}
		c := f.client()
		if _, err := c.RealPath("/nope"); !isStatus(err, StatusNoSuchFile) {
			t.Fatalf("REALPATH failure: %v", err)
		}
	})
}

func TestStatusCodes(t *testing.T) {
	codes := []uint32{StatusEOF, StatusNoSuchFile, StatusPermissionDenied, StatusFailure,
		StatusBadMessage, StatusNoConnection, StatusConnectionLost, StatusOpUnsupported, 99}
	f := newFake(t)
	next := 0
	f.hook = func(q fakeReq, r [][]byte) [][]byte {
		if q.typ == typeMkdir || q.typ == typeStat {
			return [][]byte{status(q.id, codes[next])}
		}
		return r
	}
	c := f.client()
	seen := map[string]bool{}
	for i, code := range codes {
		next = i
		err := c.Mkdir("/srv/u/x")
		if !isStatus(err, code) {
			t.Fatalf("code %d: %v", code, err)
		}
		if msg := err.Error(); !strings.HasPrefix(msg, "sftp: ") || seen[msg] {
			t.Fatalf("code %d message %q", code, msg)
		} else {
			seen[msg] = true
		}
		if _, err := c.Stat("/srv/u"); !isStatus(err, code) {
			t.Fatalf("STAT code %d: %v", code, err)
		}
	}
}

func TestOperations(t *testing.T) {
	f := newFake(t)
	c := f.client()
	home, err := c.RealPath(".")
	if err != nil || home != "/srv/u" {
		t.Fatalf("home %q, %v", home, err)
	}
	d := home + "/d"
	if err := c.Mkdir(d); err != nil {
		t.Fatal(err)
	}
	if err := c.Mkdir(d); !isStatus(err, StatusFailure) {
		t.Fatalf("Mkdir over an existing folder: %v", err)
	}
	if a, err := c.Stat(d); err != nil || a.Kind != KindDir {
		t.Fatalf("Stat folder: %+v, %v", a, err)
	}
	f.file(d+"/x", []byte("hello"))
	f.put(home+"/l", &fakeNode{link: d + "/x"})
	if a, err := c.Lstat(home + "/l"); err != nil || a.Kind != KindLink {
		t.Fatalf("Lstat link: %+v, %v", a, err)
	}
	if a, err := c.Stat(home + "/l"); err != nil || a.Kind != KindFile || a.Size != 5 || !a.HasSize {
		t.Fatalf("Stat link: %+v, %v", a, err)
	}
	if err := c.Rename(d+"/x", d+"/y"); err != nil {
		t.Fatal(err)
	}
	f.file(d+"/z", nil)
	if err := c.Rename(d+"/z", d+"/y"); !isStatus(err, StatusFailure) {
		t.Fatalf("Rename over an existing name: %v", err)
	}
	if err := c.Rmdir(d); !isStatus(err, StatusFailure) {
		t.Fatalf("Rmdir of a full folder: %v", err)
	}
	for _, p := range []string{d + "/y", d + "/z", home + "/l"} {
		if err := c.Remove(p); err != nil {
			t.Fatalf("Remove %s: %v", p, err)
		}
	}
	if err := c.Remove(d); !isStatus(err, StatusFailure) {
		t.Fatalf("Remove of a folder: %v", err)
	}
	if err := c.Rmdir(d); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stat(d); !isStatus(err, StatusNoSuchFile) {
		t.Fatalf("Stat after Rmdir: %v", err)
	}
}

// TestOnlyAllowedRequests drives every call. The fake fails the test on any
// type outside the allowed set; this also shows each allowed one is used,
// and that RENAME is plain version 3 although posix-rename is offered.
func TestOnlyAllowedRequests(t *testing.T) {
	f := newFake(t)
	f.short = true
	c := f.client()
	ctx := f.ctx()
	data := pattern(3*ChunkSize + 1)
	steps := []error{
		c.Mkdir("/srv/u/d"),
		c.Upload(ctx, "/srv/u/d/a", int64(len(data)), 1<<20, chunker(data)),
		c.Rename("/srv/u/d/a", "/srv/u/d/b"),
		c.List("/srv/u/d", 10, func(Entry) error { return nil }),
		c.Remove("/srv/u/d/b"),
		c.Rmdir("/srv/u/d"),
	}
	_, e1 := c.RealPath(".")
	_, e2 := c.Stat("/srv/u")
	_, e3 := c.Lstat("/srv/u")
	f.file("/srv/u/r", data)
	g := fetch(t, ctx, c, "/srv/u/r", 1<<20)
	for i, err := range append(steps, e1, e2, e3, g.err) {
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	for typ := range allowedRequests {
		if f.seenType(typ) == 0 {
			t.Errorf("request type %d never used", typ)
		}
	}
}

func TestSpentClient(t *testing.T) {
	f := newFake(t)
	replaceStat(f, func(id uint32) [][]byte { return [][]byte{pkt(typeAttrs, id+7, noAttrs)} })
	c := f.client()
	if _, err := c.Stat("/srv/u"); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	sent := f.count()
	ctx := f.ctx()
	_, e1 := c.RealPath(".")
	_, e2 := c.Stat("/srv/u")
	_, e3 := c.Lstat("/srv/u")
	_, e4 := c.Download(ctx, "/f", 10, func(int64) error { return nil }, func([]byte) error { return nil })
	for i, err := range []error{e1, e2, e3, e4,
		c.List("/srv/u", 10, func(Entry) error { return nil }),
		c.Mkdir("/a"), c.Rmdir("/a"), c.Remove("/a"), c.Rename("/a", "/b"),
		c.Upload(ctx, "/a", 0, 0, func() ([]byte, error) { return nil, io.EOF }),
	} {
		if err != ErrProtocol {
			t.Errorf("call %d after a protocol error: %v", i, err)
		}
	}
	if f.count() != sent {
		t.Fatal("a spent client sent requests")
	}
}

func TestReentryRefused(t *testing.T) {
	f := newFake(t)
	f.put("/d", &fakeNode{dir: true})
	f.file("/d/a", []byte("abc"))
	c := f.client()
	var inner error
	if err := c.List("/d", 10, func(Entry) error {
		_, inner = c.Stat("/d/a")
		return nil
	}); err != nil || !errors.Is(inner, errBusy) {
		t.Fatalf("Stat inside List: %v, %v", err, inner)
	}
	_, err := c.Download(f.ctx(), "/d/a", 10, func(int64) error { return nil }, func([]byte) error {
		inner = c.Mkdir("/d/b")
		return nil
	})
	if err != nil || !errors.Is(inner, errBusy) {
		t.Fatalf("Mkdir inside Download: %v, %v", err, inner)
	}
	if _, err := c.Stat("/d/a"); err != nil {
		t.Fatalf("client not usable after refused re-entry: %v", err)
	}
}
