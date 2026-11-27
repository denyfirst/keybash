package sftpclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"runtime"
	"testing"
	"time"
)

// fuzzStream plays the server: replies come from the fuzz input, and every
// request the client writes is checked against the allowed set.
type fuzzStream struct {
	t testing.TB
	r *bytes.Reader
}

func (s *fuzzStream) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *fuzzStream) Write(p []byte) (int, error) {
	if len(p) < 5 || int(binary.BigEndian.Uint32(p)) != len(p)-4 {
		s.t.Fatalf("client wrote a partial or mislabelled packet of %d bytes", len(p))
	}
	if typ := p[4]; typ != typeInit && !allowedRequests[typ] {
		s.t.Fatalf("client sent forbidden request type %d", typ)
	}
	return len(p), nil
}

// FuzzSFTPReply feeds arbitrary bytes as the server's replies after a valid
// VERSION. The client must not panic, hang or allocate past its bounds.
func FuzzSFTPReply(f *testing.F) {
	file := attrsOf(&fakeNode{data: make([]byte, 10)})
	dir := attrsOf(&fakeNode{dir: true})
	cat := func(ps ...[]byte) []byte { return bytes.Join(ps, nil) }
	eofs := func(from, to uint32) []byte {
		var b []byte
		for id := from; id <= to; id++ {
			b = append(b, status(id, StatusEOF)...)
		}
		return b
	}
	// List: OPENDIR, READDIR, READDIR, CLOSE.
	f.Add(byte(0), cat(pkt(typeHandle, uint32(1), "h"),
		pkt(typeName, uint32(2), uint32(3), ".", "", dir, "a", "-rw a", file, "b", "drwx b", dir),
		status(3, StatusEOF), status(4, statusOK)))
	f.Add(byte(0), cat(pkt(typeHandle, uint32(1), "h"), pkt(typeName, uint32(2), uint32(0)), status(3, StatusPermissionDenied)))
	// Stat and Lstat.
	f.Add(byte(1), cat(pkt(typeAttrs, uint32(1), file), pkt(typeAttrs, uint32(2), attrBlock(attrExtended, uint32(1), "a", "b"))))
	f.Add(byte(1), cat(status(1, StatusNoSuchFile), pkt(typeAttrs, uint32(2), noAttrs)))
	// Download: OPEN, FSTAT, eight READs (the first short, then asked again), CLOSE.
	f.Add(byte(2), cat(pkt(typeHandle, uint32(1), "h"), pkt(typeAttrs, uint32(2), file),
		pkt(typeData, uint32(3), "0123456789"), eofs(4, 11), status(12, statusOK)))
	f.Add(byte(2), cat(pkt(typeHandle, uint32(1), "h"), pkt(typeAttrs, uint32(2), noAttrs),
		pkt(typeData, uint32(4), "late"), pkt(typeData, uint32(3), "0123")))
	// Upload of 100000 bytes: OPEN, four WRITEs, CLOSE.
	f.Add(byte(3), cat(pkt(typeHandle, uint32(1), "h"), status(3, statusOK), status(2, statusOK),
		status(4, statusOK), status(5, statusOK), status(6, statusOK)))
	// RealPath.
	f.Add(byte(4), pkt(typeName, uint32(1), uint32(1), "/home/u", "", noAttrs))
	// Bounds.
	f.Add(byte(1), []byte{0xff, 0xff, 0xff, 0xff, typeAttrs})
	f.Add(byte(0), cat(pkt(typeHandle, uint32(1), "h"), binary.BigEndian.AppendUint32(nil, MaxPacket)))

	zero := make([]byte, ChunkSize)
	f.Fuzz(func(t *testing.T, op byte, replies []byte) {
		stream := &fuzzStream{t: t, r: bytes.NewReader(append(pkt(typeVersion, uint32(3)), replies...))}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		c, err := New(ctx, stream)
		if err != nil {
			t.Fatalf("valid VERSION refused: %v", err)
		}
		const limit = 1 << 20
		switch op % 5 {
		case 0:
			kept := 0
			_ = c.List("/d", 100, func(e Entry) error {
				if kept++; kept > 100 || !usableName(e.Name) {
					t.Fatalf("entry %d %q passed the bounds", kept, e.Name)
				}
				return nil
			})
		case 1:
			_, _ = c.Stat("/x")
			_, _ = c.Lstat("/x")
		case 2:
			var total int
			n, _ := c.Download(ctx, "/f", limit, func(size int64) error {
				if size < 0 || size > limit {
					t.Fatalf("start with size %d", size)
				}
				return nil
			}, func(p []byte) error {
				if total += len(p); len(p) == 0 || len(p) > ChunkSize || total > limit {
					t.Fatalf("write of %d bytes, %d in all", len(p), total)
				}
				return nil
			})
			if n != int64(total) {
				t.Fatalf("Download returned %d after writing %d", n, total)
			}
		case 3:
			left := 100000
			_ = c.Upload(ctx, "/u", int64(left), limit, func() ([]byte, error) {
				n := min(left, ChunkSize)
				left -= n
				return zero[:n], nil
			})
		case 4:
			if p, err := c.RealPath("."); err == nil && (len(p) == 0 || len(p) > maxPath || p[0] != '/') {
				t.Fatalf("RealPath returned %q", p)
			}
		}
		runtime.ReadMemStats(&after)
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 16<<20 {
			t.Fatalf("allocated %d bytes for %d bytes of replies", grew, len(replies))
		}
	})
}
