package sftpclient

import (
	"context"
	"errors"
	"io"
	"math"
)

// readSlot is one chunk of a download. Slots hold chunks in file order
// around a ring, starting at head, and each has at most one READ in flight.
type readSlot struct {
	id    uint32
	off   uint64 // first byte the slot has not delivered yet
	want  uint32 // bytes from off the slot still covers
	have  uint32 // bytes from off already received and kept in buf
	asked uint32 // bytes the READ in flight asked for
	busy  bool   // a READ is in flight
	eof   bool   // the server said EOF at off+have
	buf   []byte // made only when a reply arrives early or short
}

type downloader struct {
	ctx    context.Context
	c      *Client
	h      []byte
	limit  uint64
	write  func([]byte) error
	slots  [maxInFlight]readSlot
	head   int
	next   uint64 // offset of the next chunk to ask for
	done   uint64 // bytes given to write
	active int    // READs in flight
	eof    bool   // some READ met EOF: ask for no new chunks
	ended  bool   // EOF reached in order: every byte is delivered
}

// Download opens path for reading, calls start with the size FSTAT reports
// (0 when the server gives none) and gives the file to write in order, at
// most ChunkSize bytes per call. It returns the number of bytes written.
//
// The slice passed to write is reused once write returns; write must not
// keep it. More than limit bytes, or an FSTAT size over limit (checked
// before start), end the download with ErrTooLarge. A short DATA reply is
// answered by asking again for exactly the missing range, so the output has
// no gap and no repeat.
//
// When ctx ends, Download sends nothing new, reads the replies still owed
// (at most 8), closes the handle and returns ctx.Err(); the session stays
// usable. If the caller closes the stream instead, Download returns
// ctx.Err() and the Client is spent.
func (c *Client) Download(ctx context.Context, path string, limit int64, start func(size int64) error, write func([]byte) error) (int64, error) {
	if err := checkPath(path); err != nil {
		return 0, err
	}
	if limit < 0 {
		return 0, ErrTooLarge
	}
	if err := c.enter(); err != nil {
		return 0, err
	}
	defer c.leave()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	id := c.begin(typeOpen)
	c.putString(path)
	c.putU32(openRead)
	c.putU32(0)
	h, err := c.openReply(id)
	if err != nil {
		return 0, ctxErr(ctx, err)
	}
	d := downloader{ctx: ctx, c: c, h: h, limit: uint64(limit), write: write}
	err = d.run(start)
	if !c.broken {
		if cerr := c.closeHandle(h); err == nil {
			err = cerr
		}
	}
	n := toInt64(d.done)
	if err != nil {
		return n, ctxErr(ctx, err)
	}
	return n, nil
}

func (d *downloader) run(start func(int64) error) error {
	c := d.c
	id := c.begin(typeFstat)
	c.putBytes(d.h)
	typ, body, err := c.call(id)
	if err != nil {
		return err
	}
	a, err := c.attrsReply(typ, body)
	if err != nil {
		return err
	}
	var size int64
	if a.HasSize {
		if a.Size > d.limit {
			return ErrTooLarge
		}
		size = toInt64(a.Size)
	}
	if err := start(size); err != nil {
		return err
	}
	stop := d.ctx.Err()
	for i := 0; stop == nil && i < maxInFlight; i++ {
		stop = d.assign(&d.slots[i])
	}
	for stop == nil && !d.ended {
		if stop = d.ctx.Err(); stop == nil {
			stop = d.step()
		}
	}
	if c.broken {
		return stop
	}
	// Every READ sent is owed a reply; reading them keeps the stream in step
	// for the CLOSE that follows.
	if err := d.drain(); err != nil {
		return err
	}
	return stop
}

// assign gives a free slot the next chunk, unless EOF was seen or the chunk
// would start past the limit. The last chunk reaches one byte past the
// limit, so a file that is too large is noticed without reading further.
func (d *downloader) assign(s *readSlot) error {
	if d.eof || d.next > d.limit {
		return nil
	}
	if err := d.ctx.Err(); err != nil {
		return err
	}
	s.off = d.next
	s.want = uint32(min(ChunkSize, d.limit-d.next+1))
	s.have = 0
	d.next += uint64(s.want)
	return d.request(s)
}

// request asks for the part of the slot not yet received.
func (d *downloader) request(s *readSlot) error {
	c := d.c
	s.id = c.begin(typeRead)
	s.asked = s.want - s.have
	c.putBytes(d.h)
	c.putU64(s.off + uint64(s.have))
	c.putU32(s.asked)
	if err := c.send(); err != nil {
		return err
	}
	s.busy = true
	d.active++
	return nil
}

func (d *downloader) slotFor(id uint32) *readSlot {
	for i := range d.slots {
		if s := &d.slots[i]; s.busy && s.id == id {
			return s
		}
	}
	return nil
}

// receive reads one reply owed to a slot and frees that slot's request.
func (d *downloader) receive() (*readSlot, byte, []byte, error) {
	typ, id, body, err := d.c.reply()
	if err != nil {
		return nil, 0, nil, err
	}
	s := d.slotFor(id)
	if s == nil {
		return nil, 0, nil, d.c.fail("reply to a request not in flight")
	}
	s.busy = false
	d.active--
	return s, typ, body, nil
}

// parse checks a reply to READ. It returns the data, or eof, or an error.
func (d *downloader) parse(s *readSlot, typ byte, body []byte) ([]byte, bool, error) {
	c := d.c
	switch typ {
	case typeData:
		r := reader{b: body}
		data := r.str(int(s.asked))
		// An empty DATA would make no progress and could repeat forever.
		if r.bad || len(r.b) != 0 || len(data) == 0 {
			return nil, false, c.fail("malformed DATA")
		}
		return data, false, nil
	case typeStatus:
		code, err := c.statusOf(body)
		switch {
		case err != nil:
			return nil, false, err
		case code == StatusEOF:
			return nil, true, nil
		case code == statusOK:
			return nil, false, c.fail("status OK where data was expected")
		}
		return nil, false, &StatusError{Code: code}
	}
	return nil, false, c.fail("unexpected reply to READ")
}

func (d *downloader) step() error {
	s, typ, body, err := d.receive()
	if err != nil {
		return err
	}
	data, eof, err := d.parse(s, typ, body)
	if err != nil {
		return err
	}
	if eof {
		s.eof = true
		d.eof = true
		return d.advance()
	}
	n := u32(len(data))
	if s == &d.slots[d.head] && s.have == 0 {
		// The next bytes in file order: hand them over without a copy.
		if err := d.deliver(data); err != nil {
			return err
		}
		s.off += uint64(n)
		s.want -= n
	} else {
		if s.buf == nil {
			s.buf = make([]byte, ChunkSize)
		}
		copy(s.buf[s.have:], data)
		s.have += n
	}
	if s.have < s.want {
		// A short reply: ask again for exactly the missing range.
		if err := d.request(s); err != nil {
			return err
		}
	}
	return d.advance()
}

// advance delivers what the head slot holds and moves the head past every
// finished slot, giving each the next chunk.
func (d *downloader) advance() error {
	for {
		s := &d.slots[d.head]
		if s.have > 0 {
			if err := d.deliver(s.buf[:s.have]); err != nil {
				return err
			}
			s.off += uint64(s.have)
			s.want -= s.have
			s.have = 0
		}
		switch {
		case s.busy:
			return nil
		case s.eof:
			d.ended = true
			return nil
		case s.want > 0:
			// Unreachable: a short reply is asked again at once. Waiting
			// here would wait for a reply that is never coming.
			return errState
		}
		if err := d.assign(s); err != nil {
			return err
		}
		d.head = (d.head + 1) % maxInFlight
		if d.idle() {
			// Unreachable: the last chunk ends past the limit or at EOF,
			// and both stop the loop before every slot is empty.
			return errState
		}
	}
}

func (d *downloader) idle() bool {
	for i := range d.slots {
		if s := &d.slots[i]; s.busy || s.want > 0 || s.eof {
			return false
		}
	}
	return true
}

// toInt64 converts a count that never passes an int64 limit.
func toInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		panic("sftpclient: count out of range")
	}
	return int64(v)
}

// deliver hands bytes to write. Several early chunks can become ready at
// once, so the context is checked before each, not only between packets.
func (d *downloader) deliver(p []byte) error {
	if uint64(len(p)) > d.limit-d.done {
		return ErrTooLarge
	}
	if err := d.ctx.Err(); err != nil {
		return err
	}
	if err := d.write(p); err != nil {
		return err
	}
	d.done += uint64(len(p))
	return nil
}

// drain reads the replies still owed and drops their data. Only a broken
// stream is an error here; the transfer already has its result.
func (d *downloader) drain() error {
	for d.active > 0 {
		s, typ, body, err := d.receive()
		if err != nil {
			return err
		}
		if _, _, err := d.parse(s, typ, body); err != nil && d.c.broken {
			return err
		}
	}
	return nil
}

// Upload creates path, which must not exist yet (WRITE|CREAT|EXCL), and
// writes exactly size bytes taken from next. Each call of next returns the
// following chunk of 1 to ChunkSize bytes, or an error; io.EOF before size
// bytes is an error. The chunk is copied before next is called again.
// Up to 8 WRITEs are in flight, and Upload returns only after every one is
// acknowledged and the handle is closed.
//
// size over limit is refused with ErrTooLarge before anything is sent. On a
// failure after OPEN the handle is closed while the stream is sound, but
// the partial file is left for the caller to remove. Cancellation works as
// for Download; next should also return when ctx ends.
func (c *Client) Upload(ctx context.Context, path string, size, limit int64, next func() ([]byte, error)) error {
	if err := checkPath(path); err != nil {
		return err
	}
	if size < 0 {
		return errSize
	}
	if size > limit {
		return ErrTooLarge
	}
	if err := c.enter(); err != nil {
		return err
	}
	defer c.leave()
	if err := ctx.Err(); err != nil {
		return err
	}
	id := c.begin(typeOpen)
	c.putString(path)
	c.putU32(openWrite | openCreat | openExcl)
	c.putU32(0)
	h, err := c.openReply(id)
	if err != nil {
		return ctxErr(ctx, err)
	}
	err = c.upload(ctx, h, uint64(size), next)
	if !c.broken {
		if cerr := c.closeHandle(h); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return ctxErr(ctx, err)
	}
	return nil
}

func (c *Client) upload(ctx context.Context, h []byte, size uint64, next func() ([]byte, error)) error {
	var (
		ids    [maxInFlight]uint32
		used   [maxInFlight]bool
		active int
		off    uint64
		stop   error
	)
	for {
		for stop == nil && active < maxInFlight && off < size {
			if stop = ctx.Err(); stop != nil {
				break
			}
			chunk, err := next()
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			if err == nil {
				// next may have waited long; data after a cancel is not sent.
				err = ctx.Err()
			}
			if err != nil {
				stop = err
				break
			}
			if len(chunk) == 0 || len(chunk) > ChunkSize || uint64(len(chunk)) > size-off {
				stop = errChunk
				break
			}
			id := c.begin(typeWrite)
			c.putBytes(h)
			c.putU64(off)
			c.putBytes(chunk)
			if err := c.send(); err != nil {
				return err
			}
			for i := range used {
				if !used[i] {
					ids[i], used[i] = id, true
					break
				}
			}
			active++
			off += uint64(len(chunk))
		}
		if active == 0 {
			return stop
		}
		typ, id, body, err := c.reply()
		if err != nil {
			return err
		}
		found := false
		for i := range used {
			if used[i] && ids[i] == id {
				used[i], found = false, true
				break
			}
		}
		if !found {
			return c.fail("reply to a request not in flight")
		}
		active--
		if typ != typeStatus {
			return c.fail("expected STATUS")
		}
		code, err := c.statusOf(body)
		if err != nil {
			return err
		}
		if code != statusOK && stop == nil {
			stop = &StatusError{Code: code}
		}
		if stop == nil {
			stop = ctx.Err()
		}
	}
}
