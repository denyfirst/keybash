package rdplab

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

// The legacy profile has a fixed viewport; the manager workspace adds bounded
// text/display controls. Neither admits arbitrary streams, URLs or parameters.
type viewerLayer struct{ width, height, depth int }
type viewerImage struct {
	layer, x, y int
	pixels      []byte
}
type viewerStream struct {
	native                *nativeStream
	workspace             bool
	layers                map[int]viewerLayer // owned by the single output reader
	images                map[string]*viewerImage
	imageBytes            int
	decode, render        pacer               // owned by the single output reader
	clock                 func() time.Time    // nil means time.Now; tests supply a fake
	sleep                 func(time.Duration) // nil means time.Sleep
	pending               bytes.Buffer
	ready                 bytes.Reader
	writeMu               sync.Mutex
	metaMu                sync.Mutex
	acks                  map[string]int
	syncs                 []int // frames sent and not yet answered, oldest first
	newestSync            int   // the newest frame timestamp sent; -1 before any
	keys                  map[uint32]bool
	heard                 atomic.Int64 // when the browser last sent a valid instruction, in Unix nanoseconds
	done                  chan struct{}
	closeOnce             sync.Once
	closed                atomic.Bool
	width, height         atomic.Int64
	inputClip, outputClip clipboard
	pastes, copies        pacer
	resizeWindow          time.Time
	resizeCount           int
}

func newViewerStream(native *nativeStream) *viewerStream {
	s := &viewerStream{native: native, layers: map[int]viewerLayer{0: {1024, 768, 0}},
		images: make(map[string]*viewerImage), acks: make(map[string]int), newestSync: -1, keys: make(map[uint32]bool), done: make(chan struct{})}
	s.heard.Store(time.Now().UnixNano())
	s.width.Store(1024)
	s.height.Store(768)
	var initial bytes.Buffer
	s.workspace = native != nil && native.workspace
	if s.workspace {
		_ = writeInstruction(&initial, instruction{"keybash", "1", "text", "display-update"})
	}
	_ = writeInstruction(&initial, instruction{"size", "0", "1024", "768"})
	s.ready.Reset(initial.Bytes())
	return s
}
func (s *viewerStream) Close() error {
	s.closed.Store(true)
	s.closeOnce.Do(func() { close(s.done) })
	s.native.close()
	s.inputClip.close()
	s.outputClip.close()
	s.metaMu.Lock()
	clear(s.keys)
	clear(s.acks)
	s.syncs = nil
	s.metaMu.Unlock()
	return nil
}

// Reason says, with a fixed word, why the desktop ended by itself. Only guacd's
// status code is read (guacd 1.6, src/protocols/rdp/error.c), never its
// message; a failure without a word of its own gives none.
func (s *viewerStream) Reason() terminalweb.Reason {
	if s.native == nil {
		return ""
	}
	failure, _ := s.native.failure.Load().(string)
	switch failure {
	case "native status 769": // CLIENT_UNAUTHORIZED: wrong user name or password
		return terminalweb.ReasonCredentials
	case "native status 771": // CLIENT_FORBIDDEN: locked, disabled, expired or not allowed
		return terminalweb.ReasonAccount
	case "native status 521": // SESSION_CONFLICT: another connection took the session
		return terminalweb.ReasonTakenOver
	case "native status 522", "native status 523", "disconnect": // SESSION_TIMEOUT, SESSION_CLOSED, or no error at all
		return terminalweb.ReasonRemoteEnded
	case "native status 514", "native status 519", "native status 520": // UPSTREAM_TIMEOUT, _NOT_FOUND, _UNAVAILABLE
		return terminalweb.ReasonUnreachable
	case "native status 776": // CLIENT_TIMEOUT: guacd heard nothing from the gateway
		return terminalweb.ReasonNotResponding
	case "output quota", "unexpected instruction", "unsupported drawing property", "invalid owner notice", "unexpected parameter request", "workspace clipboard schema":
		return terminalweb.ReasonRefused
	}
	if strings.HasPrefix(failure, "viewer drawing ") {
		return terminalweb.ReasonRefused
	}
	return ""
}

// guacd ends a user it hears nothing from for 15 seconds ("User is not
// responding"). Its user is this gateway, not the browser, and guacd's own
// keep-alives stop here, so the browser's keep-alive timer was all that kept
// the link open; a hidden page runs that timer as rarely as once a minute, and
// a real Windows desktop ended whenever someone switched to another program.
// The gateway now keeps its own link alive, but only while the browser has
// been heard from within browserQuiet: a browser silent for longer (a closed
// laptop, a frozen tab) still lets guacd end the session. Keybash's idle limit
// counts only keys and mouse, which these never are.
const (
	nativeKeepAlive = 5 * time.Second
	browserQuiet    = 2 * time.Minute
)

// startKeepAlive runs keepAlive on a real ticker until the stream closes.
func (s *viewerStream) startKeepAlive() *viewerStream {
	ticker := time.NewTicker(nativeKeepAlive)
	go func() {
		defer ticker.Stop()
		s.keepAlive(ticker.C)
	}()
	return s
}

// keepAlive sends guacd a nop at each tick while the browser has been heard
// from within browserQuiet, and returns once the stream closes.
func (s *viewerStream) keepAlive(ticks <-chan time.Time) {
	for {
		select {
		case <-s.done:
			return
		case <-ticks:
			if s.now().Sub(time.Unix(0, s.heard.Load())) > browserQuiet {
				continue
			}
			if s.send(instruction{"nop"}) != nil {
				_ = s.Close()
				return
			}
		}
	}
}
func (s *viewerStream) ReadStderr([]byte) (int, error) { return 0, io.EOF }
func (s *viewerStream) Resize(uint32, uint32) error    { _ = s.Close(); return errNative }
func (s *viewerStream) revoked() bool                  { return s.closed.Load() || s.native.revoked() }

func canonicalNumber(raw string, low, high int) (int, bool) {
	n, err := strconv.Atoi(raw)
	return n, err == nil && n >= low && n <= high && strconv.Itoa(n) == raw
}

func (s *viewerStream) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// spend paces work against a budget; it refuses only a single cost larger
// than the burst, or a stream revoked while waiting.
func (s *viewerStream) spend(budget *pacer, cost int, burst, perSecond float64) bool {
	wait, ok := budget.reserve(cost, burst, perSecond, s.now())
	if !ok {
		return false
	}
	sleep := time.Sleep
	if s.sleep != nil {
		sleep = s.sleep
	}
	return pause(wait, s.revoked, sleep)
}

func (s *viewerStream) renderWork(pixels int) bool {
	return s.spend(&s.render, pixels, renderBurst, renderPerSecond)
}

type viewerBoundedWriter struct {
	buffer *bytes.Buffer
	limit  int
}

func (w viewerBoundedWriter) Write(data []byte) (int, error) {
	if len(data) > w.limit-w.buffer.Len() {
		return 0, errNative
	}
	return w.buffer.Write(data)
}

// guacd numbers buffers from libguac's pool, which hands out new numbers until
// 1024 have been used and only then reuses freed ones, so a buffer's number
// says nothing about how many are live: a real Windows desktop reached -33 with
// 30 live, and 90 later. What bounds the browser's memory is the pixel budget
// in fit, each layer rounded up to 64 by 64. It is sized from what a real
// Windows Server 2025 desktop needs, not from the 1024 by 768 lab: at full HD
// guacd copies the whole display into a buffer of the same size, and FreeRDP
// may hold up to 129 pointers of up to 384 by 384 (the native build caps the
// cache at 32; FreeRDP keeps the server's large-pointer sizes). 16 Mi pixels,
// at most 64 MiB of canvas, holds two full-HD surfaces beside every pointer
// FreeRDP could hold at that cap. The live count only caps per-canvas overhead
// below that, and a number only has to stay within what guacd can reach.
const (
	viewerLayers       = 1024     // live layers and buffers at once, the display included
	viewerPixels       = 16 << 20 // every live layer's pixels, rounded up to 64 by 64
	viewerLowestBuffer = -4096    // past 1024 + viewerLayers
	viewerHighestLayer = 32
	viewerSyncs        = 128 // unanswered frames remembered at once
)

// normalizedPNG re-encodes a decoded image for the browser within limit bytes.
// The fastest level first: re-encoding cost several times decoding on a real
// desktop, and a few more bytes are cheap next to that delay. When that does
// not fit, the default level, so speed never refuses an image that fitted.
func normalizedPNG(decoded image.Image, limit int) ([]byte, bool) {
	var out bytes.Buffer
	fast := png.Encoder{CompressionLevel: png.BestSpeed}
	if fast.Encode(viewerBoundedWriter{&out, limit}, decoded) == nil {
		return out.Bytes(), true
	}
	out.Reset()
	if png.Encode(viewerBoundedWriter{&out, limit}, decoded) == nil {
		return out.Bytes(), true
	}
	return nil, false
}

func (s *viewerStream) layer(raw string) (int, bool) {
	id, ok := canonicalNumber(raw, viewerLowestBuffer, viewerHighestLayer)
	if !ok {
		return 0, false
	}
	if _, exists := s.layers[id]; !exists {
		if len(s.layers) >= viewerLayers {
			return 0, false
		}
		s.layers[id] = viewerLayer{}
	}
	return id, true
}

// Account for the renderer's 64-pixel canvas rounding and buffer autosizing.
func (s *viewerStream) fit(id, x, y, w, h int, exact bool) bool {
	mw, mh := s.bounds()
	if x < 0 || y < 0 || w < 0 || h < 0 || x+w > mw || y+h > mh {
		return false
	}
	layer := s.layers[id]
	if exact {
		if !s.renderWork(w * h) {
			return false
		}
		layer.width, layer.height = w, h
	} else if id < 0 {
		layer.width, layer.height = max(layer.width, x+w), max(layer.height, y+h)
	}
	pixels := 0
	for index, l := range s.layers {
		if index == id {
			l = layer
		}
		pixels += ((l.width + 63) / 64 * 64) * ((l.height + 63) / 64 * 64)
	}
	if pixels > viewerPixels {
		return false
	}
	s.layers[id] = layer
	return true
}

func (s *viewerStream) drawing(in instruction) bool {
	mw, mh := s.bounds()
	if len(in) == 0 {
		return false
	}
	num := func(i, low, high int) (int, bool) {
		if i >= len(in) {
			return 0, false
		}
		return canonicalNumber(in[i], low, high)
	}
	layer := func(i int) (int, bool) {
		if i >= len(in) {
			return 0, false
		}
		return s.layer(in[i])
	}
	xy := func(id, xi, yi, wi, hi int) bool {
		x, a := num(xi, 0, mw)
		y, b := num(yi, 0, mh)
		w, c := num(wi, 0, mw)
		h, d := num(hi, 0, mh)
		return a && b && c && d && s.fit(id, x, y, w, h, false)
	}
	switch in[0] {
	case "size":
		id, a := layer(1)
		w, b := num(2, 0, mw)
		h, c := num(3, 0, mh)
		valid := len(in) == 4 && a && b && c && (id != 0 || (!s.workspace && w == 1024 && h == 768 || s.workspace && w >= 64 && h >= 64)) && s.fit(id, 0, 0, w, h, true)
		if valid && id == 0 {
			s.width.Store(int64(w))
			s.height.Store(int64(h))
		}
		return valid
	case "img":
		id, a := layer(3)
		_, b := num(2, 0, 15)
		x, c := num(5, 0, mw)
		y, d := num(6, 0, mh)
		if len(in) != 7 || !a || !b || !c || !d || !streamID(in[1]) || in[4] != "image/png" || len(s.images) >= 8 || s.images[in[1]] != nil || s.outputClip.matches(in[1]) {
			return false
		}
		s.images[in[1]] = &viewerImage{layer: id, x: x, y: y}
		return true
	case "blob":
		if len(in) != 3 || s.images[in[1]] == nil {
			return false
		}
		data, err := base64.StdEncoding.Strict().DecodeString(in[2])
		image := s.images[in[1]]
		if err != nil || base64.StdEncoding.EncodeToString(data) != in[2] || len(data) == 0 || len(image.pixels)+len(data) > 256*1024 || s.imageBytes+len(data) > 1024*1024 {
			return false
		}
		image.pixels = append(image.pixels, data...)
		s.imageBytes += len(data)
		// Acknowledge the native blob to prevent a staged image from deadlocking.
		// Browser acks are checked separately and never forwarded a second time.
		return s.send(instruction{"ack", in[1], "OK", "0"}) == nil
	case "end":
		if len(in) != 2 || s.images[in[1]] == nil {
			return false
		}
		image := s.images[in[1]]
		cfg, err := png.DecodeConfig(bytes.NewReader(image.pixels))
		if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > mw || cfg.Height > mh || !s.fit(image.layer, image.x, image.y, cfg.Width, cfg.Height, false) {
			return false
		}
		pixels := cfg.Width * cfg.Height
		if !s.spend(&s.decode, pixels, decodeBurst, decodePerSecond) || !s.renderWork(pixels) {
			return false
		}
		decoded, err := png.Decode(bytes.NewReader(image.pixels))
		if err != nil {
			return false
		}
		// Re-encode only the decoded static image. Ancillary metadata, APNG
		// frames and trailing/polyglot bytes never reach the browser decoder.
		normalized, ok := normalizedPNG(decoded, 256*1024)
		if !ok {
			return false
		}
		chunks := (len(normalized) + 12*1024 - 1) / (12 * 1024)
		// The browser's Guacamole client never acknowledges image blobs: neither
		// of its image readers sends an ack. So nothing here waits for one; a
		// count that refused at 128 unacknowledged chunks ended real Windows
		// sessions. Flow to the browser is the relay's credit window. The count
		// only lets a browser ack chunks it was sent, should one ever do so, and
		// it stays bounded: 128 streams, 128 chunks each.
		s.metaMu.Lock()
		if _, known := s.acks[in[1]]; known || len(s.acks) < 128 {
			s.acks[in[1]] = min(s.acks[in[1]]+chunks, 128)
		}
		s.metaMu.Unlock()
		for data := normalized; len(data) > 0; {
			n := min(len(data), 12*1024)
			if writeInstruction(viewerBoundedWriter{&s.pending, 2 * 1024 * 1024}, instruction{"blob", in[1], base64.StdEncoding.EncodeToString(data[:n])}) != nil {
				return false
			}
			data = data[n:]
		}
		s.imageBytes -= len(image.pixels)
		clear(image.pixels)
		delete(s.images, in[1])
		return true
	case "copy", "transfer":
		_, a := layer(1)
		dst, b := layer(7)
		_, c := num(6, 0, 15)
		if len(in) != 10 || !a || !b || !c {
			return false
		}
		for i, hi := range map[int]int{2: mw, 3: mh, 4: mw, 5: mh, 8: mw, 9: mh} {
			if _, ok := num(i, 0, hi); !ok {
				return false
			}
		}
		w, _ := num(4, 0, mw)
		h, _ := num(5, 0, mh)
		x, _ := num(8, 0, mw)
		y, _ := num(9, 0, mh)
		return s.fit(dst, x, y, w, h, false) && s.renderWork(w*h)
	case "cursor":
		_, a := layer(3)
		if len(in) != 8 || !a {
			return false
		}
		for i, hi := range map[int]int{1: 256, 2: 256, 4: mw, 5: mh, 6: 256, 7: 256} {
			if _, ok := num(i, 0, hi); !ok {
				return false
			}
		}
		w, _ := num(6, 0, 256)
		h, _ := num(7, 0, 256)
		return s.renderWork(w * h)
	case "cfill":
		_, a := num(1, 0, 15)
		id, b := layer(2)
		if len(in) != 7 || !a || !b {
			return false
		}
		for i := 3; i < 7; i++ {
			if _, ok := num(i, 0, 255); !ok {
				return false
			}
		}
		l := s.layers[id]
		return s.renderWork(l.width * l.height)
	case "rect":
		id, ok := layer(1)
		return len(in) == 6 && ok && xy(id, 2, 3, 4, 5)
	case "start", "line":
		id, a := layer(1)
		x, b := num(2, 0, mw)
		y, c := num(3, 0, mh)
		return len(in) == 4 && a && b && c && s.fit(id, x, y, 0, 0, false)
	case "clip", "close", "identity", "reset", "push", "pop":
		id, ok := layer(1)
		if len(in) != 2 || !ok {
			return false
		}
		l := s.layers[id]
		if in[0] == "push" {
			if l.depth >= 8 {
				return false
			}
			l.depth++
		}
		if in[0] == "pop" {
			if l.depth == 0 {
				return false
			}
			l.depth--
		}
		if in[0] == "reset" {
			l.depth = 0
		}
		s.layers[id] = l
		return true
	case "dispose":
		if len(in) != 2 {
			return false
		}
		id, ok := canonicalNumber(in[1], viewerLowestBuffer, viewerHighestLayer)
		if !ok || id == 0 {
			return false
		}
		for _, image := range s.images {
			if image.layer == id {
				return false
			}
		}
		delete(s.layers, id)
		return true
	case "mouse":
		_, a := num(1, 0, int(s.width.Load())-1)
		_, b := num(2, 0, int(s.height.Load())-1)
		_, c := num(3, 0, 31)
		_, d := num(4, 0, 1<<53-1)
		return len(in) == 5 && a && b && c && d
	case "sync":
		if len(in) != 2 && len(in) != 3 {
			return false
		}
		timestamp, ok := num(1, 0, 1<<53-1)
		if !ok {
			return false
		}
		if len(in) == 3 {
			if _, ok := num(2, 0, 8192); !ok {
				return false
			}
		}
		// A browser may fall behind on frames, as a hidden page does, so the
		// oldest unanswered frame is forgotten rather than the session ended.
		// Only answers to frames actually sent ever reach guacd.
		s.metaMu.Lock()
		defer s.metaMu.Unlock()
		if len(s.syncs) >= viewerSyncs {
			s.syncs = append(s.syncs[:0], s.syncs[1:]...)
		}
		s.syncs = append(s.syncs, timestamp)
		s.newestSync = max(s.newestSync, timestamp)
		return true
	}
	return false // No remote names, arbitrary transforms or auxiliary streams.
}

func (s *viewerStream) Read(data []byte) (int, error) {
	if s.revoked() {
		_ = s.Close()
		return 0, errNative
	}
	for s.ready.Len() == 0 {
		in, err := s.native.next()
		if err != nil || s.revoked() {
			_ = s.Close()
			return 0, errNative
		}
		if in[0] == "name" {
			continue
		} // remote text never becomes browser UI/HTML
		handled, valid := s.clipboardOutput(in)
		if handled {
			if !valid {
				s.native.failure.Store("workspace clipboard schema")
				_ = s.Close()
				return 0, errNative
			}
			if s.pending.Len() > 0 && len(s.images) == 0 {
				s.ready.Reset(append([]byte(nil), s.pending.Bytes()...))
				s.pending.Reset()
			}
			continue
		}
		if !s.drawing(in) {
			s.native.failure.Store("viewer drawing " + in[0]) // next admits only fixed opcode names
			_ = s.Close()
			return 0, errNative
		}
		if in[0] != "blob" && writeInstruction(viewerBoundedWriter{&s.pending, 2 * 1024 * 1024}, in) != nil {
			_ = s.Close()
			return 0, errNative
		}
		if len(s.images) == 0 {
			s.ready.Reset(append([]byte(nil), s.pending.Bytes()...))
			s.pending.Reset()
		}
	}
	if s.revoked() {
		return 0, errNative
	}
	n, err := s.ready.Read(data)
	if s.revoked() {
		clear(data[:n])
		return 0, errNative
	}
	return n, err
}
func (s *viewerStream) send(in instruction) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.revoked() {
		return errNative
	}
	return writeInstruction(s.native.raw, in)
}
func (s *viewerStream) Write(data []byte) (int, error) {
	refuse := func() (int, error) { _ = s.Close(); return 0, errNative }
	if s.revoked() || len(data) == 0 || len(data) > 1024 && !s.workspace || len(data) > 8192 {
		return refuse()
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	in, err := readInstruction(reader)
	if err != nil {
		return refuse()
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return refuse()
	}
	if s.workspace && (in[0] == "clipboard" || in[0] == "blob" || in[0] == "end") {
		if !s.clipboardInput(in) {
			return refuse()
		}
		s.heard.Store(s.now().UnixNano())
		return len(data), nil
	}
	s.metaMu.Lock()
	valid, forward := false, false
	switch in[0] {
	case "size":
		if s.workspace && len(in) == 3 {
			w, a := canonicalNumber(in[1], 64, 1920)
			h, b := canonicalNumber(in[2], 64, 1080)
			now := time.Now()
			if now.Sub(s.resizeWindow) >= time.Second {
				s.resizeWindow = now
				s.resizeCount = 0
			}
			s.resizeCount++
			valid = a && b && w%2 == 0 && h%2 == 0 && s.resizeCount <= 4
			forward = valid
		}
	case "nop":
		valid, forward = len(in) == 1, len(in) == 1
	case "ack":
		if len(in) == 4 && in[2] == "OK" && in[3] == "0" && s.acks[in[1]] > 0 {
			s.acks[in[1]]--
			if s.acks[in[1]] == 0 {
				delete(s.acks, in[1])
			}
			valid = true
		}
	case "sync":
		// An answer to an unanswered frame goes to guacd. An answer to a frame
		// already answered or forgotten is dropped; one to a frame never sent
		// refuses.
		if len(in) == 2 {
			timestamp, ok := canonicalNumber(in[1], 0, 1<<53-1)
			valid = ok && timestamp <= s.newestSync
			for i, sent := range s.syncs {
				if valid && sent == timestamp {
					s.syncs = append(s.syncs[:i], s.syncs[i+1:]...)
					forward = true
					break
				}
			}
		}
	case "mouse":
		if len(in) == 4 {
			_, a := canonicalNumber(in[1], 0, int(s.width.Load())-1)
			_, b := canonicalNumber(in[2], 0, int(s.height.Load())-1)
			_, c := canonicalNumber(in[3], 0, 31)
			valid = a && b && c
			forward = valid
		}
	case "key":
		if len(in) == 3 {
			key, e := strconv.ParseUint(in[1], 10, 32)
			code := uint32(key)
			scalar := code & 0xffffff
			allowed := code >= 0x20 && code <= 0xff || code >= 0xff00 && code <= 0xffff || code >= 0x1000100 && code <= 0x110ffff && !(scalar >= 0xd800 && scalar <= 0xdfff)
			if e == nil && strconv.FormatUint(key, 10) == in[1] && allowed && (in[2] == "0" || in[2] == "1") {
				valid = true
				if in[2] == "1" {
					if !s.keys[code] && len(s.keys) >= 32 {
						valid = false
					} else {
						s.keys[code] = true
						forward = true
					}
				} else {
					forward = s.keys[code]
					delete(s.keys, code)
				}
			}
		}
	}
	s.metaMu.Unlock()
	if !valid {
		return refuse()
	}
	s.heard.Store(s.now().UnixNano())
	if forward && s.send(in) != nil {
		return refuse()
	}
	return len(data), nil
}

func (s *viewerStream) bounds() (int, int) {
	if s.workspace {
		return 1920, 1080
	}
	return 1024, 768
}

// The browser sees one completed, typed text notification, never a raw native
// clipboard stream. It can display this text but cannot automatically write it
// to the OS clipboard. Partial UTF-8 and image/clipboard ID collisions refuse.
func (s *viewerStream) clipboardOutput(in instruction) (bool, bool) {
	if !s.workspace || len(in) == 0 {
		return false, false
	}
	isClip := in[0] == "clipboard" || (in[0] == "blob" || in[0] == "end") && len(in) > 1 && s.outputClip.matches(in[1])
	if !isClip {
		return false, false
	}
	if len(in) < 2 || s.images[in[1]] != nil {
		return true, false
	}
	text, complete, e := s.outputClip.accept(in)
	if e != nil {
		return true, false
	}
	if complete {
		if !s.copies.allow(1, clipboardBurst, clipboardPerSecond, s.now()) || strings.ContainsRune(text, 0) {
			return true, false
		}
		if writeInstruction(viewerBoundedWriter{&s.pending, 2 * 1024 * 1024}, instruction{"keybash-clipboard", text}) != nil {
			return true, false
		}
	}
	return true, true
}
func (s *viewerStream) clipboardInput(in instruction) bool {
	if len(in) < 2 || in[1] != "0" {
		return false
	}
	text, complete, e := s.inputClip.accept(in)
	if e != nil {
		return false
	}
	if !complete {
		return true
	}
	if strings.ContainsRune(text, 0) {
		return false
	}
	s.metaMu.Lock()
	valid := s.pastes.allow(1, clipboardBurst, clipboardPerSecond, s.now())
	s.metaMu.Unlock()
	if !valid {
		return false
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.revoked() {
		return false
	}
	if writeInstruction(s.native.raw, instruction{"clipboard", "0", "text/plain"}) != nil {
		return false
	}
	for b := []byte(text); len(b) > 0; {
		if s.revoked() {
			return false
		}
		n := min(len(b), 512)
		if writeInstruction(s.native.raw, instruction{"blob", "0", base64.StdEncoding.EncodeToString(b[:n])}) != nil {
			return false
		}
		b = b[n:]
	}
	return !s.revoked() && writeInstruction(s.native.raw, instruction{"end", "0"}) == nil
}
