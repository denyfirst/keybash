package rdplab

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"image"
	"image/png"
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// The legacy profile has a fixed viewport; the manager workspace adds bounded
// text/display controls. Neither admits arbitrary streams, URLs or parameters.
type viewerLayer struct {
	width, height int
	path          viewerPath
}

// viewerPath is a layer's current path as the browser's canvas keeps it, by
// its bounds and its number of rects: a fill paints only inside the bounds and
// rasterizes every rect. A fill closes the path without clearing it, so
// another fill paints it again; the next rect after that begins a new path
// (guacamole-common-js Layer). Charging a fill for the whole layer instead took
// the render budget on every small fill: scrolling a 200% Windows desktop spent
// nine tenths of each second paused for pixels never drawn.
type viewerPath struct {
	x0, y0, x1, y1 int
	rects          int  // rects in the path; 0 means it is empty
	closed         bool // the next rect begins a new path
}

// viewerPathRects bounds the rects one path may hold. guacd 1.6 sends one rect
// and then fills it; display workers drawing on the same small non-opaque
// buffer at once can add one each before the first fill. A path of more would
// make every fill of it rasterize them all for the price of their bounds.
const viewerPathRects = 64

// add takes a rect's bounds into the path, beginning a new path if the last one
// was closed. It reports false when the path already holds viewerPathRects.
func (p viewerPath) add(x0, y0, x1, y1 int) (viewerPath, bool) {
	if p.closed || p.rects == 0 {
		return viewerPath{x0: x0, y0: y0, x1: x1, y1: y1, rects: 1}, true
	}
	if p.rects >= viewerPathRects {
		return p, false
	}
	return viewerPath{x0: min(p.x0, x0), y0: min(p.y0, y0), x1: max(p.x1, x1), y1: max(p.y1, y1), rects: p.rects + 1}, true
}

// canvas is the layer's canvas size: the renderer allocates it in multiples of
// 64 pixels.
func (l viewerLayer) canvas() (int, int) {
	return (l.width + 63) / 64 * 64, (l.height + 63) / 64 * 64
}

// fillPixels is what a fill can paint: the path's bounds within the layer's
// canvas.
func (l viewerLayer) fillPixels() int {
	if l.path.rects == 0 {
		return 0
	}
	cw, ch := l.canvas()
	w := max(0, min(l.path.x1, cw)-min(l.path.x0, cw))
	h := max(0, min(l.path.y1, ch)-min(l.path.y0, ch))
	return w * h
}

// boundedMask reports whether a channel mask's canvas operation changes only
// the pixels under what is drawn (guacamole-common-js Layer: 0x2
// destination-out, 0x6 source-atop, 0xA xor, 0xB destination-over, 0xE
// source-over, 0xF lighter). The others change the whole canvas outside the
// drawing too (0x1 destination-in, 0x4 source-in, 0x8 source-out, 0x9
// destination-atop, 0xC copy), and a mask the client does not map leaves the
// layer's previous operation in force, so those cost the whole canvas. guacd
// 1.6 draws with 0xE and 0x2, and uses 0x9 only on its small non-opaque buffers.
func boundedMask(mask int) bool {
	switch mask {
	case 0x2, 0x6, 0xA, 0xB, 0xE, 0xF:
		return true
	}
	return false
}

// drawPixels is the render cost of drawing area pixels on layer id with mask:
// the area for a bounded operation, else the whole canvas, and never less than
// the area.
func (s *viewerStream) drawPixels(id, mask, area int) int {
	if boundedMask(mask) {
		return area
	}
	cw, ch := s.layers[id].canvas()
	return max(area, cw*ch)
}

type viewerImage struct {
	layer, x, y, mask int
	limit             int // pngLimit of the size its header gives; 0 until the header has arrived
	pixels            []byte
}

// imageWorkers bounds the images rebuilt at once across every desktop: one per
// processor, so a busy desktop uses the machine without starving it.
var imageWorkers = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))

// maxImageJobs bounds the images one desktop has waiting to be rebuilt, and
// viewerImageBytes the compressed bytes they and the open images hold, each.
const maxImageJobs = 16

// viewerImages bounds the image streams open at once. guacd streams one PNG per
// display worker at the same time (the native build runs four, prepare.py);
// what bounds memory is imageBytes, not the count.
const viewerImages = 32

// viewerImageBytes is what open images may hold together, and again what images
// waiting to be rebuilt may hold, at full HD; times areaScale like every
// full-HD budget. Eight of guacd's largest tiles, 512 by 512 photographs.
const viewerImageBytes = 8 << 20

// pngLimit is the largest PNG of a width by height image: every row stored
// unfiltered at four bytes a pixel, with room for zlib's stored blocks and the
// chunks around them. guacd's PNG of a photograph comes close to it; a larger
// file is not a picture of that size.
func pngLimit(width, height int) int {
	raw := height * (1 + 4*width)
	return raw + raw/64 + 4096
}

// pngHeader reads a PNG's size from its first 33 bytes, which hold the
// signature and the header chunk, and refuses what guacd never writes: 16-bit
// samples and interlacing, which double or add decoding memory. The full
// decode at the image's end checks the rest.
func pngHeader(data []byte) (width, height int, ok bool) {
	if len(data) < 33 || string(data[:8]) != "\x89PNG\r\n\x1a\n" || binary.BigEndian.Uint32(data[8:12]) != 13 || string(data[12:16]) != "IHDR" {
		return 0, 0, false
	}
	w, h := binary.BigEndian.Uint32(data[16:20]), binary.BigEndian.Uint32(data[20:24])
	depth, kind := data[24], data[25]
	if w == 0 || h == 0 || w > 1<<16 || h > 1<<16 || data[26] != 0 || data[27] != 0 || data[28] != 0 {
		return 0, 0, false
	}
	switch {
	case depth == 8 && (kind == 0 || kind == 2 || kind == 3 || kind == 4 || kind == 6):
	case (depth == 1 || depth == 2 || depth == 4) && (kind == 0 || kind == 3):
	default:
		return 0, 0, false
	}
	return int(w), int(h), true
}

// imageJob is one image decoded and written again off the reader, while the
// images after it are read; its blobs take its place in the output.
type imageJob struct {
	stream string
	limit  int // the rebuilt PNG's largest size: pngLimit of its own size
	size   int // the compressed bytes it holds until it is rebuilt
	done   chan struct{}
	blobs  []byte
	chunks int
	ok     bool
}

// viewerPart is output held in order: bytes ready to go, or an image's job.
type viewerPart struct {
	data []byte
	job  *imageJob
}

// rebuild decodes the PNG and writes it again as the browser's blobs. Nothing
// of the sender's file survives: only its pixels, through normalizedPNG.
func (j *imageJob) rebuild(stream string, data []byte, revoked func() bool) {
	defer close(j.done)
	imageWorkers <- struct{}{}
	defer func() { <-imageWorkers }()
	defer clear(data)
	if revoked() {
		return
	}
	decoded, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return
	}
	// Re-encode only the decoded static image. Ancillary metadata, APNG
	// frames and trailing/polyglot bytes never reach the browser decoder.
	normalized, ok := normalizedPNG(decoded, j.limit)
	if !ok {
		return
	}
	var out bytes.Buffer
	for rest := normalized; len(rest) > 0; {
		n := min(len(rest), 12*1024)
		if writeInstruction(&out, instruction{"blob", stream, base64.StdEncoding.EncodeToString(rest[:n])}) != nil {
			return
		}
		rest = rest[n:]
		j.chunks++
	}
	j.blobs, j.ok = out.Bytes(), true
}

type viewerStream struct {
	native         *nativeStream
	workspace      bool
	layers         map[int]viewerLayer // owned by the single output reader
	images         map[string]*viewerImage
	imageBytes     int                 // compressed bytes the open images hold
	jobBytes       int                 // compressed bytes the images waiting to be rebuilt hold
	decode, render pacer               // owned by the single output reader
	clock          func() time.Time    // nil means time.Now; tests supply a fake
	sleep          func(time.Duration) // nil means time.Sleep
	pending        bytes.Buffer
	ready          bytes.Reader
	// Images being rebuilt off the reader, with the output held behind each in
	// order, and what is ready for the browser (owned by the single reader).
	parts                 []viewerPart
	jobs, held            int // images being rebuilt; bytes held behind them
	out                   []byte
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
	dpi                   int // the DPI the desktop opened at; fixed for the session
	area                  int // areaScale(dpi): every full-HD budget is multiplied by it
	inputClip, outputClip clipboard
	pastes, copies        pacer
	resizeWindow          time.Time
	resizeCount           int
}

func newViewerStream(native *nativeStream) *viewerStream {
	// A workspace starts at the size and DPI its desktop was opened at; the lab
	// and anything else at its fixed 1024 by 768 at 96.
	w, h, dpi := 1024, 768, 96
	if native != nil && native.workspace && desktopSize(native.width, native.height, native.dpi) {
		w, h, dpi = native.width, native.height, defaultDPI(native.dpi)
	}
	s := &viewerStream{native: native, dpi: dpi, area: areaScale(dpi), layers: map[int]viewerLayer{0: {width: w, height: h}},
		images: make(map[string]*viewerImage), acks: make(map[string]int), newestSync: -1, keys: make(map[uint32]bool), done: make(chan struct{})}
	s.outputClip.dropOversize = true
	s.heard.Store(time.Now().UnixNano())
	s.width.Store(int64(w))
	s.height.Store(int64(h))
	var initial bytes.Buffer
	s.workspace = native != nil && native.workspace
	if s.workspace {
		_ = writeInstruction(&initial, instruction{"keybash", "1", "text", "display-update"})
	}
	_ = writeInstruction(&initial, instruction{"size", "0", strconv.Itoa(w), strconv.Itoa(h)})
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
	return s.spend(&s.render, pixels, float64(renderBurst*s.area), float64(renderPerSecond*s.area))
}

// heldLimit bounds the output held behind images being rebuilt or still open,
// besides the image staging: 2 MiB at full HD, times areaScale like every
// full-HD budget.
func (s *viewerStream) heldLimit() int {
	return (2 << 20) * s.area
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
	viewerPointer      = 384 // the largest pointer FreeRDP accepts, each side
)

// normalizedPNG re-encodes a decoded image for the browser within limit bytes.
// Our own minimal encoder first (fastpng.go): re-encoding cost several times
// decoding on a real desktop, and that delay is what a person sees. Then the
// standard encoder, fastest level and default, so speed never refuses an
// image that fitted.
func normalizedPNG(decoded image.Image, limit int) ([]byte, bool) {
	if out, ok := fastPNG(decoded, limit); ok {
		return out, true
	}
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
		// The browser creates a visible layer at the display's size the first
		// time it is named, and that size may still be one a pending resize is
		// about to replace, so it is counted at the session's largest display
		// until a size instruction sets it. guacd 1.6 draws RDP on the default
		// layer and buffers only. Buffers start empty and grow with what is
		// drawn into them.
		if id > 0 {
			mw, mh := s.bounds()
			if !s.fit(id, 0, 0, mw, mh, true) {
				delete(s.layers, id)
				return 0, false
			}
		}
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
	if pixels > viewerPixels*s.area {
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
		mask, b := num(2, 0, 15)
		x, c := num(5, 0, mw)
		y, d := num(6, 0, mh)
		if len(in) != 7 || !a || !b || !c || !d || !streamID(in[1]) || in[4] != "image/png" || len(s.images) >= viewerImages || s.images[in[1]] != nil || s.outputClip.matches(in[1]) {
			return false
		}
		s.images[in[1]] = &viewerImage{layer: id, x: x, y: y, mask: mask}
		return true
	case "blob":
		if len(in) != 3 || s.images[in[1]] == nil {
			return false
		}
		data, err := base64.StdEncoding.Strict().DecodeString(in[2])
		image := s.images[in[1]]
		if err != nil || base64.StdEncoding.EncodeToString(data) != in[2] || len(data) == 0 || s.imageBytes+len(data) > viewerImageBytes*s.area {
			return false
		}
		image.pixels = append(image.pixels, data...)
		s.imageBytes += len(data)
		// An image may hold what a PNG of its own size can: a photograph's
		// 512 by 512 tile is over 400 KiB, past the fixed 256 KiB this was.
		if image.limit == 0 && len(image.pixels) >= 33 {
			w, h, ok := pngHeader(image.pixels)
			if !ok || w > mw || h > mh {
				return false
			}
			image.limit = pngLimit(w, h)
		}
		if image.limit != 0 && len(image.pixels) > image.limit {
			return false
		}
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
		if !s.spend(&s.decode, pixels, float64(decodeBurst*s.area), float64(decodePerSecond*s.area)) || !s.renderWork(s.drawPixels(image.layer, image.mask, pixels)) {
			return false
		}
		// Decoding and writing it again happen off the reader, at the same time
		// as the images after it; its blobs take its place in the output
		// (settle), so the browser receives everything in guacd's order.
		// At most 16 images wait, holding at most viewerImageBytes times the
		// area, and 2 MiB besides the pending output, as the pending output
		// alone was bounded before; past that the reader waits for them.
		size := len(image.pixels)
		if (s.jobs >= maxImageJobs || s.jobBytes+size > viewerImageBytes*s.area || s.held+s.pending.Len() > s.heldLimit()) && !s.settle(true) {
			return false
		}
		job := &imageJob{stream: in[1], limit: pngLimit(cfg.Width, cfg.Height), size: size, done: make(chan struct{})}
		s.parts = append(s.parts, viewerPart{data: bytes.Clone(s.pending.Bytes())}, viewerPart{job: job})
		s.held += s.pending.Len()
		s.pending.Reset()
		s.jobs++
		s.jobBytes += size
		s.imageBytes -= size
		go job.rebuild(in[1], image.pixels, s.revoked)
		delete(s.images, in[1])
		return true
	case "copy":
		_, a := layer(1)
		dst, b := layer(7)
		mask, c := num(6, 0, 15)
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
		return s.fit(dst, x, y, w, h, false) && s.renderWork(s.drawPixels(dst, mask, w*h))
	case "cursor":
		// FreeRDP accepts pointers of up to 384 by 384, and Windows sends them
		// that large on a scaled desktop or with a large pointer setting.
		_, a := layer(3)
		if len(in) != 8 || !a {
			return false
		}
		for i, hi := range map[int]int{1: viewerPointer - 1, 2: viewerPointer - 1, 4: mw, 5: mh, 6: viewerPointer, 7: viewerPointer} {
			if _, ok := num(i, 0, hi); !ok {
				return false
			}
		}
		w, _ := num(6, 0, viewerPointer)
		h, _ := num(7, 0, viewerPointer)
		return s.renderWork(w * h)
	case "cfill":
		mask, a := num(1, 0, 15)
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
		if !s.renderWork(s.drawPixels(id, mask, l.fillPixels())) {
			return false
		}
		l.path.closed = true
		s.layers[id] = l
		return true
	case "rect":
		id, ok := layer(1)
		if len(in) != 6 || !ok || !xy(id, 2, 3, 4, 5) {
			return false
		}
		x, _ := num(2, 0, mw)
		y, _ := num(3, 0, mh)
		w, _ := num(4, 0, mw)
		h, _ := num(5, 0, mh)
		l := s.layers[id]
		path, ok := l.path.add(x, y, x+w, y+h)
		l.path = path
		s.layers[id] = l
		return ok
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
	// No remote names, arbitrary transforms or auxiliary streams. guacd 1.6
	// draws RDP with size, img, copy, rect and cfill alone: transfer (a pixel
	// function the browser runs in JavaScript for every pixel), start, line,
	// clip, close, push, pop, identity and reset come only from guacd's
	// terminal surfaces, so they are refused rather than priced.
	return false
}

func (s *viewerStream) Read(data []byte) (int, error) {
	if s.revoked() {
		_ = s.Close()
		return 0, errNative
	}
	for s.ready.Len() == 0 {
		if len(s.out) > 0 {
			s.ready.Reset(s.out)
			s.out = nil
			break
		}
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
			if !s.release(in[0]) {
				s.native.failure.Store("viewer image")
				_ = s.Close()
				return 0, errNative
			}
			continue
		}
		if !s.drawing(in) {
			s.native.failure.Store("viewer drawing " + in[0]) // next admits only fixed opcode names
			_ = s.Close()
			return 0, errNative
		}
		if in[0] != "blob" && writeInstruction(viewerBoundedWriter{&s.pending, s.heldLimit()}, in) != nil {
			_ = s.Close()
			return 0, errNative
		}
		if !s.release(in[0]) {
			s.native.failure.Store("viewer image")
			_ = s.Close()
			return 0, errNative
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

// release moves out what may go to the browser. While images are being
// rebuilt it waits for them only when the frame ends or guacd has nothing more
// already waiting; otherwise it reads on, so the next images are rebuilt at
// the same time. Output never passes an image still open or being rebuilt.
func (s *viewerStream) release(op string) bool {
	wait := s.jobs > 0 && len(s.images) == 0 && (op == "sync" || s.native.reader == nil || s.native.reader.Buffered() == 0)
	if !s.settle(wait) {
		return false
	}
	if len(s.parts) == 0 && len(s.images) == 0 && s.pending.Len() > 0 {
		s.out = append(s.out, s.pending.Bytes()...)
		s.pending.Reset()
	}
	return true
}

// settle moves out, in order, the output held behind rebuilt images: all of it
// once every image is rebuilt (wait), or up to the first image still being
// rebuilt. An image that failed ends the desktop, as it did on the reader.
func (s *viewerStream) settle(wait bool) bool {
	for len(s.parts) > 0 {
		part := s.parts[0]
		if job := part.job; job != nil {
			if wait {
				select {
				case <-job.done:
				case <-s.done:
					return false
				}
			} else {
				select {
				case <-job.done:
				default:
					return true
				}
			}
			s.jobs--
			s.jobBytes -= job.size
			if !job.ok {
				return false
			}
			// The browser's Guacamole client never acknowledges image blobs:
			// neither of its image readers sends an ack. So nothing here waits for
			// one; a count that refused at 128 unacknowledged chunks ended real
			// Windows sessions. Flow to the browser is the relay's credit window.
			// The count only lets a browser ack chunks it was sent, should one ever
			// do so, and it stays bounded: 128 streams, 128 chunks each.
			s.metaMu.Lock()
			if _, known := s.acks[job.stream]; known || len(s.acks) < 128 {
				s.acks[job.stream] = min(s.acks[job.stream]+job.chunks, 128)
			}
			s.metaMu.Unlock()
			part.data = job.blobs
		} else {
			s.held -= len(part.data)
		}
		s.out = append(s.out, part.data...)
		s.parts[0] = viewerPart{}
		s.parts = s.parts[1:]
	}
	return true
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
			mw, mh := s.bounds()
			w, a := canonicalNumber(in[1], 64, mw)
			h, b := canonicalNumber(in[2], 64, mh)
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
		// The browser applies a new desktop size only when its frame arrives,
		// so a pointer may still be over a desktop that has just shrunk. A
		// point within the session's bounds is taken and moved inside the
		// current desktop; a point past the bounds still refuses.
		if len(in) == 4 {
			mw, mh := s.bounds()
			x, a := canonicalNumber(in[1], 0, mw-1)
			y, b := canonicalNumber(in[2], 0, mh-1)
			_, c := canonicalNumber(in[3], 0, 31)
			valid = a && b && c
			if valid {
				in[1] = strconv.Itoa(min(x, int(s.width.Load())-1))
				in[2] = strconv.Itoa(min(y, int(s.height.Load())-1))
			}
			forward = valid
		}
	case "key":
		if len(in) == 3 {
			key, e := strconv.ParseUint(in[1], 10, 32)
			code := uint32(key)
			scalar := code & 0xffffff
			// The ISO group keys (0xfe01-0xfe0f) are what the browser's
			// Guacamole keyboard sends for AltGr and for every Mac Option key;
			// guacd reads 0xfe03 as AltGr.
			allowed := code >= 0x20 && code <= 0xff || code >= 0xfe01 && code <= 0xfe0f || code >= 0xff00 && code <= 0xffff || code >= 0x1000100 && code <= 0x110ffff && !(scalar >= 0xd800 && scalar <= 0xdfff)
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
		if w, h, ok := identity.DesktopBounds(s.dpi); ok {
			return w, h
		}
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
	// A copy larger than a page takes is dropped and the page told, in fixed
	// words; ending the desktop over it bounded nothing.
	tooLarge := errors.Is(e, ErrClipboardTooLarge)
	if e != nil && !tooLarge {
		return true, false
	}
	if complete {
		if !s.copies.allow(1, clipboardBurst, clipboardPerSecond, s.now()) || strings.ContainsRune(text, 0) {
			return true, false
		}
		told := instruction{"keybash-clipboard", text}
		if tooLarge {
			told = instruction{"keybash-clipboard-large"}
		}
		if writeInstruction(viewerBoundedWriter{&s.pending, s.heldLimit()}, told) != nil {
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
