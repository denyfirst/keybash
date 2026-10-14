package rdplab

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"image/png"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
)

// Fixed lab viewport. This boundary does not enable native clipboard, resize,
// arbitrary streams, URLs or user-selected connection parameters.
type viewerLayer struct{ width, height, depth int }
type viewerImage struct {
	layer, x, y int
	pixels      []byte
}
type viewerStream struct {
	native     *nativeStream
	layers     map[int]viewerLayer // owned by the single output reader
	images     map[string]*viewerImage
	imageBytes int
	pending    bytes.Buffer
	ready      bytes.Reader
	writeMu    sync.Mutex
	metaMu     sync.Mutex
	acks       map[string]int
	syncs      map[string]bool
	keys       map[uint32]bool
	closed     atomic.Bool
}

func newViewerStream(native *nativeStream) *viewerStream {
	s := &viewerStream{native: native, layers: map[int]viewerLayer{0: {1024, 768, 0}},
		images: make(map[string]*viewerImage), acks: make(map[string]int), syncs: make(map[string]bool), keys: make(map[uint32]bool)}
	var initial bytes.Buffer
	_ = writeInstruction(&initial, instruction{"size", "0", "1024", "768"})
	s.ready.Reset(initial.Bytes())
	return s
}
func (s *viewerStream) Close() error {
	s.closed.Store(true)
	s.native.close()
	s.metaMu.Lock()
	clear(s.keys)
	clear(s.acks)
	clear(s.syncs)
	s.metaMu.Unlock()
	return nil
}
func (s *viewerStream) ReadStderr([]byte) (int, error) { return 0, io.EOF }
func (s *viewerStream) Resize(uint32, uint32) error    { _ = s.Close(); return errNative }

func canonicalNumber(raw string, low, high int) (int, bool) {
	n, err := strconv.Atoi(raw)
	return n, err == nil && n >= low && n <= high && strconv.Itoa(n) == raw
}
func (s *viewerStream) layer(raw string) (int, bool) {
	id, ok := canonicalNumber(raw, -32, 32)
	if !ok {
		return 0, false
	}
	if _, exists := s.layers[id]; !exists {
		if len(s.layers) >= 32 {
			return 0, false
		}
		s.layers[id] = viewerLayer{}
	}
	return id, true
}

// Account for the renderer's 64-pixel canvas rounding and buffer autosizing.
func (s *viewerStream) fit(id, x, y, w, h int, exact bool) bool {
	if x < 0 || y < 0 || w < 0 || h < 0 || x+w > 1024 || y+h > 768 {
		return false
	}
	layer := s.layers[id]
	if exact {
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
	if pixels > 4*1024*1024 {
		return false
	}
	s.layers[id] = layer
	return true
}

func (s *viewerStream) drawing(in instruction) bool {
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
		x, a := num(xi, 0, 1024)
		y, b := num(yi, 0, 768)
		w, c := num(wi, 0, 1024)
		h, d := num(hi, 0, 768)
		return a && b && c && d && s.fit(id, x, y, w, h, false)
	}
	switch in[0] {
	case "size":
		id, a := layer(1)
		w, b := num(2, 0, 1024)
		h, c := num(3, 0, 768)
		return len(in) == 4 && a && b && c && (id != 0 || w == 1024 && h == 768) && s.fit(id, 0, 0, w, h, true)
	case "img":
		id, a := layer(3)
		_, b := num(2, 0, 15)
		x, c := num(5, 0, 1024)
		y, d := num(6, 0, 768)
		if len(in) != 7 || !a || !b || !c || !d || !streamID(in[1]) || in[4] != "image/png" || len(s.images) >= 8 || s.images[in[1]] != nil {
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
		s.metaMu.Lock()
		if len(s.acks) >= 128 && s.acks[in[1]] == 0 || s.acks[in[1]] >= 128 {
			s.metaMu.Unlock()
			return false
		}
		s.acks[in[1]]++
		s.metaMu.Unlock()
		return s.send(instruction{"ack", in[1], "OK", "0"}) == nil
	case "end":
		if len(in) != 2 || s.images[in[1]] == nil {
			return false
		}
		image := s.images[in[1]]
		cfg, err := png.DecodeConfig(bytes.NewReader(image.pixels))
		if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 1024 || cfg.Height > 768 || !s.fit(image.layer, image.x, image.y, cfg.Width, cfg.Height, false) {
			return false
		}
		if _, err := png.Decode(bytes.NewReader(image.pixels)); err != nil {
			return false
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
		for i, hi := range map[int]int{2: 1024, 3: 768, 4: 1024, 5: 768, 8: 1024, 9: 768} {
			if _, ok := num(i, 0, hi); !ok {
				return false
			}
		}
		w, _ := num(4, 0, 1024)
		h, _ := num(5, 0, 768)
		x, _ := num(8, 0, 1024)
		y, _ := num(9, 0, 768)
		return s.fit(dst, x, y, w, h, false)
	case "cursor":
		_, a := layer(3)
		if len(in) != 8 || !a {
			return false
		}
		for i, hi := range map[int]int{1: 256, 2: 256, 4: 1024, 5: 768, 6: 256, 7: 256} {
			if _, ok := num(i, 0, hi); !ok {
				return false
			}
		}
		return true
	case "cfill":
		_, a := num(1, 0, 15)
		_, b := layer(2)
		if len(in) != 7 || !a || !b {
			return false
		}
		for i := 3; i < 7; i++ {
			if _, ok := num(i, 0, 255); !ok {
				return false
			}
		}
		return true
	case "rect":
		id, ok := layer(1)
		return len(in) == 6 && ok && xy(id, 2, 3, 4, 5)
	case "start", "line":
		id, a := layer(1)
		x, b := num(2, 0, 1024)
		y, c := num(3, 0, 768)
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
		id, ok := canonicalNumber(in[1], -32, 32)
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
		_, a := num(1, 0, 1023)
		_, b := num(2, 0, 767)
		return len(in) == 3 && a && b
	case "sync":
		if len(in) != 2 && len(in) != 3 {
			return false
		}
		if _, ok := num(1, 0, 1<<53-1); !ok {
			return false
		}
		if len(in) == 3 {
			if _, ok := num(2, 0, 8192); !ok {
				return false
			}
		}
		s.metaMu.Lock()
		defer s.metaMu.Unlock()
		if len(s.syncs) >= 128 {
			return false
		}
		s.syncs[in[1]] = true
		return true
	}
	return false // No remote names, arbitrary transforms or auxiliary streams.
}

func (s *viewerStream) Read(data []byte) (int, error) {
	if s.closed.Load() {
		return 0, errNative
	}
	for s.ready.Len() == 0 {
		in, err := s.native.next()
		if err != nil {
			_ = s.Close()
			return 0, errNative
		}
		if in[0] == "name" {
			continue
		} // remote text never becomes browser UI/HTML
		if !s.drawing(in) || writeInstruction(&s.pending, in) != nil || s.pending.Len() > 2*1024*1024 {
			_ = s.Close()
			return 0, errNative
		}
		if len(s.images) == 0 {
			s.ready.Reset(append([]byte(nil), s.pending.Bytes()...))
			s.pending.Reset()
		}
	}
	return s.ready.Read(data)
}
func (s *viewerStream) send(in instruction) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeInstruction(s.native.raw, in)
}
func (s *viewerStream) Write(data []byte) (int, error) {
	refuse := func() (int, error) { _ = s.Close(); return 0, errNative }
	if s.closed.Load() || len(data) == 0 || len(data) > 1024 {
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
	s.metaMu.Lock()
	valid, forward := false, false
	switch in[0] {
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
		if len(in) == 2 && s.syncs[in[1]] {
			delete(s.syncs, in[1])
			valid, forward = true, true
		}
	case "mouse":
		if len(in) == 4 {
			_, a := canonicalNumber(in[1], 0, 1023)
			_, b := canonicalNumber(in[2], 0, 767)
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
	if forward && s.send(in) != nil {
		return refuse()
	}
	return len(data), nil
}
