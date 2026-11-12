package rdplab

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"image/png"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// tilePNG is a small desktop-like PNG, different for every seed.
func tilePNG(t testing.TB, w, h int, seed uint64) []byte {
	t.Helper()
	var b bytes.Buffer
	if png.Encode(&b, desktopLike(w, h, seed)) != nil {
		t.Fatal("fixture tile failed")
	}
	return b.Bytes()
}

// frameOf is one guacd frame: n tiles across the screen, each followed by a
// copy on the screen layer, and the frame's sync.
func frameOf(t testing.TB, n int, w, h int) ([]instruction, map[string][]byte) {
	t.Helper()
	var in []instruction
	tiles := map[string][]byte{}
	for i := range n {
		id, data := strconv.Itoa(i), tilePNG(t, w, h, uint64(i+1))
		tiles[id] = data
		x, y := strconv.Itoa((i%(1024/w))*w), strconv.Itoa((i/(1024/w))*h%(768-h))
		in = append(in, instruction{"img", id, "14", "0", "image/png", x, y}, instruction{"blob", id, base64.StdEncoding.EncodeToString(data)}, instruction{"end", id},
			instruction{"copy", "0", "0", "0", "2", "2", "14", "0", "4", "4"})
	}
	return append(in, instruction{"sync", "4242", "1"}), tiles
}

// readTimed reads one instruction, failing rather than hanging on silence.
func readTimed(t *testing.T, r *bufio.Reader, wait time.Duration) (instruction, error) {
	t.Helper()
	type result struct {
		in  instruction
		err error
	}
	got := make(chan result, 1)
	go func() { in, err := readInstruction(r); got <- result{in, err} }()
	select {
	case x := <-got:
		return x.in, x.err
	case <-time.After(wait):
		t.Fatal("the viewer said nothing")
		return nil, nil
	}
}

// A frame of more tiles than may wait at once is rebuilt off the reader, and
// the browser still receives every instruction in guacd's order, each image's
// own blobs between its start and its end, with its pixels unchanged.
func TestViewerRebuildsImagesAtOnceInGuacdOrder(t *testing.T) {
	// guacd sends the frame in one burst, read ahead as the stream reads it.
	a, remote := net.Pipe()
	s := newViewerStream(&nativeStream{raw: a, reader: bufio.NewReaderSize(a, 1<<20), stop: func() bool { return true }})
	go func() { _, _ = io.Copy(io.Discard, remote) }() // the viewer's acks to guacd
	t.Cleanup(func() { _ = s.Close(); _ = remote.Close() })
	if _, err := s.Read(make([]byte, 128)); err != nil {
		t.Fatal("initial viewer state missing")
	}
	frame, tiles := frameOf(t, maxImageJobs+4, 40, 30)
	// Every worker is held first, so no image can be rebuilt yet: after the
	// first image's start nothing may reach the browser until its blobs can.
	for range cap(imageWorkers) {
		imageWorkers <- struct{}{}
	}
	held := true
	letGo := func() {
		if held {
			held = false
			for range cap(imageWorkers) {
				<-imageWorkers
			}
		}
	}
	t.Cleanup(letGo)
	var burst bytes.Buffer
	for _, in := range frame {
		_ = writeInstruction(&burst, in)
	}
	go func() { _, _ = remote.Write(burst.Bytes()) }()
	r := bufio.NewReader(s)
	if in, err := readTimed(t, r, 5*time.Second); err != nil || in[0] != "img" || in[1] != "0" {
		t.Fatalf("the frame began with %v", in)
	}
	early := make(chan instruction, 1)
	go func() {
		if in, err := readInstruction(r); err == nil {
			early <- in
		}
	}()
	var waiting instruction
	select {
	case in := <-early:
		t.Fatalf("%v overtook an image still being rebuilt", in)
	case <-time.After(300 * time.Millisecond):
	}
	letGo()
	waiting = <-early
	next := func() (instruction, error) {
		if waiting != nil {
			in := waiting
			waiting = nil
			return in, nil
		}
		return readTimed(t, r, 5*time.Second)
	}
	open := "0"
	var body []byte
	for _, want := range frame[1:] {
		if want[0] == "blob" {
			continue // the viewer's own blobs are checked at the image's end
		}
		in, err := next()
		for err == nil && in[0] == "blob" {
			if in[1] != open {
				t.Fatalf("a blob of image %s came while image %q was open", in[1], open)
			}
			chunk, e := base64.StdEncoding.Strict().DecodeString(in[2])
			if e != nil {
				t.Fatal("blob encoding invalid")
			}
			body = append(body, chunk...)
			in, err = next()
		}
		if err != nil || !bytes.Equal(encodedInstruction(t, in), encodedInstruction(t, want)) {
			t.Fatalf("got %v, want %v", in, want)
		}
		switch in[0] {
		case "img":
			open, body = in[1], nil
		case "end":
			assertViewerPixels(t, tiles[in[1]], body)
			open = ""
		}
	}
	if s.jobs != 0 || len(s.parts) != 0 || s.held != 0 {
		t.Fatal("work was left behind after the frame")
	}
}

// An image that does not decode ends the desktop, as it did on the reader:
// nothing of it, and nothing after it, reaches the browser.
func TestViewerEndsAtAnImageThatFailsAndSendsNothingAfterIt(t *testing.T) {
	s, remote, _ := viewerFixture(t)
	if _, err := s.Read(make([]byte, 128)); err != nil {
		t.Fatal("initial viewer state missing")
	}
	broken := tilePNG(t, 40, 30, 9)
	// The header still reads, so it passes the checks on the reader; its image
	// data does not, so only the rebuild finds out.
	at := bytes.Index(broken, []byte("IDAT")) + 12
	copy(broken[at:at+8], bytes.Repeat([]byte{0xff}, 8))
	good := tilePNG(t, 40, 30, 3)
	frame := []instruction{
		{"img", "1", "14", "0", "image/png", "0", "0"}, {"blob", "1", base64.StdEncoding.EncodeToString(good)}, {"end", "1"},
		{"img", "2", "14", "0", "image/png", "40", "0"}, {"blob", "2", base64.StdEncoding.EncodeToString(broken)}, {"end", "2"},
		{"img", "3", "14", "0", "image/png", "80", "0"}, {"blob", "3", base64.StdEncoding.EncodeToString(good)}, {"end", "3"},
		{"sync", "77", "1"},
	}
	go func() {
		for _, in := range frame {
			if writeInstruction(remote, in) != nil {
				return
			}
		}
	}()
	r := bufio.NewReader(s)
	for {
		in, err := readTimed(t, r, 5*time.Second)
		if err != nil {
			break
		}
		if in[1] == "2" && in[0] != "img" || in[1] == "3" || in[0] == "sync" {
			t.Fatalf("%v reached the browser past an image that failed", in)
		}
	}
	if failure, _ := s.native.failure.Load().(string); failure != "viewer image" {
		t.Fatalf("the desktop ended as %q", failure)
	}
}

// When guacd says nothing more after an image, the image goes to the browser
// at once: nothing waits for a frame's end that has not come.
func TestViewerSendsAnImageAtOnceWhenGuacdGoesQuiet(t *testing.T) {
	s, remote, _ := viewerFixture(t)
	if _, err := s.Read(make([]byte, 128)); err != nil {
		t.Fatal("initial viewer state missing")
	}
	data := tilePNG(t, 40, 30, 5)
	go func() {
		for _, in := range []instruction{{"img", "4", "14", "0", "image/png", "0", "0"}, {"blob", "4", base64.StdEncoding.EncodeToString(data)}, {"end", "4"}} {
			if writeInstruction(remote, in) != nil {
				return
			}
		}
	}()
	r := bufio.NewReader(s)
	var body []byte
	for _, want := range []string{"img", "blob", "end"} {
		in, err := readTimed(t, r, 3*time.Second)
		if err != nil || in[0] != want {
			t.Fatalf("got %v (%v), want %s", in, err, want)
		}
		if in[0] == "blob" {
			body, _ = base64.StdEncoding.DecodeString(in[2])
		}
	}
	assertViewerPixels(t, data, body)
}

// Closing the desktop while images are being rebuilt ends its reads, and
// nothing more reaches the browser.
func TestViewerClosedWhileRebuildingSendsNothingMore(t *testing.T) {
	s, remote, _ := viewerFixture(t)
	if _, err := s.Read(make([]byte, 128)); err != nil {
		t.Fatal("initial viewer state missing")
	}
	frame, _ := frameOf(t, 8, 128, 96)
	go func() {
		for _, in := range frame[:len(frame)-1] {
			if writeInstruction(remote, in) != nil {
				return
			}
		}
	}()
	r := bufio.NewReader(s)
	if _, err := readTimed(t, r, 5*time.Second); err != nil {
		t.Fatal("the frame did not start")
	}
	_ = s.Close()
	for {
		in, err := readTimed(t, r, 5*time.Second)
		if err != nil {
			return
		}
		if in[0] == "sync" {
			t.Fatal("output went on after the desktop closed")
		}
	}
}

// BenchmarkViewerFrameOfTiles is what a moving desktop costs the gateway: a
// frame of 64 tiles of 156x156, from guacd's bytes to the browser's.
func BenchmarkViewerFrameOfTiles(b *testing.B) {
	frame, _ := frameOf(b, 64, 156, 156)
	var wire bytes.Buffer
	for _, in := range frame {
		_ = writeInstruction(&wire, in)
	}
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		a, c := net.Pipe()
		s := newViewerStream(&nativeStream{raw: a, reader: bufio.NewReaderSize(a, 64*1024), stop: func() bool { return true }})
		s.sleep = func(time.Duration) {}
		go func() { _, _ = io.Copy(io.Discard, c) }() // the viewer's acks to guacd
		go func() { _, _ = c.Write(wire.Bytes()) }()
		r := bufio.NewReader(s)
		b.StartTimer()
		for {
			in, err := readInstruction(r)
			if err != nil {
				b.Fatal(err)
			}
			if in[0] == "sync" {
				break
			}
		}
		b.StopTimer()
		_ = s.Close()
		_ = c.Close()
	}
}

// However many images a frame has, one desktop holds at most 16 waiting to be
// rebuilt, and at most 2 MiB of output behind them.
func TestViewerHoldsAtMostSixteenImagesWaiting(t *testing.T) {
	s, _, _ := viewerFixture(t)
	if _, err := s.Read(make([]byte, 128)); err != nil {
		t.Fatal("initial viewer state missing")
	}
	frame, _ := frameOf(t, maxImageJobs*2, 64, 48)
	most := 0
	for _, in := range frame[:len(frame)-1] {
		if !s.drawing(in) {
			t.Fatalf("%v refused", in[:2])
		}
		most = max(most, s.jobs)
		if s.held+s.pending.Len() > 4*1024*1024 {
			t.Fatal("more than the bound was held")
		}
	}
	if most > maxImageJobs || most < 2 {
		t.Fatalf("at most %d images waited", most)
	}
}
