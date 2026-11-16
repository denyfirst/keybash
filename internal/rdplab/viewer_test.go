package rdplab

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

func viewerFixture(t *testing.T) (*viewerStream, net.Conn, <-chan instruction) {
	t.Helper()
	a, b := net.Pipe()
	s := newViewerStream(&nativeStream{raw: a, reader: bufio.NewReader(a), stop: func() bool { return true }})
	input := make(chan instruction, 32)
	go func() {
		defer close(input)
		r := bufio.NewReader(b)
		for {
			in, err := readInstruction(r)
			if err != nil {
				return
			}
			select {
			case input <- in:
			default:
				return
			}
		}
	}()
	t.Cleanup(func() { _ = s.Close(); _ = b.Close() })
	return s, b, input
}
func encodedInstruction(t *testing.T, in instruction) []byte {
	t.Helper()
	var b bytes.Buffer
	if writeInstruction(&b, in) != nil {
		t.Fatal("fixture instruction encoding failed")
	}
	return b.Bytes()
}
func fixturePNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	i := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	i.SetNRGBA(0, 0, color.NRGBA{R: 31, G: 160, B: 90, A: 255})
	if png.Encode(&b, i) != nil {
		t.Fatal("fixture PNG failed")
	}
	return b.Bytes()
}
func TestViewerValidatedPNGGroupingInputAndRevocation(t *testing.T) {
	s, remote, input := viewerFixture(t)
	initial := make([]byte, 128)
	if n, err := s.Read(initial); err != nil || !bytes.Contains(initial[:n], []byte("1024")) {
		t.Fatal("fixed viewport missing")
	}
	data := fixturePNG(t)
	instructions := []instruction{{"img", "0", "14", "-1", "image/png", "0", "0"}, {"img", "1", "14", "-2", "image/png", "0", "0"},
		{"blob", "0", base64.StdEncoding.EncodeToString(data)}, {"blob", "1", base64.StdEncoding.EncodeToString(data)},
		{"end", "1"}, {"end", "0"}, {"copy", "-1", "0", "0", "2", "2", "14", "0", "4", "4"}, {"mouse", "0", "0", "0", "0"}, {"sync", "123", "1"}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, in := range instructions {
			if writeInstruction(remote, in) != nil {
				return
			}
		}
	}()
	got := bufio.NewReader(s)
	// Image bodies are normalized when their own end arrives. Drawing starts,
	// ends and operations retain their order even when image streams interleave.
	for _, index := range []int{0, 1, 3, 4, 2, 5, 6, 7, 8} {
		expected := instructions[index]
		in, err := readInstruction(got)
		if err != nil || len(in) != len(expected) || in[0] != expected[0] {
			t.Fatal("valid native drawing changed/refused")
		}
		if in[0] == "blob" {
			if in[1] != expected[1] {
				t.Fatal("normalized image changed stream")
			}
			body, err := base64.StdEncoding.Strict().DecodeString(in[2])
			if err != nil {
				t.Fatal("normalized image encoding invalid")
			}
			assertViewerPixels(t, data, body)
		} else if !bytes.Equal(encodedInstruction(t, in), encodedInstruction(t, expected)) {
			t.Fatal("valid native drawing changed/refused")
		}
	}
	<-done
	for range 2 {
		select {
		case in := <-input:
			if in[0] != "ack" {
				t.Fatal("native PNG acknowledgement missing")
			}
		case <-time.After(time.Second):
			t.Fatal("native PNG deadlocked")
		}
	}
	for _, in := range []instruction{{"ack", "0", "OK", "0"}, {"ack", "1", "OK", "0"}, {"sync", "123"}, {"key", "97", "1"}, {"key", "97", "0"}, {"mouse", "40", "50", "1"}, {"nop"}} {
		b := encodedInstruction(t, in)
		if n, err := s.Write(b); err != nil || n != len(b) {
			t.Fatal("valid viewer input refused")
		}
	}
	for _, op := range []string{"sync", "key", "key", "mouse", "nop"} {
		select {
		case in := <-input:
			if in[0] != op {
				t.Fatal("viewer input changed")
			}
		case <-time.After(time.Second):
			t.Fatal("viewer input not forwarded")
		}
	}
	_ = s.Close()
	if n, err := s.Read(make([]byte, 16)); n != 0 || err != errNative {
		t.Fatal("late drawing escaped revocation")
	}
	if _, err := s.Write(encodedInstruction(t, instruction{"nop"})); err != errNative {
		t.Fatal("late input escaped revocation")
	}
}

func assertViewerPixels(t *testing.T, want, got []byte) {
	t.Helper()
	a, err := png.Decode(bytes.NewReader(want))
	if err != nil {
		t.Fatal("fixture image decode failed")
	}
	b, err := png.Decode(bytes.NewReader(got))
	if err != nil || a.Bounds() != b.Bounds() {
		t.Fatal("normalized image dimensions changed/refused")
	}
	for y := a.Bounds().Min.Y; y < a.Bounds().Max.Y; y++ {
		for x := a.Bounds().Min.X; x < a.Bounds().Max.X; x++ {
			if color.NRGBAModel.Convert(a.At(x, y)) != color.NRGBAModel.Convert(b.At(x, y)) {
				t.Fatal("normalized image pixels changed")
			}
		}
	}
}

func TestViewerNormalizesPNGWithoutMetadataAnimationOrTrailingData(t *testing.T) {
	data := fixturePNG(t)
	var untrusted bytes.Buffer
	untrusted.Write(data[:33]) // signature and complete IHDR
	for _, chunk := range []struct {
		kind string
		body []byte
	}{{"tEXt", []byte("Comment\x00private remote metadata")}, {"acTL", []byte{0, 0, 0, 2, 0, 0, 0, 0}}} {
		_ = binary.Write(&untrusted, binary.BigEndian, uint32(len(chunk.body)))
		untrusted.WriteString(chunk.kind)
		untrusted.Write(chunk.body)
		crc := crc32.NewIEEE()
		_, _ = crc.Write([]byte(chunk.kind))
		_, _ = crc.Write(chunk.body)
		_ = binary.Write(&untrusted, binary.BigEndian, crc.Sum32())
	}
	untrusted.Write(data[33:])
	untrusted.WriteString("<script>trailing remote payload</script>")
	s, remote, _ := viewerFixture(t)
	_, _ = s.Read(make([]byte, 128))
	go func() {
		for _, in := range []instruction{{"img", "0", "14", "0", "image/png", "0", "0"}, {"blob", "0", base64.StdEncoding.EncodeToString(untrusted.Bytes())}, {"end", "0"}} {
			if writeInstruction(remote, in) != nil {
				return
			}
		}
	}()
	r := bufio.NewReader(s)
	var normalized bytes.Buffer
	for _, op := range []string{"img", "blob", "end"} {
		in, err := readInstruction(r)
		if err != nil || in[0] != op {
			t.Fatal("valid annotated PNG refused")
		}
		if op == "blob" {
			body, err := base64.StdEncoding.Strict().DecodeString(in[2])
			if err != nil {
				t.Fatal("normalized PNG encoding invalid")
			}
			normalized.Write(body)
		}
	}
	for _, marker := range []string{"tEXt", "private remote metadata", "acTL", "trailing remote payload"} {
		if bytes.Contains(normalized.Bytes(), []byte(marker)) {
			t.Fatal("untrusted PNG metadata/animation/trailing content reached browser")
		}
	}
	assertViewerPixels(t, data, normalized.Bytes())
}
func TestViewerRefusesMalformedAndExcessDrawing(t *testing.T) {
	for _, in := range []instruction{{"dispose"}, {"size", "0", "999999", "1"}, {"size", "0", "800", "600"}, {"size", "33", "1", "1"},
		{"img", "0", "14", "0", "image/svg+xml", "0", "0"}, {"img", "0", "14", "0", "image/png", "NaN", "0"},
		{"copy", "0", "0", "0", "1024", "768", "14", "-1", "1000", "0"}, {"pop", "0"}, {"cursor", "999999", "0", "0", "0", "0", "1", "1"},
		{"transform", "0", "1", "0", "0", "1", "999999", "0"}, {"clipboard", "0", "text/plain"}, {"file", "0", "image/png", "private name"}} {
		s, _, _ := viewerFixture(t)
		if s.drawing(in) {
			t.Fatalf("unsafe drawing accepted: %s", in[0])
		}
	}
	s, _, _ := viewerFixture(t)
	accepted := 0
	for i := 1; i <= 32 && s.drawing(instruction{"size", strconv.Itoa(i), "1024", "768"}); i++ {
		accepted++
	}
	if want := viewerPixels/(1024*768) - 1; accepted != want {
		t.Fatalf("aggregate canvas quota took %d full layers beside the display, want %d", accepted, want)
	}
	// A visible layer named without a size is counted at the largest display,
	// as the browser may create it before a pending resize: the same quota.
	s, _, _ = viewerFixture(t)
	accepted = 0
	for i := 1; i <= 32 && s.drawing(instruction{"rect", strconv.Itoa(i), "0", "0", "1", "1"}); i++ {
		accepted++
	}
	if want := viewerPixels/(1024*768) - 1; accepted != want || s.layers[1].width != 1024 || s.layers[1].height != 768 {
		t.Fatalf("visible layers named without a size: %d accepted (want %d), first counted at %dx%d", accepted, want, s.layers[1].width, s.layers[1].height)
	}
	// guacd 1.6 never sends these for RDP; they are refused, not priced.
	s, _, _ = viewerFixture(t)
	for _, in := range []instruction{{"transfer", "0", "0", "0", "2", "2", "12", "0", "50", "50"}, {"start", "0", "5", "5"}, {"line", "0", "5", "5"},
		{"clip", "0"}, {"close", "0"}, {"push", "0"}, {"pop", "0"}, {"identity", "0"}, {"reset", "0"}, {"move", "1", "0", "0", "0", "0"}, {"shade", "1", "128"}} {
		if s.drawing(in) {
			t.Fatalf("%s accepted", in[0])
		}
	}
	// One path holds viewerPathRects rects before a fill and no more; a fill
	// closes it and the next rect begins a new one.
	for i := 0; i <= viewerPathRects; i++ {
		if s.drawing(instruction{"rect", "-1", strconv.Itoa(i), "0", "1", "1"}) != (i < viewerPathRects) {
			t.Fatalf("rect %d into one path: accepted %v", i+1, i < viewerPathRects)
		}
	}
	if !s.drawing(instruction{"cfill", "14", "-1", "0", "0", "0", "255"}) || !s.drawing(instruction{"rect", "-1", "0", "0", "1", "1"}) {
		t.Fatal("a filled path did not begin anew")
	}
}

// A pointer still over a desktop that has just shrunk is moved inside it, not
// refused: the browser draws a new size only when its frame arrives. A point
// past the session's bounds still refuses. The ISO group keys the browser's
// keyboard sends for AltGr and for Mac Option reach guacd; their neighbours do
// not. A pointer image up to FreeRDP's 384 by 384 is shown.
func TestViewerInputSurvivesAShrinkAndTakesAltGr(t *testing.T) {
	scaled := func() (*viewerStream, <-chan instruction) {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		sent := make(chan instruction, 8)
		go func() {
			r := bufio.NewReader(b)
			for {
				in, err := readInstruction(r)
				if err != nil {
					return
				}
				sent <- in
			}
		}()
		return newViewerStream(&nativeStream{raw: a, reader: bufio.NewReader(a), stop: func() bool { return true }, workspace: true, width: 2880, height: 1800, dpi: 192}), sent
	}
	s, sent := scaled()
	if !s.drawing(instruction{"size", "0", "2400", "1300"}) {
		t.Fatal("a shrink was refused")
	}
	for _, c := range []struct {
		in   instruction
		want string
	}{
		{instruction{"mouse", "2700", "1700", "1"}, "mouse 2399 1299 1"},
		{instruction{"mouse", "3839", "2159", "0"}, "mouse 2399 1299 0"},
		{instruction{"mouse", "100", "200", "0"}, "mouse 100 200 0"},
		{instruction{"key", "65027", "1"}, "key 65027 1"},
		{instruction{"key", "65027", "0"}, "key 65027 0"},
		{instruction{"key", "65025", "1"}, "key 65025 1"},
		{instruction{"key", "65039", "1"}, "key 65039 1"},
	} {
		if _, err := s.Write(encodedInstruction(t, c.in)); err != nil {
			t.Fatalf("%v was refused", c.in)
		}
		select {
		case got := <-sent:
			if g := fmt.Sprint(strings.Join(got, " ")); g != c.want {
				t.Fatalf("%v reached guacd as %q, want %q", c.in, g, c.want)
			}
		case <-time.After(time.Second):
			t.Fatalf("%v never reached guacd", c.in)
		}
	}
	for _, in := range []instruction{{"mouse", "3840", "0", "0"}, {"mouse", "0", "2160", "0"}, {"mouse", "01", "0", "0"}, {"mouse", "-1", "0", "0"},
		{"key", "65024", "1"}, {"key", "65040", "1"}, {"key", "65105", "1"}} {
		s, _ := scaled()
		if _, err := s.Write(encodedInstruction(t, in)); err == nil {
			t.Fatalf("%v was accepted", in)
		}
	}
	s, _ = scaled()
	for _, c := range []struct {
		in instruction
		ok bool
	}{
		{instruction{"cursor", "383", "383", "-1", "0", "0", "384", "384"}, true},
		{instruction{"cursor", "0", "0", "-1", "0", "0", "385", "384"}, false},
		{instruction{"cursor", "384", "0", "-1", "0", "0", "384", "384"}, false},
	} {
		if s.drawing(c.in) != c.ok {
			t.Fatalf("%v accepted %v, want %v", c.in, !c.ok, c.ok)
		}
	}
}

// Re-encoding takes the fastest level, and falls back to the default when the
// fastest does not fit, so speed never refuses an image the default would take.
func TestViewerNormalizesFastAndFallsBack(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 320, 200))
	for y := range 200 {
		for x := range 320 {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 7 % 251), G: uint8(y*13 + x/9), B: uint8((x ^ y) % 17 * 15), A: 255})
		}
	}
	var def, fast bytes.Buffer
	if png.Encode(&def, img) != nil || (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(&fast, img) != nil {
		t.Fatal("fixture encoding failed")
	}
	if fast.Len() <= def.Len() {
		t.Fatalf("fixture does not separate the levels: fastest %d, default %d bytes", fast.Len(), def.Len())
	}
	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{{"room for the fastest", fast.Len(), fast.Len()}, {"room for the default only", def.Len(), def.Len()}, {"room for neither", def.Len() - 1, 0}} {
		out, ok := normalizedPNG(img, tc.limit)
		if ok != (tc.want != 0) || len(out) != tc.want {
			t.Fatalf("%s: got %d bytes (%v), want %d", tc.name, len(out), ok, tc.want)
		}
		if ok {
			assertViewerPixels(t, def.Bytes(), out)
		}
	}
}

// The browser's Guacamole client never acknowledges image blobs, so a desktop's
// images must flow with no browser ack at all: a real Windows session ended
// after 128 chunks on one stream. guacd reuses a few stream numbers and opens
// fresh ones; the bookkeeping stays bounded, and still takes only acks for
// chunks that were sent.
func TestViewerImagesNeedNoBrowserAck(t *testing.T) {
	s, remote, input := viewerFixture(t)
	go func() {
		for range input { // the native side: the viewer's own acks to guacd
		}
	}()
	if _, err := s.Read(make([]byte, 128)); err != nil {
		t.Fatal("fixed viewport missing")
	}
	data := base64.StdEncoding.EncodeToString(fixturePNG(t))
	const images = 500
	go func() {
		for i := range images {
			stream := strconv.Itoa(i % 2)
			if i >= 200 {
				stream = strconv.Itoa(1000 + i)
			}
			for _, in := range []instruction{{"img", stream, "14", "0", "image/png", "0", "0"}, {"blob", stream, data}, {"end", stream}} {
				if writeInstruction(remote, in) != nil {
					return
				}
			}
		}
	}()
	got := bufio.NewReader(s)
	for ends := 0; ends < images; {
		in, err := readInstruction(got)
		if err != nil {
			t.Fatalf("the desktop ended after %d images with no browser ack", ends)
		}
		if in[0] == "end" {
			ends++
		}
	}
	s.metaMu.Lock()
	streams, most := len(s.acks), 0
	for _, n := range s.acks {
		most = max(most, n)
	}
	s.metaMu.Unlock()
	if streams > 128 || most > 128 || streams == 0 {
		t.Fatalf("ack bookkeeping: %d streams, %d chunks at most", streams, most)
	}
	if _, err := s.Write(encodedInstruction(t, instruction{"ack", "0", "OK", "0"})); err != nil {
		t.Fatal("an ack for chunks that were sent was refused")
	}
	if _, err := s.Write(encodedInstruction(t, instruction{"ack", "77", "OK", "0"})); err != errNative {
		t.Fatal("an ack for a stream never sent was accepted")
	}
}

// What a real Windows Server 2025 desktop needs at full HD fits: the display, the
// copy of it guacd keeps in a buffer the same size (which ended every session
// at the old budget), and every pointer FreeRDP may hold at the native cap, at
// the largest size it allows. Past that the budget still refuses.
func TestViewerHoldsAFullHDWindowsDesktop(t *testing.T) {
	a, _ := net.Pipe()
	defer a.Close()
	s := newViewerStream(&nativeStream{raw: a, reader: bufio.NewReader(a), stop: func() bool { return true }, workspace: true})
	for _, in := range []instruction{{"size", "0", "1920", "1080"}, {"copy", "0", "0", "0", "1920", "1080", "14", "-1", "0", "0"}} {
		if !s.drawing(in) {
			t.Fatalf("a full-HD desktop was refused at %v", in)
		}
	}
	for i := range 33 { // 32 cached pointers and the one in use
		if !s.drawing(instruction{"size", strconv.Itoa(-2 - i), "384", "384"}) {
			t.Fatalf("pointer %d of 384 by 384 was refused", i+1)
		}
	}
	for i := range 64 { // and small buffers besides
		if !s.drawing(instruction{"size", strconv.Itoa(-100 - i), "96", "96"}) {
			t.Fatalf("small buffer %d was refused", i+1)
		}
	}
	refused := false
	for i := range 8 {
		if !s.drawing(instruction{"copy", "0", "0", "0", "1920", "1080", "14", strconv.Itoa(-200 - i), "0", "0"}) {
			refused = true
			break
		}
	}
	if !refused {
		t.Fatal("eight more full-HD buffers fitted: the pixel budget is not bounding")
	}
}

// guacd numbers buffers past -32 while few are live, as a real Windows desktop
// showed (-33 with 30 live); the live count and the pixels are what bound them.
func TestViewerTakesGuacdBufferNumbersAndBoundsLiveLayers(t *testing.T) {
	s, _, _ := viewerFixture(t)
	if !s.drawing(instruction{"rect", "-33", "8", "8", "26", "24"}) || !s.drawing(instruction{"size", "-1100", "64", "64"}) || !s.drawing(instruction{"dispose", "-1100"}) {
		t.Fatal("a buffer number guacd uses was refused")
	}
	for _, in := range []instruction{{"size", "-4097", "64", "64"}, {"rect", "-99999", "0", "0", "1", "1"}, {"dispose", "-4097"}, {"size", "33", "64", "64"}, {"size", "-0064", "64", "64"}} {
		if s.drawing(in) {
			t.Fatalf("a layer number outside the range was accepted: %v", in)
		}
	}
	// Up to the bound, the display included; disposing one frees its place.
	s, _, _ = viewerFixture(t)
	for i := 1; len(s.layers) < viewerLayers; i++ {
		if !s.drawing(instruction{"size", strconv.Itoa(-i), "64", "64"}) {
			t.Fatalf("live layer %d refused", len(s.layers)+1)
		}
	}
	if s.drawing(instruction{"size", "-2000", "64", "64"}) || len(s.layers) != viewerLayers {
		t.Fatal("a layer past the live bound was accepted")
	}
	if !s.drawing(instruction{"dispose", "-1"}) || !s.drawing(instruction{"size", "-2000", "64", "64"}) {
		t.Fatal("a disposed layer did not free its place")
	}
}

func TestViewerInvalidPNGIsNeverForwarded(t *testing.T) {
	for _, payload := range [][]byte{[]byte("bad png"), fixturePNG(t)[:33]} {
		s, remote, _ := viewerFixture(t)
		_, _ = s.Read(make([]byte, 128))
		go func() {
			for _, in := range []instruction{{"img", "0", "14", "0", "image/png", "0", "0"}, {"blob", "0", base64.StdEncoding.EncodeToString(payload)}, {"end", "0"}} {
				if writeInstruction(remote, in) != nil {
					return
				}
			}
		}()
		if n, err := s.Read(make([]byte, 4096)); n != 0 || err != errNative {
			t.Fatal("invalid PNG reached the viewer")
		}
	}
}

func FuzzViewerDrawingSchemas(f *testing.F) {
	for _, in := range []instruction{{"dispose"}, {"img", "0", "14", "-1", "image/png", "0", "0"}, {"size", "0", "1024", "768"}, {"mouse", "0", "0", "0", "0"}, {"copy", "-1", "0", "0", "1024", "768", "14", "0", "0", "0"}, {"sync", "123"}} {
		var data bytes.Buffer
		if writeInstruction(&data, in) != nil {
			f.Fatal("fuzz seed encoding failed")
		}
		f.Add(data.Bytes())
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := readInstruction(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		// Each fuzz case has fresh state. Blob/end cannot exist without an image
		// start, so this schema pass performs no transport I/O or native launch.
		viewer := newViewerStream(nil)
		_ = viewer.drawing(in)
		if len(viewer.layers) > viewerLayers || len(viewer.images) > viewerImages {
			t.Fatal("viewer state quota escaped")
		}
	})
}
func TestViewerInputRefusesArbitraryParametersReplayAndBounds(t *testing.T) {
	for _, in := range []instruction{{"select", "rdp"}, {"connect", "private-password"}, {"clipboard", "0", "text/plain"}, {"size", "1", "1"},
		{"ack", "999", "OK", "0"}, {"sync", "123"}, {"key", "0", "1"}, {"key", "97", "2"}, {"key", "16777216", "1"}, {"mouse", "1024", "0", "0"}, {"mouse", "0", "0", "32"}} {
		s, _, _ := viewerFixture(t)
		if _, err := s.Write(encodedInstruction(t, in)); err != errNative {
			t.Fatalf("unsafe browser opcode accepted: %s", in[0])
		}
	}
	s, _, _ := viewerFixture(t)
	multiple := append(encodedInstruction(t, instruction{"nop"}), encodedInstruction(t, instruction{"nop"})...)
	if _, err := s.Write(multiple); err != errNative {
		t.Fatal("multiple browser commands accepted")
	}
	s, _, _ = viewerFixture(t)
	if _, err := s.Write(bytes.Repeat([]byte{'a'}, 1025)); err != errNative {
		t.Fatal("excess browser input accepted")
	}
}
func TestViewerPartialImageAndCancellationCloseReaders(t *testing.T) {
	s, remote, _ := viewerFixture(t)
	_, _ = s.Read(make([]byte, 128))
	go func() { _ = writeInstruction(remote, instruction{"img", "0", "14", "0", "image/png", "0", "0"}) }()
	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(s); done <- err }()
	_ = s.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("partial image treated as complete")
		}
	case <-time.After(time.Second):
		t.Fatal("closed viewer reader stayed blocked")
	}
}

// pacedViewer freezes time so a test can see exactly when work waits.
func pacedViewer(t *testing.T) (*viewerStream, *time.Duration) {
	s, _, _ := viewerFixture(t)
	now := time.Unix(1000, 0)
	slept := new(time.Duration)
	s.clock = func() time.Time { return now }
	s.sleep = func(d time.Duration) { *slept += d; now = now.Add(d) }
	s.render.last, s.decode.last = now, now
	return s, slept
}

func TestViewerDecodeAndRenderWorkArePacedNotEnded(t *testing.T) {
	s, slept := pacedViewer(t)
	s.render.debt = renderBurst - 4
	if !s.drawing(instruction{"copy", "0", "0", "0", "2", "2", "14", "0", "0", "0"}) || *slept != 0 {
		t.Fatal("render work within the burst was refused or delayed")
	}
	if !s.drawing(instruction{"copy", "0", "0", "0", "1", "1", "14", "0", "0", "0"}) || *slept <= 0 {
		t.Fatal("render work beyond the burst ended the session instead of pacing it")
	}
	// The former lifetime total (128M pixels) is not a session end any more.
	for i := 0; i < 200; i++ {
		if !s.drawing(instruction{"copy", "0", "0", "0", "1024", "768", "14", "0", "0", "0"}) {
			t.Fatal("long desktop session ended at its former render total")
		}
	}
	s, slept = pacedViewer(t)
	s.decode.debt = decodeBurst
	s.images["0"] = &viewerImage{layer: 0, pixels: fixturePNG(t)}
	if !s.drawing(instruction{"end", "0"}) || *slept <= 0 {
		t.Fatal("decode beyond the burst ended the session instead of pacing it")
	}
	// A cost larger than any burst refuses outright.
	if s.spend(&s.render, renderBurst+1, renderBurst, renderPerSecond) {
		t.Fatal("unbounded single render cost accepted")
	}
}

// A fill is charged for what the browser's canvas paints: the current path's
// bounds within the layer's canvas, never the whole layer for a small rect,
// and never nothing for a path it paints again.
func TestViewerFillIsChargedForThePathItPaints(t *testing.T) {
	const display = 1024 * 768 // a visible layer is created at the largest display
	s, slept := pacedViewer(t)
	fill := func(id string) instruction { return instruction{"cfill", "14", id, "1", "2", "3", "255"} }
	for i, c := range []struct {
		ins  []instruction
		cost float64
	}{
		{[]instruction{{"rect", "0", "10", "10", "4", "4"}, fill("0")}, 16},
		// A fill closes the path without clearing it: a second fill paints it again.
		{[]instruction{fill("0")}, 16},
		// The next rect after a closed path begins a new one.
		{[]instruction{{"rect", "0", "100", "100", "2", "3"}, fill("0")}, 6},
		// Rects in an open path paint within their joint bounds.
		{[]instruction{{"rect", "0", "0", "0", "2", "2"}, {"rect", "0", "10", "10", "2", "2"}, fill("0")}, 144},
		// guacd's own sequence on a non-opaque buffer: one rect, two fills.
		{[]instruction{{"rect", "-3", "0", "0", "8", "8"}, {"cfill", "2", "-3", "0", "0", "0", "255"}, fill("-3")}, 64 + 64},
		// A whole-layer path still costs the whole layer.
		{[]instruction{{"rect", "0", "0", "0", "1024", "768"}, fill("0")}, 1024 * 768},
		// A path past a layer is cut at its canvas, rounded up to 64 pixels.
		{[]instruction{{"size", "1", "100", "100"}, {"rect", "1", "0", "0", "300", "300"}, fill("1")}, display + 100*100 + 128*128},
		// A visible layer named first by a rect is filled across its whole canvas.
		{[]instruction{{"rect", "2", "0", "0", "1024", "768"}, fill("2")}, display + display},
		// A buffer grows with what is drawn into it, and so does its fill.
		{[]instruction{{"rect", "-1", "0", "0", "30", "40"}, fill("-1")}, 1200},
	} {
		before := s.render.debt
		for _, in := range c.ins {
			if !s.drawing(in) {
				t.Fatalf("case %d: %v refused", i, in)
			}
		}
		if got := s.render.debt - before; got != c.cost {
			t.Fatalf("case %d: charged %v pixels, want %v", i, got, c.cost)
		}
	}
	if *slept != 0 {
		t.Fatal("fills within the burst were delayed")
	}
	// Fills beyond the budget still pace the reader rather than end the desktop.
	s.render.debt = renderBurst
	if !s.drawing(instruction{"rect", "0", "0", "0", "8", "8"}) || !s.drawing(fill("0")) || *slept <= 0 {
		t.Fatal("a fill past the budget was not paced")
	}
}

// A channel mask whose canvas operation changes the whole canvas outside the
// drawing (destination-in, source-in, source-out, destination-atop, copy), or
// one the client does not map and so leaves the previous operation in force,
// costs the destination's whole canvas, for fills, copies and images alike.
// The bounded operations cost what they draw.
func TestViewerUnboundedMasksCostTheWholeCanvas(t *testing.T) {
	const canvas = 1024 * 768
	s, _ := pacedViewer(t)
	charge := func(in instruction) float64 {
		t.Helper()
		before := s.render.debt
		if !s.drawing(in) {
			t.Fatalf("%v refused", in)
		}
		return s.render.debt - before
	}
	if charge(instruction{"rect", "0", "10", "10", "4", "4"}) != 0 {
		t.Fatal("a rect alone was charged")
	}
	for mask := 0; mask < 16; mask++ {
		want := float64(canvas)
		switch mask {
		case 0x2, 0x6, 0xA, 0xB, 0xE, 0xF:
			want = 16
		}
		if got := charge(instruction{"cfill", strconv.Itoa(mask), "0", "1", "2", "3", "255"}); got != want {
			t.Fatalf("cfill with mask %#x charged %v, want %v", mask, got, want)
		}
		if mask == 0xC || mask == 0xE {
			want = 4
			if mask == 0xC {
				want = canvas
			}
			if got := charge(instruction{"copy", "0", "0", "0", "2", "2", strconv.Itoa(mask), "0", "50", "50"}); got != want {
				t.Fatalf("copy with mask %#x charged %v, want %v", mask, got, want)
			}
		}
	}
	// A buffer's canvas is what has been drawn into it, rounded up to 64.
	if got := charge(instruction{"copy", "0", "0", "0", "2", "2", "12", "-2", "0", "0"}); got != 64*64 {
		t.Fatalf("copy into a buffer with mask 0xc charged %v, want %v", got, 64*64)
	}
	// Drawing larger than a small layer's canvas never costs less than itself.
	if charge(instruction{"size", "1", "10", "10"}) != canvas+100 {
		t.Fatal("a new 10 by 10 layer was not charged its creation and its pixels")
	}
	if got := charge(instruction{"copy", "0", "0", "0", "100", "100", "12", "1", "0", "0"}); got != 100*100 {
		t.Fatalf("copy past a small layer with mask 0xc charged %v, want %v", got, 100*100)
	}
	// An image draws with its mask too: 2 by 2 pixels, or the whole canvas.
	for mask, want := range map[string]float64{"14": 4, "12": canvas, "0": canvas} {
		id := "3" + mask
		if !s.drawing(instruction{"img", id, mask, "0", "image/png", "0", "0"}) {
			t.Fatalf("image with mask %s refused", mask)
		}
		s.images[id].pixels = fixturePNG(t)
		s.imageBytes += len(s.images[id].pixels)
		if got := charge(instruction{"end", id}); got != want {
			t.Fatalf("image with mask %s charged %v, want %v", mask, got, want)
		}
	}
}

// Images may be what guacd legitimately sends: a 512 by 512 photograph is over
// 256 KiB, and guacd's display workers stream several at once. Each image may
// hold what a PNG of its own size can, the open images and those waiting to be
// rebuilt viewerImageBytes each, and at most viewerImages may be open; the
// sizes and forms guacd never writes refuse at the header.
func TestViewerImagesTakeWhatGuacdSends(t *testing.T) {
	viewer := func() *viewerStream {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		go func() { _, _ = io.Copy(io.Discard, b) }()
		return newViewerStream(&nativeStream{raw: a, reader: bufio.NewReader(a), stop: func() bool { return true }})
	}
	encode := func(img image.Image) []byte {
		var b bytes.Buffer
		if png.Encode(&b, img) != nil {
			t.Fatal("fixture encoding failed")
		}
		return b.Bytes()
	}
	feed := func(s *viewerStream, id string, data []byte) bool {
		if !s.drawing(instruction{"img", id, "14", "0", "image/png", "0", "0"}) {
			return false
		}
		for len(data) > 0 {
			n := min(len(data), 256<<10)
			if !s.drawing(instruction{"blob", id, base64.StdEncoding.EncodeToString(data[:n])}) {
				return false
			}
			data = data[n:]
		}
		return true
	}
	noise := image.NewRGBA(image.Rect(0, 0, 512, 512))
	state := uint32(1)
	for i := range noise.Pix {
		state = state*1664525 + 1013904223
		noise.Pix[i] = byte(state >> 24)
		if i%4 == 3 {
			noise.Pix[i] = 255
		}
	}
	photo := encode(noise)
	if len(photo) <= 256<<10 || len(photo) > pngLimit(512, 512) {
		t.Fatalf("a 512 by 512 photograph is %d bytes, want past 256 KiB and within %d", len(photo), pngLimit(512, 512))
	}
	s := viewer()
	if !feed(s, "1", photo) || !s.drawing(instruction{"end", "1"}) || !s.settle(true) {
		t.Fatal("a 512 by 512 photograph at 100% was refused")
	}
	// A file larger than a PNG of its own size can be, a size past the
	// desktop, 16-bit samples and interlacing refuse at the header.
	small := fixturePNG(t)
	wide := encode(image.NewRGBA(image.Rect(0, 0, 1025, 2)))
	deep := encode(image.NewRGBA64(image.Rect(0, 0, 2, 2)))
	interlaced := bytes.Clone(small)
	interlaced[28] = 1
	for name, data := range map[string][]byte{"padded": append(bytes.Clone(small), make([]byte, 8<<10)...), "wide": wide, "16-bit": deep, "interlaced": interlaced} {
		if feed(viewer(), "1", data) {
			t.Fatalf("a %s PNG was taken", name)
		}
	}
	// viewerImages open at once, and no more.
	s = viewer()
	for i := 0; i <= viewerImages; i++ {
		if s.drawing(instruction{"img", strconv.Itoa(2*i + 1), "14", "-1", "image/png", "0", "0"}) != (i < viewerImages) {
			t.Fatalf("open image %d: accepted %v", i+1, i < viewerImages)
		}
	}
	// Open images hold viewerImageBytes together: the first photograph past
	// it refuses.
	s = viewer()
	fits := viewerImageBytes / len(photo)
	for i := 0; i <= fits; i++ {
		if feed(s, strconv.Itoa(2*i+1), photo) != (i < fits) {
			t.Fatalf("open photograph %d: accepted %v, want %v", i+1, i >= fits, i < fits)
		}
	}
	// Images waiting to be rebuilt hold at most viewerImageBytes too: past it
	// the reader waits for them rather than refusing.
	s = viewer()
	for i := 0; i < 3*fits; i++ {
		id := strconv.Itoa(2*i + 1)
		if !feed(s, id, photo) || !s.drawing(instruction{"end", id}) {
			t.Fatalf("photograph %d was refused", i+1)
		}
		if i == 0 && (s.jobBytes != len(photo) || s.imageBytes != 0) {
			t.Fatalf("an ended photograph moved %d bytes to the jobs and left %d open, want %d and 0", s.jobBytes, s.imageBytes, len(photo))
		}
		if s.jobBytes > viewerImageBytes {
			t.Fatalf("images waiting to be rebuilt hold %d bytes", s.jobBytes)
		}
	}
	if !s.settle(true) || s.jobBytes != 0 || s.imageBytes != 0 {
		t.Fatalf("after every image: %d bytes waiting, %d open", s.jobBytes, s.imageBytes)
	}
}

func TestViewerRevocationEndsAPacedWait(t *testing.T) {
	s, _ := pacedViewer(t)
	s.render.debt = renderBurst
	s.sleep = func(time.Duration) { s.closed.Store(true) }
	if s.drawing(instruction{"copy", "0", "0", "0", "1", "1", "14", "0", "0", "0"}) {
		t.Fatal("revoked viewer kept drawing after its pause")
	}
}

// Why a desktop ended by itself reaches the page as one fixed word, read from
// guacd's status code alone; its message never counts, and a failure with no
// word of its own gives none.
func TestViewerSaysWhyTheDesktopEnded(t *testing.T) {
	for _, c := range []struct {
		from []instruction
		want terminalweb.Reason
	}{
		{[]instruction{{"error", "Authentication failure (invalid credentials?)", "769"}}, terminalweb.ReasonCredentials},
		{[]instruction{{"error", "<b>any text</b>", "769"}}, terminalweb.ReasonCredentials},
		{[]instruction{{"error", "Access denied by server (account locked/disabled?)", "771"}}, terminalweb.ReasonAccount},
		{[]instruction{{"error", "Disconnected by other connection.", "521"}}, terminalweb.ReasonTakenOver},
		{[]instruction{{"error", "Idle session time limit exceeded.", "522"}}, terminalweb.ReasonRemoteEnded},
		{[]instruction{{"error", "Logged off.", "523"}}, terminalweb.ReasonRemoteEnded},
		{[]instruction{{"disconnect"}}, terminalweb.ReasonRemoteEnded},
		{[]instruction{{"error", "Connection failed (server unreachable?)", "519"}}, terminalweb.ReasonUnreachable},
		{[]instruction{{"error", "Server refused connection.", "520"}}, terminalweb.ReasonUnreachable},
		{[]instruction{{"error", "User is not responding.", "776"}}, terminalweb.ReasonNotResponding},
		{[]instruction{{"error", "Upstream error.", "515"}}, ""},
		{[]instruction{{"error", "Authentication failure", "x769"}}, terminalweb.ReasonRefused},
		{[]instruction{{"argv", "0", "text/plain", "password"}}, terminalweb.ReasonRefused},
		{[]instruction{{"rect", "0", "0", "0", "99999", "1"}}, terminalweb.ReasonRefused},
		{[]instruction{{"disconnect", "now"}}, terminalweb.ReasonRefused},
		{nil, ""}, // guacd's connection just closed
	} {
		s, remote, _ := viewerFixture(t)
		_, _ = s.Read(make([]byte, 128))
		go func() {
			for _, in := range c.from {
				if writeInstruction(remote, in) != nil {
					return
				}
			}
			if c.from == nil {
				_ = remote.Close()
			}
		}()
		if n, err := s.Read(make([]byte, 4096)); n != 0 || err != errNative {
			t.Fatalf("%q did not end the desktop", c.from)
		}
		if got := s.Reason(); got != c.want {
			t.Fatalf("%q gave %q, want %q", c.from, got, c.want)
		}
	}
	if newViewerStream(nil).Reason() != "" {
		t.Fatal("a viewer with no native side gave a reason")
	}
}

// guacd ends a user it hears nothing from for 15 seconds, and a hidden page
// runs Guacamole's keep-alive as rarely as once a minute: the gateway keeps its
// own link to guacd alive while the browser has been heard from recently.
func TestViewerKeepsGuacdAliveWhileTheBrowserIsHeard(t *testing.T) {
	s, _, input := viewerFixture(t)
	var clock atomic.Int64
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	s.clock = func() time.Time { return time.Unix(0, clock.Load()) }
	s.heard.Store(clock.Load())
	ticks := make(chan time.Time)
	stopped := make(chan struct{})
	go func() { defer close(stopped); s.keepAlive(ticks) }()
	next := func(want instruction) {
		t.Helper()
		select {
		case in := <-input:
			if !bytes.Equal(encodedInstruction(t, in), encodedInstruction(t, want)) {
				t.Fatalf("guacd got %q, want %q", in, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("guacd did not get %q", want)
		}
	}
	ticks <- time.Time{}
	next(instruction{"nop"})
	clock.Add(int64(browserQuiet))
	ticks <- time.Time{}
	next(instruction{"nop"})
	// Silent for longer than browserQuiet: guacd is left to end the session.
	// The second tick returns only once the first has been handled.
	clock.Add(int64(time.Second))
	ticks <- time.Time{}
	ticks <- time.Time{}
	mouse := instruction{"mouse", "40", "50", "0"}
	if _, err := s.Write(encodedInstruction(t, mouse)); err != nil {
		t.Fatal("valid browser input refused")
	}
	next(mouse)
	// That input was the browser being heard again.
	ticks <- time.Time{}
	next(instruction{"nop"})
	_ = s.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("keep-alive outlived its stream")
	}
}

// A browser that falls behind on frames, as a hidden page does, is not ended:
// the oldest unanswered frame is forgotten and a late answer to it dropped.
// Only answers to frames actually sent reach guacd.
func TestViewerForgetsOldFramesAndDropsTheirAnswers(t *testing.T) {
	s, remote, input := viewerFixture(t)
	_, _ = s.Read(make([]byte, 128))
	const first, count = 1000, viewerSyncs + 2
	go func() {
		for i := range count {
			if writeInstruction(remote, instruction{"sync", strconv.Itoa(first + i)}) != nil {
				return
			}
		}
	}()
	r := bufio.NewReader(s)
	for i := range count {
		in, err := readInstruction(r)
		if err != nil || len(in) != 2 || in[0] != "sync" || in[1] != strconv.Itoa(first+i) {
			t.Fatal("a frame past the remembered ones ended the session")
		}
	}
	if len(s.syncs) != viewerSyncs {
		t.Fatalf("remembered %d unanswered frames, want %d", len(s.syncs), viewerSyncs)
	}
	newest, oldest := strconv.Itoa(first+count-1), strconv.Itoa(first+2)
	for _, answer := range []string{strconv.Itoa(first), newest, newest, oldest, strconv.Itoa(first + 1)} {
		if _, err := s.Write(encodedInstruction(t, instruction{"sync", answer})); err != nil {
			t.Fatalf("answer to frame %s ended the session", answer)
		}
	}
	if _, err := s.Write(encodedInstruction(t, instruction{"nop"})); err != nil {
		t.Fatal("valid browser input refused")
	}
	for _, want := range []instruction{{"sync", newest}, {"sync", oldest}, {"nop"}} {
		select {
		case in := <-input:
			if !bytes.Equal(encodedInstruction(t, in), encodedInstruction(t, want)) {
				t.Fatalf("guacd got %q, want %q", in, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("guacd did not get %q", want)
		}
	}
	for _, answer := range []string{strconv.Itoa(first + count), "0" + newest, "-1", ""} {
		s, remote, _ := viewerFixture(t)
		_, _ = s.Read(make([]byte, 128))
		go func() { _ = writeInstruction(remote, instruction{"sync", newest}) }()
		if in, err := readInstruction(bufio.NewReader(s)); err != nil || in[0] != "sync" {
			t.Fatal("valid frame refused")
		}
		if _, err := s.Write(encodedInstruction(t, instruction{"sync", answer})); err != errNative {
			t.Fatalf("answer to a frame never sent (%q) accepted", answer)
		}
	}
}
