package rdplab

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/adler32"
	"image"
	"image/color"
	"image/png"
	"io"
	"math/rand/v2"
	"testing"
)

// chunks lists a PNG's chunk types, checking each length and CRC.
func pngChunks(t *testing.T, data []byte) ([]string, []byte) {
	t.Helper()
	if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("no PNG signature")
	}
	var kinds []string
	var idat []byte
	for rest := data[8:]; len(rest) > 0; {
		if len(rest) < 12 {
			t.Fatal("truncated chunk")
		}
		n := int(binary.BigEndian.Uint32(rest))
		if len(rest) < 12+n {
			t.Fatal("chunk longer than the file")
		}
		kind := string(rest[4:8])
		kinds = append(kinds, kind)
		if kind == "IDAT" {
			idat = append(idat, rest[8:8+n]...)
		}
		rest = rest[12+n:]
	}
	return kinds, idat
}

// The fast encoder's output is a minimal PNG whose pixels are exactly the
// input's, at every size from one pixel to a full screen, with and without
// transparency, as one band or many.
func TestFastPNGKeepsEveryPixelAndNothingElse(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	sizes := [][2]int{{1, 1}, {1, 300}, {300, 1}, {63, 65}, {256, 256}, {300, 700}, {1920, 1080}}
	for _, size := range sizes {
		for _, alpha := range []bool{false, true} {
			w, h := size[0], size[1]
			var img image.Image
			if alpha {
				m := image.NewNRGBA(image.Rect(0, 0, w, h))
				for i := range m.Pix {
					m.Pix[i] = uint8(r.IntN(256))
				}
				m.Pix[3] = 0x7f // at least one pixel is not opaque
				img = m
			} else {
				m := desktopLike(w, h, uint64(w*h))
				img = m
			}
			out, ok := fastPNG(img, 64<<20)
			if !ok {
				t.Fatalf("%dx%d alpha=%v refused", w, h, alpha)
			}
			kinds, idat := pngChunks(t, out)
			if len(kinds) != 3 || kinds[0] != "IHDR" || kinds[1] != "IDAT" || kinds[2] != "IEND" {
				t.Fatalf("%dx%d: chunks %v", w, h, kinds)
			}
			// The joined bands are one zlib stream whose checksum holds.
			z, err := zlib.NewReader(bytes.NewReader(idat))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, z); err != nil {
				t.Fatalf("%dx%d: the image data does not read to its end: %v", w, h, err)
			}
			back, err := png.Decode(bytes.NewReader(out))
			if err != nil {
				t.Fatalf("%dx%d: %v", w, h, err)
			}
			if back.Bounds() != img.Bounds() {
				t.Fatalf("%dx%d came back %v", w, h, back.Bounds())
			}
			for y := 0; y < h; y++ {
				for x := 0; x < w; x++ {
					if color.NRGBAModel.Convert(back.At(x, y)) != color.NRGBAModel.Convert(img.At(x, y)) {
						t.Fatalf("%dx%d alpha=%v: pixel %d,%d changed", w, h, alpha, x, y)
					}
				}
			}
		}
	}
}

// What the fast encoder does not take, it leaves to the standard one; what
// does not fit is refused, never cut.
func TestFastPNGLeavesTheRestToTheStandardEncoder(t *testing.T) {
	premultiplied := image.NewRGBA(image.Rect(0, 0, 4, 4))
	premultiplied.Pix[3] = 0x80
	for name, img := range map[string]image.Image{
		"premultiplied transparency": premultiplied,
		"grey":                       image.NewGray(image.Rect(0, 0, 4, 4)),
		"16-bit":                     image.NewNRGBA64(image.Rect(0, 0, 4, 4)),
		"paletted":                   image.NewPaletted(image.Rect(0, 0, 4, 4), color.Palette{color.Black}),
		"empty":                      image.NewRGBA(image.Rect(0, 0, 0, 0)),
	} {
		if _, ok := fastPNG(img, 1<<20); ok {
			t.Fatalf("%s was taken by the fast encoder", name)
		}
		if name == "empty" {
			continue
		}
		out, ok := normalizedPNG(img, 1<<20)
		if !ok {
			t.Fatalf("%s was not normalized", name)
		}
		if _, err := png.Decode(bytes.NewReader(out)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	noisy := image.NewNRGBA(image.Rect(0, 0, 512, 512))
	r := rand.New(rand.NewPCG(3, 4))
	for i := range noisy.Pix {
		noisy.Pix[i] = uint8(r.IntN(256))
	}
	if out, ok := fastPNG(noisy, 64*1024); ok || out != nil {
		t.Fatal("an image over the limit was written")
	}
	if _, ok := normalizedPNG(noisy, 64*1024); ok {
		t.Fatal("an image over the limit was normalized")
	}
}

func TestAdler32CombineIsTheChecksumOfTheJoinedRuns(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	for i := 0; i < 200; i++ {
		a := make([]byte, r.IntN(200000))
		b := make([]byte, r.IntN(200000))
		for j := range a {
			a[j] = uint8(r.IntN(256))
		}
		for j := range b {
			b[j] = 0xff // long runs of high bytes push both sums toward the modulus
			if r.IntN(7) == 0 {
				b[j] = uint8(r.IntN(256))
			}
		}
		want := adler32.Checksum(append(append([]byte(nil), a...), b...))
		if got := adler32Combine(adler32.Checksum(a), adler32.Checksum(b), int64(len(b))); got != want {
			t.Fatalf("combined %08x, want %08x (%d+%d bytes)", got, want, len(a), len(b))
		}
	}
}

// The viewer takes the fast path for what a desktop sends: every row of the
// image it forwards carries the one Sub filter that path writes.
func TestViewerNormalizesThroughTheFastEncoder(t *testing.T) {
	data := encodedFixture(t, desktopLike(300, 200, 11))
	decoded, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out, ok := normalizedPNG(decoded, 256*1024)
	if !ok {
		t.Fatal("normalization refused")
	}
	_, idat := pngChunks(t, out)
	z, err := zlib.NewReader(bytes.NewReader(idat))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	if err != nil || len(raw) != 200*(1+300*3) {
		t.Fatalf("image data %d bytes, %v", len(raw), err)
	}
	for y := 0; y < 200; y++ {
		if raw[y*(1+300*3)] != 1 {
			t.Fatalf("row %d was not written by the fast encoder", y)
		}
	}
}

func encodedFixture(t *testing.T, img image.Image) []byte {
	t.Helper()
	var out bytes.Buffer
	if png.Encode(&out, img) != nil {
		t.Fatal("fixture encoding failed")
	}
	return out.Bytes()
}
