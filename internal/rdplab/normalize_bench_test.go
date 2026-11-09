package rdplab

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math/rand/v2"
	"testing"
)

// desktopLike draws what a remote desktop sends: flat window areas, lines of
// text set from a small font of anti-aliased glyphs, and a photograph in one
// corner, opaque as guacd's screen updates are.
func desktopLike(w, h int, seed uint64) *image.RGBA {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	var glyphs [80][12][7]uint8
	for g := range glyphs {
		for y := 2; y < 11; y++ {
			for x := 0; x < 6; x++ {
				if r.IntN(3) == 0 {
					glyphs[g][y][x] = uint8(120 + r.IntN(136))
				}
			}
		}
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{0xf3, 0xf3, 0xf3, 0xff}
			switch {
			case y < 32:
				c = color.RGBA{0x20, 0x2a, 0x3a, 0xff} // a title bar
			case x >= w*3/4 && y >= h*3/4:
				// A photograph: smooth gradients with sensor noise.
				n := uint8(r.IntN(24))
				c = color.RGBA{uint8(x*255/w) ^ n, uint8(y*255/h) + n, uint8((x+y)*127/(w+h)) + n, 0xff}
			case x > 16 && x < w*3/5 && y > 48:
				// Text: words of glyphs on white lines, gaps between words.
				line, col := (y-48)/18, (x-16)/7
				c = color.RGBA{0xff, 0xff, 0xff, 0xff}
				if (col+line*3)%9 != 8 && (y-48)%18 < 12 {
					if v := glyphs[(col*31+line*17)%80][(y-48)%18][(x-16)%7]; v > 0 {
						c = color.RGBA{255 - v, 255 - v, 255 - v/2, 0xff}
					}
				}
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img
}

func encoded(b *testing.B, img image.Image) []byte {
	b.Helper()
	var out bytes.Buffer
	if png.Encode(&out, img) != nil {
		b.Fatal("fixture encoding failed")
	}
	return out.Bytes()
}

// BenchmarkNormalizeDesktop is the work the viewer does for every image guacd
// sends: decode it, then re-encode it for the browser. Sizes are a full
// 1920x1080 update and a typical 256x256 changed tile.
func BenchmarkNormalizeDesktop(b *testing.B) {
	for _, size := range []struct {
		name string
		w, h int
	}{{"full-1080p", 1920, 1080}, {"tile-256", 256, 256}} {
		data := encoded(b, desktopLike(size.w, size.h, 7))
		b.Run(size.name, func(b *testing.B) {
			b.SetBytes(int64(size.w * size.h * 4))
			for b.Loop() {
				decoded, err := png.Decode(bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
				if _, ok := normalizedPNG(decoded, 16<<20); !ok {
					b.Fatal("normalization refused")
				}
			}
		})
	}
}

func BenchmarkDecodeOnlyDesktop(b *testing.B) {
	data := encoded(b, desktopLike(1920, 1080, 7))
	b.SetBytes(1920 * 1080 * 4)
	for b.Loop() {
		if _, err := png.Decode(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFastNormalizeDesktop(b *testing.B) {
	for _, size := range []struct {
		name string
		w, h int
	}{{"full-1080p", 1920, 1080}, {"tile-256", 256, 256}} {
		data := encoded(b, desktopLike(size.w, size.h, 7))
		b.Run(size.name, func(b *testing.B) {
			b.SetBytes(int64(size.w * size.h * 4))
			var n int
			for b.Loop() {
				decoded, err := png.Decode(bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
				out, ok := fastPNG(decoded, 16<<20)
				if !ok {
					b.Fatal("fast normalization refused")
				}
				n = len(out)
			}
			b.ReportMetric(float64(n), "bytes")
			b.ReportMetric(float64(len(data)), "input-bytes")
		})
	}
}
