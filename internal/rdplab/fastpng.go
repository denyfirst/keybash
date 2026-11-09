package rdplab

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/adler32"
	"hash/crc32"
	"image"
	"runtime"
	"sync"
)

// fastPNG writes the decoded image again as a minimal PNG for the browser:
// IHDR, one IDAT and IEND, nothing else, 8 bits per channel, RGB when every
// pixel is opaque and RGBA otherwise. It is the same normalization the
// standard encoder gives (only pixels survive, never the sender's chunks or
// compressed stream), several times faster:
//   - every row uses the one cheap Sub filter instead of trying all five;
//   - a large image is compressed in bands at once, one per processor, each
//     band a complete deflate segment ending on a byte boundary, so the bands
//     join into one ordinary zlib stream that any decoder reads;
//   - compressors are reused, reset before each band.
//
// It handles the two layouts the PNG decoder gives for 8-bit colour; anything
// else, or an image that would not fit in limit, is left to the standard
// encoder.
func fastPNG(img image.Image, limit int) ([]byte, bool) {
	var pix []byte
	var stride, w, h int
	var nonPremultiplied bool
	switch m := img.(type) {
	case *image.NRGBA:
		pix, stride, nonPremultiplied = m.Pix, m.Stride, true
		w, h = m.Rect.Dx(), m.Rect.Dy()
	case *image.RGBA:
		pix, stride = m.Pix, m.Stride
		w, h = m.Rect.Dx(), m.Rect.Dy()
	default:
		return nil, false
	}
	if w < 1 || h < 1 || w > 1<<14 || h > 1<<14 || len(pix) < (h-1)*stride+4*w {
		return nil, false
	}
	opaque := true
	for y := 0; y < h && opaque; y++ {
		row := pix[y*stride : y*stride+4*w]
		for i := 3; i < len(row); i += 4 {
			if row[i] != 0xff {
				opaque = false
				break
			}
		}
	}
	// A premultiplied image with transparency needs dividing back out; the
	// standard encoder does that, and remote desktops send it rarely.
	if !opaque && !nonPremultiplied {
		return nil, false
	}
	channels := 4
	colour := byte(6) // truecolour with alpha
	if opaque {
		channels, colour = 3, 2 // truecolour
	}

	// Bands of at least 64 rows and 64K pixels; a small image is one band.
	bands := min(runtime.GOMAXPROCS(0), h/64, w*h/(64*1024), 16)
	bands = max(bands, 1)
	type band struct {
		data  bytes.Buffer
		sum   uint32
		size  int64
		ok    bool
		first int
	}
	parts := make([]band, bands)
	compress := func(b *band, from, to int, last bool) {
		z := flateWriters.Get().(*flate.Writer)
		defer flateWriters.Put(z)
		z.Reset(&b.data)
		sum := adler32.New()
		row := make([]byte, 1+channels*w)
		row[0] = 1 // Sub: each byte minus the same channel of the pixel to its left
		for y := from; y < to; y++ {
			filterSub(row[1:], pix[y*stride:y*stride+4*w], channels)
			_, _ = sum.Write(row)
			if _, err := z.Write(row); err != nil || b.data.Len() > limit {
				return
			}
		}
		// A band that is not the last ends with a sync flush: an empty
		// stored block that ends on a byte, so the next band can follow it.
		var err error
		if last {
			err = z.Close()
		} else {
			err = z.Flush()
		}
		b.sum, b.size, b.ok = sum.Sum32(), int64(to-from)*int64(len(row)), err == nil
	}
	var wg sync.WaitGroup
	for i := range parts {
		from, to := i*h/bands, (i+1)*h/bands
		parts[i].first = from
		wg.Add(1)
		go func() { defer wg.Done(); compress(&parts[i], from, to, i == bands-1) }()
	}
	wg.Wait()

	sum, total := uint32(1), 0
	for i := range parts {
		if !parts[i].ok {
			return nil, false
		}
		sum = adler32Combine(sum, parts[i].sum, parts[i].size)
		total += parts[i].data.Len()
	}
	if total+64 > limit {
		return nil, false
	}
	out := bytes.NewBuffer(make([]byte, 0, total+64))
	out.WriteString("\x89PNG\r\n\x1a\n")
	var ihdr [13]byte
	binary.BigEndian.PutUint32(ihdr[0:], uint32(w)) // #nosec G115 -- bounded above to 1..16384
	binary.BigEndian.PutUint32(ihdr[4:], uint32(h)) // #nosec G115 -- bounded above to 1..16384
	ihdr[8], ihdr[9] = 8, colour                    // bit depth; compression, filter and interlace stay 0
	writeChunk(out, "IHDR", ihdr[:])
	idat := make([]byte, 0, total+6)
	idat = append(idat, 0x78, 0x01) // zlib: deflate, 32 KiB window, fastest
	for i := range parts {
		idat = append(idat, parts[i].data.Bytes()...)
	}
	idat = binary.BigEndian.AppendUint32(idat, sum)
	writeChunk(out, "IDAT", idat)
	writeChunk(out, "IEND", nil)
	return out.Bytes(), true
}

// filterSub writes one row with the Sub filter, dropping alpha when the image
// is opaque (three channels).
func filterSub(dst, src []byte, channels int) {
	if channels == 3 {
		var r, g, b byte
		for x, o := 0, 0; x+3 < len(src); x, o = x+4, o+3 {
			dst[o], dst[o+1], dst[o+2] = src[x]-r, src[x+1]-g, src[x+2]-b
			r, g, b = src[x], src[x+1], src[x+2]
		}
		return
	}
	var r, g, b, a byte
	for x := 0; x+3 < len(src); x += 4 {
		dst[x], dst[x+1], dst[x+2], dst[x+3] = src[x]-r, src[x+1]-g, src[x+2]-b, src[x+3]-a
		r, g, b, a = src[x], src[x+1], src[x+2], src[x+3]
	}
}

// adler32Combine is zlib's: the checksum of two byte runs joined, from each
// run's checksum and the second run's length.
func adler32Combine(a1, a2 uint32, len2 int64) uint32 {
	const base = 65521
	rem := uint32(len2 % base) // #nosec G115 -- below base
	sum1 := a1 & 0xffff
	sum2 := (rem * sum1) % base
	sum1 += (a2 & 0xffff) + base - 1
	sum2 += (a1 >> 16) + (a2 >> 16) + base - rem
	if sum1 >= base {
		sum1 -= base
	}
	if sum1 >= base {
		sum1 -= base
	}
	if sum2 >= base<<1 {
		sum2 -= base << 1
	}
	if sum2 >= base {
		sum2 -= base
	}
	return sum2<<16 | sum1
}

// One compressor per band at a time, reset before each: Reset drops all
// earlier input, so nothing of one image or session reaches another's output.
var flateWriters = sync.Pool{New: func() any {
	z, _ := flate.NewWriter(nil, flate.BestSpeed)
	return z
}}

func writeChunk(out *bytes.Buffer, kind string, data []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(data))) // #nosec G115 -- chunks here are bounded by the caller's limit
	out.Write(n[:])
	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte(kind))
	_, _ = crc.Write(data)
	out.WriteString(kind)
	out.Write(data)
	binary.BigEndian.PutUint32(n[:], crc.Sum32())
	out.Write(n[:])
}
