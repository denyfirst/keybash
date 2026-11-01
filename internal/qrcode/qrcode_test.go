package qrcode

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"testing"
)

// corpus is deterministic: every length from 1 to 213 bytes (versions 1 to
// 10), inputs for which the penalty rules choose each of the eight masks, and
// authenticator key URIs like the ones Keybash draws.
func corpus() []string {
	var out []string
	for length := 1; length <= 213; length++ {
		s := "k"
		for i := 0; len(s) < length; i++ {
			sum := sha256.Sum256([]byte("keybash-qr-" + strconv.Itoa(length) + "-" + strconv.Itoa(i)))
			s += hex.EncodeToString(sum[:]) + "&/:?=."
		}
		out = append(out, s[:length])
	}
	out = append(out, "ka", "kd5a8df1158491b89c", "otpauth://totp/Keybash:u0?secret=f322ba8ea890ba4cd424&issuer=Keybash",
		"kcf650", "k2c", "kefcce84493b6aad98697225c8b11e", "otpauth://totp/Keybash:u6?secret=8c787adc7b3ea7f2ae25&issuer=Keybash",
		"otpauth://totp/Keybash:u249?secret=413ec1981336b2ff7093&issuer=Keybash")
	for _, user := range []string{"a", "alice", "alice.ops-1", "bob_admin", "x-y.z", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		out = append(out, "otpauth://totp/Keybash:"+user+"?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Keybash")
	}
	return out
}

// The digest of every corpus code, row by row as "0" and "1", exactly as the
// third-party encoder this package replaced drew them
// (github.com/boombuler/barcode, qr.Encode(input, qr.M, qr.Auto)). The same
// codes were also decoded independently (jsQR 1.4.0) back to their inputs.
const drawnBefore = "d083cee6309d4ab6c03b82bf40e50c40ae8b68888af4f84593fdf7e9d7660353"

func TestEncodeDrawsWhatKeybashDrewBefore(t *testing.T) {
	all := sha256.New()
	masks := map[int]bool{}
	for _, input := range corpus() {
		rows, e := Encode([]byte(input))
		if e != nil {
			t.Fatalf("refused %d bytes", len(input))
		}
		for _, row := range rows {
			line := make([]byte, len(row))
			for x, dark := range row {
				line[x] = '0'
				if dark {
					line[x] = '1'
				}
			}
			all.Write(line)
		}
		masks[formatOf(t, rows)&7] = true
	}
	if len(masks) != 8 {
		t.Fatal("the corpus no longer reaches every mask")
	}
	if got := hex.EncodeToString(all.Sum(nil)); got != drawnBefore {
		t.Fatalf("codes differ from the ones drawn before: %s", got)
	}
}

// ISO/IEC 18004's worked example, as thonky.com's QR tutorial gives it:
// "HELLO WORLD" at 1-M, data codewords and their error correction.
func TestErrorCorrectionMatchesThePublishedExample(t *testing.T) {
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}
	if got := remainder(data, 10); !bytes.Equal(got, want) {
		t.Fatalf("error correction %v, want %v", got, want)
	}
}

// Every version's function patterns leave exactly its codewords' modules,
// plus the standard's remainder bits (7 for versions 2 to 6).
func TestLayoutsFillTheirSymbols(t *testing.T) {
	totals := []int{0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346}
	for v := 1; v < len(layouts); v++ {
		l := layouts[v]
		total := l.dataCodewords() + (l.groups[0][0]+l.groups[1][0])*l.ecPerBlock
		free := 0
		for _, row := range newSymbol(v, l).reserved {
			for _, used := range row {
				if !used {
					free++
				}
			}
		}
		remainderBits := 0
		if v >= 2 && v <= 6 {
			remainderBits = 7
		}
		if total != totals[v] || free != 8*total+remainderBits {
			t.Fatalf("version %d: %d codewords, %d data modules", v, total, free)
		}
	}
}

// formatOf reads and checks both copies of the format information and
// returns its five data bits.
func formatOf(t *testing.T, rows [][]bool) int {
	t.Helper()
	n := len(rows)
	first, second := 0, 0
	for i := range 15 {
		var x, y int
		switch {
		case i < 6:
			x, y = 8, i
		case i < 8:
			x, y = 8, i+1
		case i == 8:
			x, y = 7, 8
		default:
			x, y = 14-i, 8
		}
		if rows[y][x] {
			first |= 1 << i
		}
		x, y = n-1-i, 8
		if i >= 8 {
			x, y = 8, n-15+i
		}
		if rows[y][x] {
			second |= 1 << i
		}
	}
	data := (first ^ 0x5412) >> 10
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	if first != second || (data<<10|rem)^0x5412 != first || data>>3 != 0 || !rows[n-8][8] {
		t.Fatal("format information is not level M, or its copies differ")
	}
	return data
}

// readBack decodes a code as a reader would: format, version information,
// unmasked codewords in placement order, blocks whose error correction
// syndromes are zero, then the byte-mode segment.
func readBack(t *testing.T, rows [][]bool) []byte {
	t.Helper()
	n := len(rows)
	version := (n - 17) / 4
	if n < 21 || n > 57 || (n-17)%4 != 0 {
		t.Fatalf("%d modules is no version from 1 to 10", n)
	}
	for _, row := range rows {
		if len(row) != n {
			t.Fatal("not square")
		}
	}
	mask := formatOf(t, rows) & 7
	if version >= 7 {
		for i := range 18 {
			a, b := n-11+i%3, i/3
			if rows[b][a] != ((version<<12|bch18(version))>>i&1 == 1) || rows[a][b] != rows[b][a] {
				t.Fatal("version information is wrong")
			}
		}
	}
	l := layouts[version]
	reserved := newSymbol(version, l).reserved
	var bits []bool
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		upward := (right+1)&2 == 0
		for vert := range n {
			y := vert
			if upward {
				y = n - 1 - vert
			}
			for x := right; x >= right-1; x-- {
				if !reserved[y][x] {
					bits = append(bits, rows[y][x] != masked(mask, x, y))
				}
			}
		}
	}
	blocks := l.groups[0][0] + l.groups[1][0]
	total := l.dataCodewords() + blocks*l.ecPerBlock
	if slices.Contains(bits[8*total:], true) {
		t.Fatal("remainder modules are not light")
	}
	codewords := make([]byte, total)
	for i := range codewords {
		for _, bit := range bits[8*i : 8*i+8] {
			codewords[i] <<= 1
			if bit {
				codewords[i] |= 1
			}
		}
	}
	sized := make([][]byte, 0, blocks)
	for _, group := range l.groups {
		for range group[0] {
			sized = append(sized, make([]byte, 0, group[1]+l.ecPerBlock))
		}
	}
	next := 0
	for i := range max(l.groups[0][1], l.groups[1][1]) {
		for b, group := 0, 0; b < blocks; b++ {
			if b == l.groups[0][0] {
				group = 1
			}
			if i < l.groups[group][1] {
				sized[b] = append(sized[b], codewords[next])
				next++
			}
		}
	}
	for range l.ecPerBlock {
		for b := range sized {
			sized[b] = append(sized[b], codewords[next])
			next++
		}
	}
	var data []byte
	for b, block := range sized {
		for j := range l.ecPerBlock {
			syndrome := byte(0)
			for _, c := range block {
				syndrome = mul(syndrome, exp[j]) ^ c
			}
			if syndrome != 0 {
				t.Fatalf("block %d fails error correction", b)
			}
		}
		data = append(data, block[:len(block)-l.ecPerBlock]...)
	}
	at := 0
	take := func(width int) int {
		v := 0
		for range width {
			v = v<<1 | int(data[at>>3]>>(7-at&7)&1)
			at++
		}
		return v
	}
	if take(4) != 0b0100 {
		t.Fatal("not byte mode")
	}
	out := make([]byte, take(countBits(version)))
	for i := range out {
		out[i] = byte(take(8))
	}
	return out
}

func bch18(version int) int {
	rem := version
	for range 12 {
		rem = rem<<1 ^ (rem>>11)*0x1F25
	}
	return rem
}

func TestEveryCodeReadsBack(t *testing.T) {
	for _, input := range append(corpus(), "", "\x00\xff binary \x80") {
		rows, e := Encode([]byte(input))
		if e != nil {
			t.Fatalf("refused %d bytes", len(input))
		}
		if got := readBack(t, rows); string(got) != input {
			t.Fatalf("read back %q, want %q", got, input)
		}
	}
}

func TestEncodeTakesUpTo213Bytes(t *testing.T) {
	for length, size := range map[int]int{0: 21, 14: 21, 15: 25, 180: 53, 181: 57, 213: 57} {
		if rows, e := Encode(bytes.Repeat([]byte("k"), length)); e != nil || len(rows) != size {
			t.Fatalf("%d bytes: %d modules, want %d (%v)", length, len(rows), size, e)
		}
	}
	for _, length := range []int{214, 4096} {
		if rows, e := Encode(make([]byte, length)); !errors.Is(e, ErrTooLong) || rows != nil {
			t.Fatalf("%d bytes were not refused", length)
		}
	}
}
