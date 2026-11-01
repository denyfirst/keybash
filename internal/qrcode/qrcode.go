// Package qrcode draws a QR code (ISO/IEC 18004) for the one thing Keybash
// shows as one: an authenticator's key URI, at enrollment. It encodes bytes in
// byte mode at error correction level M, in versions 1 to 10 (at most 213
// bytes, 57 modules a side), and chooses the mask by the standard's four
// penalty rules. There is no other mode, level or version, and no image: the
// caller receives the modules and the browser draws them.
//
// It replaces a third-party encoder whose output it reproduces module for
// module, so a code drawn before and after the change is the same.
package qrcode

import "errors"

// ErrTooLong refuses data that does not fit version 10 at level M.
var ErrTooLong = errors.New("qrcode: data does not fit version 10-M")

// layout is one version at level M: error correction codewords per block,
// then up to two groups of {blocks, data codewords per block}, and the
// alignment pattern centres (ISO/IEC 18004 tables 9 and E.1).
type layout struct {
	ecPerBlock int
	groups     [2][2]int
	align      []int
}

var layouts = [...]layout{
	1:  {10, [2][2]int{{1, 16}}, nil},
	2:  {16, [2][2]int{{1, 28}}, []int{6, 18}},
	3:  {26, [2][2]int{{1, 44}}, []int{6, 22}},
	4:  {18, [2][2]int{{2, 32}}, []int{6, 26}},
	5:  {24, [2][2]int{{2, 43}}, []int{6, 30}},
	6:  {16, [2][2]int{{4, 27}}, []int{6, 34}},
	7:  {18, [2][2]int{{4, 31}}, []int{6, 22, 38}},
	8:  {22, [2][2]int{{2, 38}, {2, 39}}, []int{6, 24, 42}},
	9:  {22, [2][2]int{{3, 36}, {2, 37}}, []int{6, 26, 46}},
	10: {26, [2][2]int{{4, 43}, {1, 44}}, []int{6, 28, 50}},
}

func (l layout) dataCodewords() int {
	return l.groups[0][0]*l.groups[0][1] + l.groups[1][0]*l.groups[1][1]
}

// Encode returns the smallest level-M code for data, as rows from the top,
// each a slice of modules from the left, true for dark. The quiet zone is
// the caller's.
func Encode(data []byte) ([][]bool, error) {
	version := 0
	for v := 1; v < len(layouts); v++ {
		if 4+countBits(v)+8*len(data) <= 8*layouts[v].dataCodewords() {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, ErrTooLong
	}
	l := layouts[version]
	base := newSymbol(version, l)
	base.place(interleave(l, segment(data, version, l.dataCodewords())))

	var best *symbol
	bestPenalty := -1
	for mask := range 8 {
		s := base.clone()
		s.applyMask(mask)
		s.drawFormat(mask)
		if p := s.penalty(); bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = s, p
		}
	}
	return best.dark, nil
}

// countBits is the width of byte mode's character count field.
func countBits(version int) int {
	if version < 10 {
		return 8
	}
	return 16
}

// segment is the data codeword sequence: byte mode, the count, the bytes,
// a terminator of up to four zero bits, zero bits to a byte boundary, then
// the alternating pad codewords 0xEC and 0x11.
func segment(data []byte, version, capacity int) []byte {
	var bits []bool
	put := func(value, width int) {
		for i := width - 1; i >= 0; i-- {
			bits = append(bits, value>>i&1 == 1)
		}
	}
	put(0b0100, 4)
	put(len(data), countBits(version))
	for _, b := range data {
		put(int(b), 8)
	}
	for i := 0; i < 4 && len(bits) < 8*capacity; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	out := make([]byte, 0, capacity)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for _, bit := range bits[i : i+8] {
			b <<= 1
			if bit {
				b |= 1
			}
		}
		out = append(out, b)
	}
	for pad := byte(0xEC); len(out) < capacity; pad ^= 0xEC ^ 0x11 {
		out = append(out, pad)
	}
	return out
}

// interleave splits the data codewords into the version's blocks, adds each
// block's error correction, and interleaves data then correction codewords.
func interleave(l layout, data []byte) []byte {
	var blocks, corrections [][]byte
	longest := 0
	for _, group := range l.groups {
		for range group[0] {
			block := data[:group[1]]
			data = data[group[1]:]
			blocks = append(blocks, block)
			corrections = append(corrections, remainder(block, l.ecPerBlock))
			longest = max(longest, len(block))
		}
	}
	var out []byte
	for i := range longest {
		for _, block := range blocks {
			if i < len(block) {
				out = append(out, block[i])
			}
		}
	}
	for i := range l.ecPerBlock {
		for _, correction := range corrections {
			out = append(out, correction[i])
		}
	}
	return out
}

// GF(256) with the QR code's polynomial x^8+x^4+x^3+x^2+1.
var exp, log [256]byte

func init() {
	x := 1
	for i := range 255 {
		exp[i] = byte(x)
		log[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
}

func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return exp[(int(log[a])+int(log[b]))%255]
}

// generator is (x-α^0)(x-α^1)…(x-α^(n-1)), highest degree first, without
// its leading 1.
func generator(n int) []byte {
	g := []byte{1}
	for i := range n {
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= mul(c, exp[i])
		}
		g = next
	}
	return g[1:]
}

// remainder is a block's n error correction codewords: the block times x^n,
// modulo the generator.
func remainder(block []byte, n int) []byte {
	g := generator(n)
	r := make([]byte, n)
	for _, d := range block {
		factor := d ^ r[0]
		copy(r, r[1:])
		r[n-1] = 0
		for i := range r {
			r[i] ^= mul(g[i], factor)
		}
	}
	return r
}

// symbol is the module grid, indexed [y][x], and which modules are function
// patterns rather than data.
type symbol struct {
	n        int
	dark     [][]bool
	reserved [][]bool
}

func grid(n int) [][]bool {
	g := make([][]bool, n)
	for y := range g {
		g[y] = make([]bool, n)
	}
	return g
}

func (s *symbol) set(x, y int, dark bool) {
	s.dark[y][x] = dark
	s.reserved[y][x] = true
}

func (s *symbol) clone() *symbol {
	c := &symbol{n: s.n, dark: grid(s.n), reserved: s.reserved}
	for y := range s.dark {
		copy(c.dark[y], s.dark[y])
	}
	return c
}

// newSymbol draws the function patterns: timing, the three finders with their
// separators, the alignment patterns, the dark module and, from version 7,
// the version information. The format areas are reserved here and written
// for each mask.
func newSymbol(version int, l layout) *symbol {
	n := 17 + 4*version
	s := &symbol{n: n, dark: grid(n), reserved: grid(n)}
	for i := range n {
		s.set(6, i, i%2 == 0)
		s.set(i, 6, i%2 == 0)
	}
	for _, centre := range [][2]int{{3, 3}, {n - 4, 3}, {3, n - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := centre[0]+dx, centre[1]+dy
				if x >= 0 && x < n && y >= 0 && y < n {
					ring := max(abs(dx), abs(dy))
					s.set(x, y, ring != 2 && ring != 4)
				}
			}
		}
	}
	last := len(l.align) - 1
	for i, cy := range l.align {
		for j, cx := range l.align {
			if i == 0 && j == 0 || i == 0 && j == last || i == last && j == 0 {
				continue // a finder is there
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					s.set(cx+dx, cy+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	s.drawFormat(0)
	s.set(8, n-8, true)
	if version >= 7 {
		rem := version
		for range 12 {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		bits := version<<12 | rem
		for i := range 18 {
			a, b := n-11+i%3, i/3
			s.set(a, b, bits>>i&1 == 1)
			s.set(b, a, bits>>i&1 == 1)
		}
	}
	return s
}

// drawFormat writes both copies of the 15-bit format information: level M
// (00) and the mask, BCH-protected and masked with 0x5412.
func (s *symbol) drawFormat(mask int) {
	rem := mask
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (mask<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 == 1 }
	n := s.n
	for i := range 6 {
		s.set(8, i, bit(i))
	}
	s.set(8, 7, bit(6))
	s.set(8, 8, bit(7))
	s.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		s.set(14-i, 8, bit(i))
	}
	for i := range 8 {
		s.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		s.set(8, n-15+i, bit(i))
	}
}

// place writes the codewords' bits, most significant first, up and down the
// two-module columns from the bottom right, skipping the vertical timing
// column. Remainder modules stay light.
func (s *symbol) place(codewords []byte) {
	i, total := 0, 8*len(codewords)
	for right := s.n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		upward := (right+1)&2 == 0
		for vert := range s.n {
			y := vert
			if upward {
				y = s.n - 1 - vert
			}
			for x := right; x >= right-1; x-- {
				if s.reserved[y][x] {
					continue
				}
				if i < total {
					s.dark[y][x] = codewords[i>>3]>>(7-i&7)&1 == 1
				}
				i++
			}
		}
	}
}

// masked reports whether mask inverts the module in column x, row y.
func masked(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

func (s *symbol) applyMask(mask int) {
	for y := range s.n {
		for x := range s.n {
			if !s.reserved[y][x] && masked(mask, x, y) {
				s.dark[y][x] = !s.dark[y][x]
			}
		}
	}
}

// penalty scores a finished symbol by the four rules: runs of five or more,
// 2×2 blocks, finder-like 1:1:3:1:1 runs with four light modules on one side
// inside the symbol, and the distance of the dark share from half.
func (s *symbol) penalty() int {
	n, score := s.n, 0
	at := func(line, i int, column bool) bool {
		if column {
			return s.dark[i][line]
		}
		return s.dark[line][i]
	}
	finder := [2][11]bool{
		{true, false, true, true, true, false, true, false, false, false, false},
		{false, false, false, false, true, false, true, true, true, false, true},
	}
	for _, column := range []bool{false, true} {
		for line := range n {
			run := 1
			for i := 1; i <= n; i++ {
				if i < n && at(line, i, column) == at(line, i-1, column) {
					run++
					continue
				}
				if run >= 5 {
					score += run - 2
				}
				run = 1
			}
			for start := 0; start+11 <= n; start++ {
				for _, pattern := range finder {
					same := true
					for k, dark := range pattern {
						if at(line, start+k, column) != dark {
							same = false
							break
						}
					}
					if same {
						score += 40
						break
					}
				}
			}
		}
	}
	dark := 0
	for y := range n {
		for x := range n {
			if s.dark[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n {
				c := s.dark[y][x]
				if s.dark[y][x+1] == c && s.dark[y+1][x] == c && s.dark[y+1][x+1] == c {
					score += 3
				}
			}
		}
	}
	total := n * n
	low, high := 20*dark/total, (20*dark+total-1)/total
	return score + 10*min(abs(low-10), abs(high-10))
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
