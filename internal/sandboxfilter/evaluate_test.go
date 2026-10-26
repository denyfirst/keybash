package sandboxfilter

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type instruction struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

func program(t *testing.T, list ...instruction) []byte {
	t.Helper()
	var raw bytes.Buffer
	if binary.Write(&raw, binary.LittleEndian, list) != nil {
		t.Fatal("fixture program encoding failed")
	}
	return raw.Bytes()
}

// A tiny filter with every supported opcode: kill a foreign arch, deny call
// 7, allow call 9 only when argument 0 has bit 4 set, allow the rest.
func TestEvaluateFollowsEveryBranch(t *testing.T) {
	const kill, deny, allow = 0x80000000, 0x50001, 0x7fff0000
	p := program(t,
		instruction{opLoadAbsWord, 0, 0, 4},
		instruction{opJumpEqual, 1, 0, 0xc000003e},
		instruction{opReturn, 0, 0, kill},
		instruction{opLoadAbsWord, 0, 0, 0},
		instruction{opJumpGreater, 0, 1, 0x40000000},
		instruction{opReturn, 0, 0, kill},
		instruction{opJumpEqual, 0, 1, 7},
		instruction{opReturn, 0, 0, deny},
		instruction{opJumpEqual, 0, 3, 9},
		instruction{opLoadAbsWord, 0, 0, 16},
		instruction{opJumpSet, 1, 0, 0x10},
		instruction{opReturn, 0, 0, deny},
		instruction{opReturn, 0, 0, allow},
	)
	for _, c := range []struct {
		data Data
		want uint32
	}{
		{Data{Nr: 1, Arch: 0x40000003}, kill},
		{Data{Nr: 0x40000000, Arch: 0xc000003e}, kill}, // the boundary itself is foreign
		{Data{Nr: 0x3fffffff, Arch: 0xc000003e}, allow},
		{Data{Nr: 7, Arch: 0xc000003e}, deny},
		{Data{Nr: 9, Arch: 0xc000003e, Args: [6]uint64{0x10}}, allow},
		{Data{Nr: 9, Arch: 0xc000003e, Args: [6]uint64{0x11}}, allow},      // a set bit among others, not equality
		{Data{Nr: 9, Arch: 0xc000003e, Args: [6]uint64{0x10 << 32}}, deny}, // high word is not the flags word
		{Data{Nr: 9, Arch: 0xc000003e}, deny},
		{Data{Nr: 1, Arch: 0xc000003e}, allow},
	} {
		if got, err := Evaluate(p, c.data); err != nil || got != c.want {
			t.Fatalf("evaluated %+v as %#x (%v), want %#x", c.data, got, err, c.want)
		}
	}
}

func TestEvaluateRefusesWhatItCannotRead(t *testing.T) {
	for _, p := range [][]byte{
		nil,
		make([]byte, 7),
		program(t, instruction{opLoadAbsWord, 0, 0, 0}),                                 // no verdict
		program(t, instruction{0x07, 0, 0, 0}, instruction{opReturn, 0, 0, 0x7fff0000}), // unsupported opcode before an allow
		program(t, instruction{opLoadAbsWord, 0, 0, 8}),                                 // instruction pointer is not modeled
		program(t, instruction{opJumpEqual, 9, 9, 0}, instruction{opReturn, 0, 0, 0}),   // jumps past the end
	} {
		if _, err := Evaluate(p, Data{}); err == nil {
			t.Fatal("an unreadable program produced a verdict")
		}
	}
}
