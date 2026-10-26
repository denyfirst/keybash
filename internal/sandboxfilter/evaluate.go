// Package sandboxfilter holds the syscall surface both protocol workers deny
// and a classic-BPF evaluator that lets tests check a generated seccomp
// program instruction by instruction instead of trusting its construction.
package sandboxfilter

import (
	"encoding/binary"
	"errors"
)

var ErrProgram = errors.New("unsupported seccomp program")

// Data mirrors struct seccomp_data: nr, arch, instruction pointer, args.
type Data struct {
	Nr   uint32
	Arch uint32
	Args [6]uint64
}

func (d Data) word(offset uint32) (uint32, bool) {
	switch {
	case offset == 0:
		return d.Nr, true
	case offset == 4:
		return d.Arch, true
	case offset >= 16 && offset < 64 && offset%4 == 0:
		// Read the word from the argument's little-endian bytes, exactly as
		// the kernel lays out seccomp_data on amd64.
		var raw [8]byte
		binary.LittleEndian.PutUint64(raw[:], d.Args[(offset-16)/8])
		return binary.LittleEndian.Uint32(raw[(offset-16)%8:]), true
	}
	return 0, false
}

// Classic BPF opcodes the workers' filters use. Anything else is refused so a
// test cannot pass by misreading an instruction.
const (
	opLoadAbsWord = 0x20 // BPF_LD | BPF_W | BPF_ABS
	opJumpEqual   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	opJumpGreater = 0x35 // BPF_JMP | BPF_JGE | BPF_K
	opJumpSet     = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	opReturn      = 0x06 // BPF_RET | BPF_K
)

// Evaluate runs a little-endian sock_filter program over data and returns the
// seccomp action word. Programs must be forward-only and end in a return.
func Evaluate(program []byte, data Data) (uint32, error) {
	if len(program) == 0 || len(program)%8 != 0 || len(program)/8 > 4096 {
		return 0, ErrProgram
	}
	count := len(program) / 8
	var accumulator uint32
	for pc := 0; pc < count; {
		instruction := program[pc*8 : pc*8+8]
		code := binary.LittleEndian.Uint16(instruction)
		jt, jf := int(instruction[2]), int(instruction[3])
		k := binary.LittleEndian.Uint32(instruction[4:])
		next := pc + 1
		switch code {
		case opLoadAbsWord:
			value, ok := data.word(k)
			if !ok {
				return 0, ErrProgram
			}
			accumulator = value
		case opJumpEqual, opJumpGreater, opJumpSet:
			taken := accumulator == k
			if code == opJumpGreater {
				taken = accumulator >= k
			} else if code == opJumpSet {
				taken = accumulator&k != 0
			}
			if taken {
				next += jt
			} else {
				next += jf
			}
		case opReturn:
			return k, nil
		default:
			return 0, ErrProgram
		}
		pc = next
	}
	return 0, ErrProgram // fell off the end without a verdict
}
