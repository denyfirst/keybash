package rdplab

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrWire = errors.New("RDP lab instruction refused")

const (
	maxWireBytes = 48 * 1024
	maxElements  = 16
)

// instruction is deliberately private: no unfiltered Guacamole tunnel is
// exposed. Lengths count Unicode codepoints, not UTF-8 bytes or UTF-16 units.
type instruction []string

func readInstruction(reader *bufio.Reader) (instruction, error) {
	var elements instruction
	remaining := maxWireBytes
	readByte := func() (byte, error) {
		if remaining == 0 {
			return 0, ErrWire
		}
		remaining--
		return reader.ReadByte()
	}
	for len(elements) < maxElements {
		length := 0
		digits := 0
		for {
			b, err := readByte()
			if err != nil {
				return nil, ErrWire
			}
			if b == '.' {
				if digits == 0 {
					return nil, ErrWire
				}
				break
			}
			if b < '0' || b > '9' || digits >= 5 || length > maxWireBytes/10 {
				return nil, ErrWire
			}
			length = length*10 + int(b-'0')
			digits++
			if length > maxWireBytes {
				return nil, ErrWire
			}
		}
		var value strings.Builder
		for range length {
			if remaining == 0 {
				return nil, ErrWire
			}
			r, size, err := reader.ReadRune()
			if err != nil || size > remaining || r == utf8.RuneError && size == 1 {
				return nil, ErrWire
			}
			remaining -= size
			value.WriteRune(r)
		}
		elements = append(elements, value.String())
		b, err := readByte()
		if err != nil || b != ',' && b != ';' {
			return nil, ErrWire
		}
		if b == ';' {
			if elements[0] == "" {
				return nil, ErrWire
			}
			return elements, nil
		}
	}
	return nil, ErrWire
}

func writeInstruction(writer io.Writer, elements instruction) error {
	if len(elements) == 0 || len(elements) > maxElements || elements[0] == "" {
		return ErrWire
	}
	var wire strings.Builder
	for i, value := range elements {
		if len(value) > maxWireBytes || !utf8.ValidString(value) {
			return ErrWire
		}
		prefix := strconv.Itoa(utf8.RuneCountInString(value)) + "."
		if wire.Len()+len(prefix)+len(value)+1 > maxWireBytes {
			return ErrWire
		}
		wire.WriteString(prefix)
		wire.WriteString(value)
		if i == len(elements)-1 {
			wire.WriteByte(';')
		} else {
			wire.WriteByte(',')
		}
	}
	encoded := wire.String()
	if n, err := io.WriteString(writer, encoded); err != nil || n != len(encoded) {
		return ErrWire
	}
	return nil
}
