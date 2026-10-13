package rdplab

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestRDPClipboardUnicodeFragmentedBothDirectionsAndSessionIsolation(t *testing.T) {
	text := "Azərbaycan əıöüçşğ 😀\r\nsecond\n<tag>;,.\x00"
	var inbound, outbound, other clipboard
	for _, direction := range []*clipboard{&inbound, &outbound} {
		if _, done, err := direction.accept(instruction{"clipboard", "7", "text/plain"}); done || err != nil {
			t.Fatal("valid clipboard start refused")
		}
		// One-byte blobs intentionally split UTF-8 codepoints, including emoji.
		for _, b := range []byte(text) {
			in := instruction{"blob", "7", base64.StdEncoding.EncodeToString([]byte{b})}
			var wire bytes.Buffer
			if writeInstruction(&wire, in) != nil {
				t.Fatal("encoding failed")
			}
			parsed, err := readInstruction(bufio.NewReader(&wire))
			if err != nil {
				t.Fatal(err)
			}
			if _, done, err := direction.accept(parsed); done || err != nil {
				t.Fatal("partial text surfaced or valid fragment refused")
			}
		}
		got, done, err := direction.accept(instruction{"end", "7"})
		if err != nil || !done || got != text {
			t.Fatal("Unicode/line endings/control bytes changed")
		}
		if direction.active || len(direction.data) != 0 || direction.id != "" {
			t.Fatal("completed buffer retained")
		}
	}
	if _, _, err := other.accept(instruction{"end", "7"}); err != ErrClipboard {
		t.Fatal("stream crossed sessions")
	}
	// A second completed value remains independent; no history/global buffer.
	if _, _, err := inbound.accept(instruction{"clipboard", "8", "text/plain"}); err != nil {
		t.Fatal(err)
	}
	got, done, err := inbound.accept(instruction{"end", "8"})
	if err != nil || !done || got != "" {
		t.Fatal("empty clipboard/history handling")
	}
}

func TestRDPClipboardRejectsTypesReplayMalformedAndQuota(t *testing.T) {
	cases := []struct {
		name   string
		inputs []instruction
	}{
		{"HTML", []instruction{{"clipboard", "1", "text/html"}}},
		{"image", []instruction{{"clipboard", "1", "image/png"}}},
		{"file", []instruction{{"file", "1", "text/plain", "name"}}},
		{"pipe", []instruction{{"pipe", "1", "text/plain", "name"}}},
		{"argument", []instruction{{"argv", "1", "text/plain", "password"}}},
		{"duplicate", []instruction{{"clipboard", "1", "text/plain"}, {"clipboard", "1", "text/plain"}}},
		{"bad-id", []instruction{{"clipboard", "65536", "text/plain"}}},
		{"noncanonical-id", []instruction{{"clipboard", "01", "text/plain"}}},
		{"negative-id", []instruction{{"clipboard", "-1", "text/plain"}}},
		{"unopened", []instruction{{"blob", "1", "YQ=="}}},
		{"wrong-id", []instruction{{"clipboard", "1", "text/plain"}, {"blob", "2", "YQ=="}}},
		{"padding", []instruction{{"clipboard", "1", "text/plain"}, {"blob", "1", "YR=="}}},
		{"whitespace", []instruction{{"clipboard", "1", "text/plain"}, {"blob", "1", "YQ==\n"}}},
		{"empty-blob", []instruction{{"clipboard", "1", "text/plain"}, {"blob", "1", ""}}},
		{"invalid-UTF8", []instruction{{"clipboard", "1", "text/plain"}, {"blob", "1", "/w=="}, {"end", "1"}}},
		{"wrong-end", []instruction{{"clipboard", "1", "text/plain"}, {"end", "2"}}},
		{"replay", []instruction{{"clipboard", "1", "text/plain"}, {"end", "1"}, {"end", "1"}}},
		{"extra-field", []instruction{{"clipboard", "1", "text/plain", "evil"}}},
		{"overquota", []instruction{{"clipboard", "1", "text/plain"}, {"blob", "1", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, maxClipboardBytes))}, {"blob", "1", "YQ=="}}},
		{"oversize-blob", []instruction{{"clipboard", "1", "text/plain"}, {"blob", "1", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, maxClipboardBytes+1))}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c clipboard
			for i, in := range tc.inputs {
				_, _, err := c.accept(in)
				if i == len(tc.inputs)-1 {
					if err != ErrClipboard {
						t.Fatal("forbidden clipboard accepted")
					}
				} else if err != nil {
					t.Fatal("valid prefix refused")
				}
			}
			if !c.closed || c.active || len(c.data) != 0 {
				t.Fatal("refused buffer retained")
			}
			if _, _, err := c.accept(instruction{"clipboard", "1", "text/plain"}); err != ErrClipboard {
				t.Fatal("poisoned stream reused")
			}
		})
	}
}

func TestRDPClipboardExactQuotaAndRevocation(t *testing.T) {
	var c clipboard
	_, _, _ = c.accept(instruction{"clipboard", "1", "text/plain"})
	value := strings.Repeat("a", maxClipboardBytes)
	if _, _, err := c.accept(instruction{"blob", "1", base64.StdEncoding.EncodeToString([]byte(value))}); err != nil {
		t.Fatal("valid quota refused")
	}
	got, done, err := c.accept(instruction{"end", "1"})
	if err != nil || !done || got != value {
		t.Fatal("valid maximum text refused")
	}
	_, _, _ = c.accept(instruction{"clipboard", "2", "text/plain"})
	_, _, _ = c.accept(instruction{"blob", "2", "YQ=="})
	alias := c.data
	c.close()
	c.close()
	if len(c.data) != 0 || c.active || c.id != "" || alias[0] != 0 {
		t.Fatal("revoked buffer not cleared")
	}
	if _, done, err := c.accept(instruction{"end", "2"}); done || err != ErrClipboard {
		t.Fatal("late text after close")
	}
}

func TestRDPWireCodepointsBoundsAndMalformed(t *testing.T) {
	in := instruction{"clipboard", "7", "ə😀;,."}
	var b bytes.Buffer
	if writeInstruction(&b, in) != nil {
		t.Fatal("encode")
	}
	if b.String() != "9.clipboard,1.7,5.ə😀;,.;" {
		t.Fatal("wire lengths must count codepoints")
	}
	got, err := readInstruction(bufio.NewReader(&b))
	if err != nil || !reflect.DeepEqual(got, in) {
		t.Fatal("Unicode did not roundtrip")
	}
	for _, s := range []string{"", "1.x", ".x;", "-1.x;", "999999999.x;", "49153.x;", "1.\xff;", "1.x!", "0.;", "1.x,", strings.Repeat("1.x,", maxElements) + "1.x;", "1.x,49140." + strings.Repeat("😀", 13000) + ";"} {
		if _, err := readInstruction(bufio.NewReader(strings.NewReader(s))); err != ErrWire {
			t.Fatal("bad wire accepted")
		}
	}
	for _, in := range []instruction{nil, {""}, {"x", string([]byte{255})}, {"x", strings.Repeat("a", maxWireBytes)}, make(instruction, maxElements+1)} {
		b.Reset()
		if writeInstruction(&b, in) != ErrWire || b.Len() != 0 {
			t.Fatal("invalid instruction partially written")
		}
	}
}

func FuzzRDPWireAndClipboard(f *testing.F) {
	f.Add("9.clipboard,1.1,10.text/plain;4.blob,1.1,4.YQ==;3.end,1.1;")
	f.Add("999999999.x;")
	f.Add("1.x,1.😀;")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 2*maxWireBytes {
			return
		}
		reader := bufio.NewReader(strings.NewReader(input))
		var c clipboard
		defer c.close()
		for range 8 {
			in, err := readInstruction(reader)
			if err != nil {
				return
			}
			var b bytes.Buffer
			if writeInstruction(&b, in) != nil {
				t.Fatal("parsed instruction cannot encode")
			}
			round, err := readInstruction(bufio.NewReader(&b))
			if err != nil || !reflect.DeepEqual(round, in) {
				t.Fatal("noncanonical roundtrip")
			}
			text, done, err := c.accept(in)
			if len(c.data) > maxClipboardBytes || done && len(text) > maxClipboardBytes {
				t.Fatal("unbounded clipboard")
			}
			if err != nil {
				return
			}
		}
	})
}
