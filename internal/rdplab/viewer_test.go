package rdplab

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"testing"
	"time"
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
		{"end", "1"}, {"end", "0"}, {"copy", "-1", "0", "0", "2", "2", "14", "0", "4", "4"}, {"sync", "123", "1"}}
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
	for _, expected := range instructions {
		in, err := readInstruction(got)
		if err != nil || !bytes.Equal(encodedInstruction(t, in), encodedInstruction(t, expected)) {
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
	for i := 1; i <= 5; i++ {
		in := instruction{"size", string(rune('0' + i)), "1024", "768"}
		if s.drawing(in) != (i < 5) {
			t.Fatal("aggregate canvas quota failed")
		}
	}
	for i := 0; i < 9; i++ {
		if s.drawing(instruction{"push", "0"}) != (i < 8) {
			t.Fatal("drawing stack quota failed")
		}
	}
}
func TestViewerInvalidPNGIsNeverForwarded(t *testing.T) {
	s, remote, _ := viewerFixture(t)
	_, _ = s.Read(make([]byte, 128))
	go func() {
		for _, in := range []instruction{{"img", "0", "14", "0", "image/png", "0", "0"}, {"blob", "0", base64.StdEncoding.EncodeToString([]byte("bad png"))}, {"end", "0"}} {
			if writeInstruction(remote, in) != nil {
				return
			}
		}
	}()
	if n, err := s.Read(make([]byte, 4096)); n != 0 || err != errNative {
		t.Fatal("invalid PNG reached the viewer")
	}
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
