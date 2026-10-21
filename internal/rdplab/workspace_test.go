package rdplab

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func TestWorkspacePlanKeepsNLAAndClosedAuxiliaryChannels(t *testing.T) {
	plan := validNativePlan(t)
	plan.workspace = true
	names := nativeArgumentNames()
	args, e := plan.arguments(names)
	if e != nil {
		t.Fatal("valid workspace plan refused")
	}
	values := map[string]string{}
	for i, name := range names[2:] {
		values[name] = args[i+2]
	}
	for k, v := range map[string]string{"security": "nla", "ignore-cert": "false", "cert-tofu": "false", "disable-auth": "false", "disable-copy": "false", "disable-paste": "false", "resize-method": "display-update", "enable-drive": "false", "enable-printing": "false", "disable-audio": "true", "gateway-hostname": "", "static-channels": "", "recording-path": ""} {
		if values[k] != v {
			t.Fatal("workspace security/profile mismatch: " + k)
		}
	}
}

func TestWorkspaceTextBothDirectionsAndResize(t *testing.T) {
	s, remote, input := viewerFixture(t)
	s.workspace = true
	s.native.workspace = true
	text := "Azərbaycan 🔑\nline"
	for _, in := range []instruction{{"clipboard", "0", "text/plain"}, {"blob", "0", base64.StdEncoding.EncodeToString([]byte(text))}} {
		if _, e := s.Write(encodedInstruction(t, in)); e != nil {
			t.Fatal("valid partial text refused")
		}
	}
	select {
	case <-input:
		t.Fatal("partial clipboard escaped before end")
	default:
	}
	if _, e := s.Write(encodedInstruction(t, instruction{"end", "0"})); e != nil {
		t.Fatal("valid completed paste refused")
	}
	got := ""
	for range 3 {
		in := <-input
		if len(in) == 3 && in[0] == "blob" {
			b, _ := base64.StdEncoding.DecodeString(in[2])
			got += string(b)
		}
	}
	if got != text {
		t.Fatal("native paste bytes changed")
	}
	if _, e := s.Write(encodedInstruction(t, instruction{"size", "1280", "720"})); e != nil {
		t.Fatal("valid desktop request refused")
	}
	if in := <-input; len(in) != 3 || in[0] != "size" || in[1] != "1280" {
		t.Fatal("native desktop request missing")
	}
	go func() {
		for _, in := range []instruction{{"clipboard", "8", "text/plain"}, {"blob", "8", base64.StdEncoding.EncodeToString([]byte(text))}, {"end", "8"}, {"size", "0", "1280", "720"}} {
			_ = writeInstruction(remote, in)
		}
		_ = remote.Close()
	}()
	var out bytes.Buffer
	_, _ = io.Copy(&out, s)
	if !bytes.Contains(out.Bytes(), []byte("keybash-clipboard")) || !bytes.Contains(out.Bytes(), []byte(text)) || !bytes.Contains(out.Bytes(), []byte("1280")) {
		t.Fatal("completed copy or native size missing")
	}
	if !s.outputClip.closed {
		t.Fatal("clipboard buffer remained after close")
	}
}

func TestWorkspaceRefusesAuxiliaryMalformedReplayAndLimits(t *testing.T) {
	for _, in := range []instruction{{"clipboard", "0", "text/html"}, {"clipboard", "1", "text/plain"}, {"blob", "0", "!!!!"}, {"end", "0"}, {"size", "1922", "1080"}, {"size", "1281", "720"}, {"size", "1280", "0"}, {"size", "1280", "720", "extra"}, {"file", "0", "text/plain", "x"}} {
		s, _, _ := viewerFixture(t)
		s.workspace = true
		s.native.workspace = true
		if _, e := s.Write(encodedInstruction(t, in)); e == nil {
			t.Fatal("malformed workspace input accepted")
		}
	}
	for _, text := range []string{"bad\x00text", strings.Repeat("x", 32769)} {
		s, _, _ := viewerFixture(t)
		s.workspace = true
		s.native.workspace = true
		if _, e := s.Write(encodedInstruction(t, instruction{"clipboard", "0", "text/plain"})); e != nil {
			t.Fatal("text begin refused")
		}
		failed := false
		for b := []byte(text); len(b) > 0; {
			n := min(len(b), 4096)
			_, e := s.Write(encodedInstruction(t, instruction{"blob", "0", base64.StdEncoding.EncodeToString(b[:n])}))
			b = b[n:]
			if e != nil {
				failed = true
				break
			}
		}
		_, e := s.Write(encodedInstruction(t, instruction{"end", "0"}))
		if !failed && e == nil {
			t.Fatal("invalid completed clipboard accepted")
		}
	}
	s, _, input := viewerFixture(t)
	s.workspace = true
	s.native.workspace = true
	for range 4 {
		if _, e := s.Write(encodedInstruction(t, instruction{"size", "1280", "720"})); e != nil {
			t.Fatal("bounded resize refused")
		}
		<-input
	}
	if _, e := s.Write(encodedInstruction(t, instruction{"size", "1280", "720"})); e == nil {
		t.Fatal("resize flood accepted")
	}
}

func TestWorkspaceRemoteClipboardIsCompletedTextWithDistinctStream(t *testing.T) {
	for _, sequence := range [][]instruction{
		{{"clipboard", "8", "text/html"}},
		{{"clipboard", "8", "text/plain"}, {"clipboard", "9", "text/plain"}},
		{{"clipboard", "8", "text/plain"}, {"blob", "8", "AA=="}, {"end", "8"}},
		{{"clipboard", "8", "text/plain"}, {"blob", "8", "/w=="}, {"end", "8"}},
	} {
		s, _, _ := viewerFixture(t)
		s.workspace = true
		refused := false
		for _, in := range sequence {
			handled, valid := s.clipboardOutput(in)
			if !handled || !valid {
				refused = true
				break
			}
		}
		if !refused || s.pending.Len() != 0 {
			t.Fatal("invalid remote clipboard reached the browser")
		}
	}
	s, _, _ := viewerFixture(t)
	s.workspace = true
	s.images["8"] = &viewerImage{}
	if handled, valid := s.clipboardOutput(instruction{"clipboard", "8", "text/plain"}); !handled || valid {
		t.Fatal("clipboard reused an active image stream")
	}
	delete(s.images, "8")
	if handled, valid := s.clipboardOutput(instruction{"clipboard", "8", "text/plain"}); !handled || !valid {
		t.Fatal("separate text stream refused")
	}
	if s.drawing(instruction{"img", "8", "14", "-1", "image/png", "0", "0"}) {
		t.Fatal("image reused an active clipboard stream")
	}
	if _, valid := s.clipboardOutput(instruction{"blob", "8", "YQ=="}); !valid || s.pending.Len() != 0 {
		t.Fatal("partial remote text escaped")
	}
	if _, valid := s.clipboardOutput(instruction{"end", "8"}); !valid || !bytes.Contains(s.pending.Bytes(), []byte("keybash-clipboard")) {
		t.Fatal("completed remote text missing")
	}
	_ = s.Close()
	if _, valid := s.clipboardOutput(instruction{"clipboard", "8", "text/plain"}); valid {
		t.Fatal("closed clipboard was revived")
	}
}
