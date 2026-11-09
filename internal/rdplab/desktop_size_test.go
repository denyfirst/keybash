package rdplab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// A desktop starts at the size its page has, within the bounds the page could
// ask for once connected; anything else starts at the lab's 1024 by 768.
func TestDesktopStartsAtThePageSize(t *testing.T) {
	for _, c := range []struct {
		w, h int
		ok   bool
	}{{200, 200, true}, {1920, 1080, true}, {1600, 900, true}, {198, 900, false}, {1922, 900, false}, {1600, 1082, false},
		{1600, 198, false}, {1601, 900, false}, {1600, 901, false}, {0, 0, false}, {-1600, 900, false}} {
		if desktopSize(c.w, c.h) != c.ok {
			t.Fatalf("%dx%d: got %v", c.w, c.h, !c.ok)
		}
	}
	sized := func(p nativePlan) (string, string) {
		t.Helper()
		names := nativeArgumentNames()
		args, err := p.arguments(names)
		if err != nil {
			t.Fatal(err)
		}
		values := map[string]string{}
		for i, name := range names[2:] {
			values[name] = args[i+2]
		}
		return values["width"], values["height"]
	}
	plan := validNativePlan(t)
	plan.workspace, plan.width, plan.height = true, 1600, 900
	if w, h := sized(plan); w != "1600" || h != "900" {
		t.Fatalf("the page's size did not reach guacd: %sx%s", w, h)
	}
	for _, p := range []struct {
		workspace bool
		w, h      int
	}{{false, 1600, 900}, {true, 1601, 900}, {true, 0, 0}, {true, 4096, 2160}} {
		plan.workspace, plan.width, plan.height = p.workspace, p.w, p.h
		if w, h := sized(plan); w != "1024" || h != "768" {
			t.Fatalf("%v %dx%d left the lab's size: %sx%s", p.workspace, p.w, p.h, w, h)
		}
	}
	// guacd hears the size in the handshake too.
	plan.workspace, plan.width, plan.height = true, 1600, 900
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	heard := make(chan instruction, 1)
	go func() {
		reader := bufio.NewReader(server)
		if _, err := readInstruction(reader); err != nil {
			return
		}
		if writeBoundedInstruction(server, nativeArgumentNames(), 128) != nil {
			return
		}
		size, err := readInstruction(reader)
		if err != nil {
			return
		}
		heard <- size
		for range 4 {
			if _, err := readInstruction(reader); err != nil {
				return
			}
		}
		if _, err := readBoundedInstruction(reader, 128); err != nil {
			return
		}
		if writeInstruction(server, instruction{"ready", "private-session-id"}) != nil {
			return
		}
		_, _ = io.Copy(io.Discard, reader)
	}()
	stream, err := nativeConnect(ctx, client, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.close()
	if got := strings.Join(<-heard, ","); got != "size,1600,900,96" {
		t.Fatalf("guacd's handshake said %q", got)
	}
	// The viewer starts there, and the pointer may reach its far corner.
	viewer := newViewerStream(stream)
	initial := make([]byte, 256)
	n, err := viewer.Read(initial)
	if err != nil || !bytes.Contains(initial[:n], []byte("4.size,1.0,4.1600,3.900;")) {
		t.Fatalf("the viewer did not start at the page's size: %q", initial[:n])
	}
	if _, err := viewer.Write(encodedInstruction(t, instruction{"mouse", "1599", "899", "0"})); err != nil {
		t.Fatal("the far corner of the desktop was refused")
	}
	if openWithout := newViewerStream(&nativeStream{workspace: true, width: 1601, height: 900}); openWithout.width.Load() != 1024 || openWithout.height.Load() != 768 {
		t.Fatal("an odd size reached the viewer")
	}
	// The manager plans the page's size, refuses one outside the bounds before
	// anything starts, and keeps the lab's size when there is none.
	if p, e := managedPlan(plan.identity, "synthetic-user", "synthetic-password", 1600, 900); e != nil || !p.workspace || p.width != 1600 || p.height != 900 {
		t.Fatal("the manager did not plan the page's size")
	}
	if p, e := managedPlan(plan.identity, "synthetic-user", "synthetic-password", 0, 0); e != nil || !p.workspace {
		t.Fatal("the manager refused a desktop with no size")
	} else if w, h := p.size(); w != 1024 || h != 768 {
		t.Fatal("a desktop with no size left the lab's size")
	}
	for _, size := range [][2]int{{1601, 900}, {1922, 1080}, {1600, 0}, {0, 900}, {4096, 2160}} {
		if _, e := managedPlan(plan.identity, "synthetic-user", "synthetic-password", size[0], size[1]); e != errNative {
			t.Fatalf("%v planned", size)
		}
		if s, e := (ManagerWorker{}).openDial(context.Background(), func(context.Context) (net.Conn, error) { return nil, errNative }, plan.identity, "synthetic-user", "synthetic-password", size[0], size[1]); s != nil || e != errNative {
			t.Fatalf("%v accepted", size)
		}
	}
}

// A copy on the remote larger than a page takes is dropped, the page told in
// fixed words, and the desktop goes on; a copy past anything guacd sends, or
// an oversized paste from the browser, still refuses.
func TestViewerDropsARemoteCopyTooLargeAndGoesOn(t *testing.T) {
	a, b := net.Pipe()
	s := newViewerStream(&nativeStream{raw: a, reader: bufio.NewReader(a), stop: func() bool { return true }, workspace: true})
	t.Cleanup(func() { _ = s.Close(); _ = b.Close() })
	r := bufio.NewReader(s)
	// Each read waits a bounded time: silence is a failure, not a hang.
	read := func(wait time.Duration) (instruction, error) {
		type result struct {
			in  instruction
			err error
		}
		got := make(chan result, 1)
		go func() { in, err := readInstruction(r); got <- result{in, err} }()
		select {
		case x := <-got:
			return x.in, x.err
		case <-time.After(wait):
			t.Fatal("the viewer said nothing")
			return nil, nil
		}
	}
	for range 2 {
		if _, err := read(2 * time.Second); err != nil {
			t.Fatal("initial viewer state missing")
		}
	}
	block := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, 4096))
	copyOf := func(id string, blocks int, last string) {
		go func() {
			in := []instruction{{"clipboard", id, "text/plain"}}
			for range blocks {
				in = append(in, instruction{"blob", id, block})
			}
			if last != "" {
				in = append(in, instruction{"blob", id, base64.StdEncoding.EncodeToString([]byte(last))})
			}
			in = append(in, instruction{"end", id})
			for _, i := range in {
				if writeInstruction(b, i) != nil {
					return
				}
			}
		}()
	}
	copyOf("0", 9, "")
	if in, err := read(2 * time.Second); err != nil || len(in) != 1 || in[0] != "keybash-clipboard-large" {
		t.Fatalf("a large copy was not dropped and told: %q %v", in, err)
	}
	copyOf("2", 0, "Azərbaycan 🔑")
	if in, err := read(2 * time.Second); err != nil || len(in) != 2 || in[0] != "keybash-clipboard" || in[1] != "Azərbaycan 🔑" {
		t.Fatalf("the desktop did not go on after a large copy: %q %v", in, err)
	}
	copyOf("4", maxClipboardDiscard/4096+1, "")
	for {
		in, err := read(10 * time.Second)
		if err != nil {
			break
		}
		if in[0] == "keybash-clipboard-large" {
			t.Fatal("a copy past anything guacd sends was dropped instead of refused")
		}
	}
	var paste clipboard
	if _, _, err := paste.accept(instruction{"clipboard", "0", "text/plain"}); err != nil {
		t.Fatal("paste start refused")
	}
	if _, _, err := paste.accept(instruction{"blob", "0", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, maxClipboardBytes+1))}); err != ErrClipboard {
		t.Fatal("an oversized paste from the browser was dropped instead of refused")
	}
}
