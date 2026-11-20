package rdplab

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

// The frames are the proxy's own (rdp-proxy/src/frame.rs): a type byte, a
// little-endian length, the payload, and nothing over 64 KiB either way.
func TestProxyFramesMatchTheProxyAndRefuseTheRest(t *testing.T) {
	var buf bytes.Buffer
	for _, f := range []struct {
		kind    byte
		payload []byte
	}{{proxyBrowser, []byte("hello")}, {proxyEnded, []byte{5}}, {proxySetup, nil}, {proxyDesktop, make([]byte, proxyMaxPayload)}} {
		if writeProxyFrame(&buf, f.kind, f.payload) != nil {
			t.Fatal("valid frame refused")
		}
	}
	if !bytes.Equal(buf.Bytes()[:10], []byte{2, 5, 0, 0, 0, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatalf("frame layout differs from the proxy's: %v", buf.Bytes()[:10])
	}
	for _, want := range []struct {
		kind byte
		n    int
	}{{proxyBrowser, 5}, {proxyEnded, 1}, {proxySetup, 0}, {proxyDesktop, proxyMaxPayload}} {
		kind, payload, err := readProxyFrame(&buf)
		if err != nil || kind != want.kind || len(payload) != want.n {
			t.Fatalf("read %d %d %v, want %d %d", kind, len(payload), err, want.kind, want.n)
		}
	}
	if _, _, err := readProxyFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatal("a clean end between frames is not EOF")
	}
	over := binary.LittleEndian.AppendUint32([]byte{proxyDesktop}, proxyMaxPayload+1)
	for name, raw := range map[string][]byte{
		"unknown type":   {0, 0, 0, 0, 0},
		"type 5":         {5, 0, 0, 0, 0},
		"over the limit": append(over, make([]byte, proxyMaxPayload+1)...),
		"huge length":    {2, 0xff, 0xff, 0xff, 0xff},
		"cut payload":    {2, 4, 0, 0, 0, 1, 2},
		"cut header":     {2, 4, 0},
	} {
		if _, _, err := readProxyFrame(bytes.NewReader(raw)); err == nil || errors.Is(err, io.EOF) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var out bytes.Buffer
	if writeProxyFrame(&out, proxyDesktop, make([]byte, proxyMaxPayload+1)) == nil || writeProxyFrame(&out, 9, nil) == nil || out.Len() != 0 {
		t.Fatal("an invalid frame was written")
	}
}

// The setup frame is the proxy's format 1, with its own bounds; browserSetup
// adds credentialsAllowed before it.
func TestProxySetupIsFormatOneWithItsOwnBounds(t *testing.T) {
	got, err := proxySetupPayload("kbtest", "", "Pässwörd", true)
	want := []byte{1, 6, 0, 'k', 'b', 't', 'e', 's', 't', 0, 0, 10, 0}
	want = append(append(want, "Pässwörd"...), 1)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("setup %v %v", got, err)
	}
	if got, _ := proxySetupPayload("u", "CORP", "p", false); got[len(got)-1] != 0 {
		t.Fatal("clipboard flag set")
	}
	for name, c := range map[string][3]string{
		"no user":         {"", "", "p"},
		"no password":     {"u", "", ""},
		"long user":       {strings.Repeat("u", 129), "", "p"},
		"long domain":     {"u", strings.Repeat("d", 129), "p"},
		"long password":   {"u", "", strings.Repeat("p", 4097)},
		"NUL in password": {"u", "", "p\x00"},
		"NUL in user":     {"u\x00", "", "p"},
		"bad UTF-8":       {"u", "", "\xff"},
	} {
		if p, err := proxySetupPayload(c[0], c[1], c[2], false); err == nil {
			t.Errorf("%s accepted: %v", name, p)
		}
	}
}

func proxyPair(t *testing.T) (*ProxyStream, net.Conn) {
	t.Helper()
	gateway, worker := net.Pipe()
	t.Cleanup(func() { _ = gateway.Close(); _ = worker.Close() })
	return newProxyStream(gateway), worker
}

// Messages pass whole each way; the proxy's end code becomes the page's word.
func TestProxyStreamPassesMessagesAndSaysWhyItEnded(t *testing.T) {
	for code, want := range map[byte]terminalweb.Reason{
		1: terminalweb.ReasonCredentials, 3: terminalweb.ReasonUnreachable, 4: terminalweb.ReasonRefused,
		5: terminalweb.ReasonRefused, 6: terminalweb.ReasonRemoteEnded, 2: terminalweb.ReasonRefused, 200: terminalweb.ReasonRefused,
	} {
		s, worker := proxyPair(t)
		go func() {
			_ = writeProxyFrame(worker, proxyDesktop, []byte("desktop"))
			_ = writeProxyFrame(worker, proxyEnded, []byte{code})
		}()
		if m, err := s.ReadMessage(); err != nil || string(m) != "desktop" {
			t.Fatalf("code %d: first message %q %v", code, m, err)
		}
		if _, err := s.ReadMessage(); err == nil || s.Reason() != want {
			t.Fatalf("code %d: reason %q, want %q", code, s.Reason(), want)
		}
	}
	s, worker := proxyPair(t)
	read := make(chan []byte, 1)
	go func() { _, p, _ := readProxyFrame(worker); read <- p }()
	if s.WriteMessage([]byte("browser")) != nil || string(<-read) != "browser" {
		t.Fatal("browser message not passed")
	}
	if s.WriteMessage(nil) == nil || s.WriteMessage(make([]byte, proxyMaxPayload+1)) == nil {
		t.Fatal("an empty or oversized browser message was passed")
	}
}

// Anything but a desktop message or a one-byte end is refused, and says so.
func TestProxyStreamRefusesWhatTheProxyNeverSends(t *testing.T) {
	for name, frame := range map[string][]byte{
		"setup back":     {proxySetup, 0, 0, 0, 0},
		"browser back":   {proxyBrowser, 1, 0, 0, 0, 9},
		"empty desktop":  {proxyDesktop, 0, 0, 0, 0},
		"two-byte end":   {proxyEnded, 2, 0, 0, 0, 1, 1},
		"empty end":      {proxyEnded, 0, 0, 0, 0},
		"malformed type": {7, 0, 0, 0, 0},
	} {
		s, worker := proxyPair(t)
		go func() { _, _ = worker.Write(frame) }()
		if _, err := s.ReadMessage(); err == nil || s.Reason() != terminalweb.ReasonRefused {
			t.Errorf("%s: %v, reason %q", name, err, s.Reason())
		}
	}
	// A worker that just goes away says nothing.
	s, worker := proxyPair(t)
	_ = worker.Close()
	if _, err := s.ReadMessage(); err == nil || s.Reason() != "" {
		t.Fatal("a closed worker gave a reason")
	}
}

func TestProxyStreamCloseUnblocksReadsAndWrites(t *testing.T) {
	s, _ := proxyPair(t)
	done := make(chan error, 2)
	go func() { _, err := s.ReadMessage(); done <- err }()
	go func() { done <- s.WriteMessage([]byte("x")) }()
	time.Sleep(20 * time.Millisecond)
	if s.Close() != nil {
		t.Fatal("close failed")
	}
	for range 2 {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a blocked call succeeded after close")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("close left a call blocked")
		}
	}
	if s.Reason() != "" {
		t.Fatal("closing by the gateway was reported as the proxy's reason")
	}
}

// Credentials outside credentialsAllowed, and a missing context or dial, never
// reach a manager.
func TestOpenBrowserRDPRefusesBeforeAnyManager(t *testing.T) {
	pin := &Identity{name: "server.test", der: []byte{1}, roots: x509.NewCertPool()}
	if !credentialsAllowed(pin, "u", "p") {
		t.Fatal("the fixture identity itself is refused")
	}
	dial := func(context.Context) (net.Conn, error) { t.Fatal("dialled"); return nil, nil }
	w := ManagerWorker{SocketPath: "/nonexistent/keybash-rdp.sock"}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for name, try := range map[string]func() (*ProxyStream, error){
		"no user": func() (*ProxyStream, error) { return w.openBrowserDial(context.Background(), dial, pin, "", "p") },
		// Only credentialsAllowed refuses this one: the setup frame's own bounds allow it.
		"user outside the allowed characters": func() (*ProxyStream, error) {
			return w.openBrowserDial(context.Background(), dial, pin, "kb test", "p")
		},
		"long password": func() (*ProxyStream, error) {
			return w.openBrowserDial(context.Background(), dial, pin, "u", strings.Repeat("p", 4097))
		},
		"ended context": func() (*ProxyStream, error) { return w.openBrowserDial(ended, dial, pin, "u", "p") },
		"no dial":       func() (*ProxyStream, error) { return w.openBrowserDial(context.Background(), nil, pin, "u", "p") },
	} {
		if s, err := try(); err == nil || s != nil {
			t.Errorf("%s: opened", name)
		}
	}
}

// The setup frame carries only credentials credentialsAllowed accepts, and
// turns the clipboard on: the desktop page asks for it (cliprdr), and the
// proxy refuses a channel the setup did not allow.
func TestBrowserSetupHasTheCredentialRules(t *testing.T) {
	pin := &Identity{name: "server.test", der: []byte{1}, roots: x509.NewCertPool()}
	got, err := browserSetup(pin, "synthetic-user", "p")
	if err != nil || got[len(got)-1] != 1 {
		t.Fatalf("valid credentials: %v %v", got, err)
	}
	for name, c := range map[string][2]string{
		"space in the user":   {"kb test", "p"},
		"domain in the user":  {`CORP\kb`, "p"},
		"no password":         {"u", ""},
		"NUL in the password": {"u", "p\x00"},
		"password over 4096":  {"u", strings.Repeat("p", 4097)},
		"user over 128":       {strings.Repeat("u", 129), "p"},
	} {
		if _, err := browserSetup(pin, c[0], c[1]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := browserSetup(nil, "u", "p"); err == nil {
		t.Fatal("no identity accepted")
	}
}
