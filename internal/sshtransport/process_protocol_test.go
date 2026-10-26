package sshtransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"github.com/denyfirst/keybash/internal/sshkey"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestWorkerFrameBoundsAndSchemas(t *testing.T) {
	for _, kind := range []byte{frameHello, frameStart, frameReady, frameInput, frameResize, frameOutput, frameErrorOutput, frameFailed} {
		data := bytes.Repeat([]byte{42}, frameLimit(kind))
		var b bytes.Buffer
		if writeWorkerFrame(&b, kind, data) != nil {
			t.Fatal("valid frame refused")
		}
		got, payload, err := readWorkerFrame(&b)
		if err != nil || got != kind || !bytes.Equal(payload, data) {
			t.Fatal("valid frame changed")
		}
	}
	for _, raw := range [][]byte{nil, {255, 0, 0, 0, 0}, {frameInput, 0xff, 0xff, 0xff, 0xff}, {frameResize, 0, 0, 0, 9}, {frameReady, 0, 0, 0, 1, 42}, {frameInput, 0, 0, 0, 1}} {
		if _, _, err := readWorkerFrame(bytes.NewReader(raw)); err == nil {
			t.Fatal("malformed or excessive frame accepted")
		}
	}
	var b bytes.Buffer
	if writeWorkerFrame(&b, frameOutput, make([]byte, 8193)) == nil || writeWorkerFrame(&b, 255, nil) == nil {
		t.Fatal("unsafe frame emitted")
	}
}

func workerCoreFixture(t *testing.T, pinCorrect bool) (net.Conn, *sshFixture, <-chan error, context.CancelFunc) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("entropy failed")
	}
	user, _ := ssh.NewSignerFromKey(private)
	host := syntheticSigner(t)
	fixture := newFixture(t, fixtureOptions{host: host, user: user})
	parent, child := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveSSHWorker(ctx, child, child, fixture.client) }()
	t.Cleanup(func() { cancel(); _ = parent.Close() })
	pin := host.PublicKey().Marshal()
	if !pinCorrect {
		pin = syntheticSigner(t).PublicKey().Marshal()
	}
	start := ssh.Marshal(&workerStart{Version: 1, Host: "ssh.invalid", User: "lab-user", Pin: pin, Seed: private[:32]})
	if writeWorkerFrame(parent, frameStart, start) != nil {
		t.Fatal("start write failed")
	}
	clear(start)
	clear(private)
	return parent, fixture, done, cancel
}

func TestSSHWorkerCorePinInputResizeAndCancellation(t *testing.T) {
	parent, fixture, done, cancel := workerCoreFixture(t, true)
	if kind, data, err := readWorkerFrame(parent); err != nil || kind != frameReady || len(data) != 0 {
		t.Fatal("authenticated worker did not become ready")
	}
	input := []byte("Salam, Azərbaycan!\r\n")
	if writeWorkerFrame(parent, frameInput, input) != nil {
		t.Fatal("input refused")
	}
	kind, got, err := readWorkerFrame(parent)
	if err != nil || kind != frameOutput || !bytes.Equal(got, input) {
		t.Fatal("worker input/output changed")
	}
	var size [8]byte
	binary.BigEndian.PutUint32(size[:], 123)
	binary.BigEndian.PutUint32(size[4:], 45)
	if writeWorkerFrame(parent, frameResize, size[:]) != nil {
		t.Fatal("resize refused")
	}
	deadline := time.After(time.Second)
resize:
	for {
		select {
		case event := <-fixture.events:
			if event.kind == "window-change" {
				if len(event.payload) != 16 || binary.BigEndian.Uint32(event.payload) != 123 || binary.BigEndian.Uint32(event.payload[4:]) != 45 {
					t.Fatal("resize changed")
				}
				break resize
			}
		case <-deadline:
			t.Fatal("resize not delivered")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop on revocation")
	}
	if fixture.auth.Load() == 0 {
		t.Fatal("worker bypassed user authentication")
	}
}

func TestSSHWorkerCoreChangedPinRefusesBeforeAuth(t *testing.T) {
	parent, fixture, done, cancel := workerCoreFixture(t, false)
	defer cancel()
	kind, _, err := readWorkerFrame(parent)
	if err == nil && kind != frameFailed {
		t.Fatal("changed host identity accepted")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("changed pin did not fail")
		}
	case <-time.After(time.Second):
		t.Fatal("pin refusal stalled")
	}
	if fixture.auth.Load() != 0 {
		t.Fatal("credential reached changed host identity")
	}
}

func TestSSHWorkerCoreUnexpectedInputCloses(t *testing.T) {
	parent, _, done, cancel := workerCoreFixture(t, true)
	defer cancel()
	if kind, _, err := readWorkerFrame(parent); err != nil || kind != frameReady {
		t.Fatal("valid worker refused")
	}
	if writeWorkerFrame(parent, frameStart, nil) != nil {
		t.Fatal("test write failed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("repeated startup frame retained authority")
	}
}

func TestSSHWorkerCoreMalformedStartupNeverAuthenticates(t *testing.T) {
	host, user := syntheticSigner(t), syntheticSigner(t)
	valid := workerStart{Version: 1, Host: "ssh.invalid", User: "lab-user", Pin: host.PublicKey().Marshal(), Seed: make([]byte, 32)}
	for _, variant := range []string{"version", "host", "seed", "user", "pin", "trailing"} {
		t.Run(variant, func(t *testing.T) {
			start := valid
			switch variant {
			case "version":
				start.Version = 2
			case "host":
				start.Host = ""
			case "seed":
				start.Seed = nil
			case "user":
				start.User = "bad user"
			case "pin":
				start.Pin = []byte("invalid")
			}
			data := ssh.Marshal(&start)
			if variant == "trailing" {
				data = append(data, 42)
			}
			fixture := newFixture(t, fixtureOptions{host: host, user: user})
			parent, child := net.Pipe()
			defer parent.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- serveSSHWorker(ctx, child, child, fixture.client) }()
			if writeWorkerFrame(parent, frameStart, data) != nil {
				t.Fatal("fixture start write failed")
			}
			kind, _, err := readWorkerFrame(parent)
			if err == nil && kind != frameFailed {
				t.Fatal("malformed startup became ready")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("malformed startup accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("malformed startup stalled")
			}
			if fixture.auth.Load() != 0 {
				t.Fatal("malformed startup authenticated")
			}
		})
	}
}

func TestProcessOutputDropsBufferedDataAfterRevocation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	o := processOutput{ctx: ctx, queue: make(chan []byte, 1), rest: []byte("partially read remote output")}
	o.queue <- []byte("synthetic remote output")
	cancel()
	if n, err := o.read(make([]byte, 128)); n != 0 || err != io.EOF {
		t.Fatal("revoked worker leaked queued output")
	}
}

func TestProcessOutputDrainsAfterCleanWorkerExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	defer outR.Close()
	defer outW.Close()
	s := &processStream{ctx: ctx, cancel: cancel, in: inW, out: outR}
	s.stdout = processOutput{ctx: ctx, queue: make(chan []byte, 2)}
	s.stderr = processOutput{ctx: ctx, queue: make(chan []byte, 2)}
	if writeWorkerFrame(outW, frameOutput, []byte("last remote output")) != nil {
		t.Fatal("fixture output failed")
	}
	_ = outW.Close()
	done := make(chan struct{})
	go func() { s.demux(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("EOF did not close demux")
	}
	got, err := io.ReadAll(s)
	if err != nil || string(got) != "last remote output" {
		t.Fatal("clean worker exit lost final output")
	}
	if ctx.Err() != nil {
		t.Fatal("normal EOF was treated as revocation")
	}
}

// A long session's output passes the former 16 MiB worker total; bounded
// frames and queues, not a lifetime count, keep the gateway's memory finite.
func TestProcessOutputHasNoLifetimeTotal(t *testing.T) {
	const total = 20 * 1024 * 1024
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	defer outR.Close()
	_, inW, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	defer inW.Close()
	s := &processStream{ctx: ctx, cancel: cancel, in: inW, out: outR}
	s.stdout = processOutput{ctx: ctx, queue: make(chan []byte, 2)}
	s.stderr = processOutput{ctx: ctx, queue: make(chan []byte, 2)}
	go func() {
		chunk := bytes.Repeat([]byte("o"), 8192)
		for sent := 0; sent < total; sent += len(chunk) {
			if writeWorkerFrame(outW, frameOutput, chunk) != nil {
				return
			}
		}
		_ = outW.Close()
	}()
	go s.demux()
	got, err := io.Copy(io.Discard, s)
	if err != nil || got != total || ctx.Err() != nil {
		t.Fatalf("worker output ended after %d of %d bytes", got, total)
	}
}

func TestProcessRefusalReturnsNilStream(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("entropy failed")
	}
	key, err := sshkey.New(private)
	clear(private)
	if err != nil {
		t.Fatal("key setup failed")
	}
	defer key.Close()
	called := false
	stream, err := (ProcessWorker{}).open(context.Background(), "ssh.invalid", func(context.Context) (net.Conn, error) { called = true; return nil, ErrProcess }, syntheticSigner(t).PublicKey().Marshal(), "lab-user", key)
	if err == nil || stream != nil || called {
		t.Fatal("refusal returned a typed nil stream or reached network")
	}
	var empty *processStream
	if empty.Close() != nil {
		t.Fatal("nil stream cleanup failed")
	}
}

func FuzzSSHWorkerFrames(f *testing.F) {
	f.Add([]byte{frameReady, 0, 0, 0, 0})
	f.Add([]byte{frameInput, 0, 0, 0, 1, 42})
	f.Add([]byte{255, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			return
		}
		kind, payload, err := readWorkerFrame(bytes.NewReader(raw))
		if err == nil && (frameLimit(kind) < 0 || len(payload) > frameLimit(kind)) {
			t.Fatal("frame escaped bound")
		}
	})
}
