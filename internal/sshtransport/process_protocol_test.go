package sshtransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sshkey"
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
	key, err := sshkey.New(private)
	if err != nil {
		t.Fatal("key fixture failed")
	}
	material, err := key.Material()
	if err != nil {
		t.Fatal("key handoff failed")
	}
	key.Close()
	start := ssh.Marshal(&workerStart{Version: 2, Host: "ssh.invalid", User: "lab-user", Pin: pin, Method: methodKey, Secret: material})
	if writeWorkerFrame(parent, frameStart, start) != nil {
		t.Fatal("start write failed")
	}
	clear(start)
	clear(material)
	clear(private)
	return parent, fixture, done, cancel
}

// The worker authenticates with a password handed over in its start frame,
// exactly as with a key, and only after the pinned host key is verified.
func TestSSHWorkerCorePasswordHandoff(t *testing.T) {
	host := syntheticSigner(t)
	for _, prompts := range [][]string{nil, {"Password: "}} {
		fixture := newFixture(t, fixtureOptions{host: host, password: syntheticRemotePassword, prompts: prompts, echos: []bool{false}})
		parent, child := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- serveSSHWorker(ctx, child, child, fixture.client) }()
		start := ssh.Marshal(&workerStart{Version: 2, Host: "ssh.invalid", User: "lab-user", Pin: host.PublicKey().Marshal(), Method: methodPassword, Secret: []byte(syntheticRemotePassword)})
		if writeWorkerFrame(parent, frameStart, start) != nil {
			t.Fatal("start write failed")
		}
		if kind, _, err := readWorkerFrame(parent); err != nil || kind != frameReady || fixture.auth.Load() != 1 {
			t.Fatal("password handoff did not authenticate exactly once")
		}
		cancel()
		_ = parent.Close()
		<-done
	}
}

// What the gateway encodes is what the worker decodes, for both credential
// kinds, and nothing invalid crosses.
func TestSessionHandoffRoundTrip(t *testing.T) {
	host := syntheticSigner(t)
	pin := host.PublicKey().Marshal()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sshkey.New(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	password, _ := sshkey.NewPassword(syntheticRemotePassword)
	for _, auth := range []sshkey.Credential{key, password} {
		validated, method, secret, err := sessionHandoff(auth, "lab-user", pin)
		if err != nil || !bytes.Equal(validated, pin) {
			t.Fatal("valid credential handoff refused")
		}
		config, release, err := workerConfig(workerStart{Version: 2, Host: "ssh.invalid", User: "lab-user", Pin: validated, Method: method, Secret: secret})
		if err != nil {
			t.Fatalf("%s handoff did not decode", method)
		}
		if method == methodKey && (config.Signer == nil || !bytes.Equal(config.Signer.PublicKey().Marshal(), key.PublicKey().Marshal()) || config.Password != nil) ||
			method == methodPassword && (config.Signer != nil || string(config.Password) != syntheticRemotePassword) {
			t.Fatalf("%s handoff changed the credential", method)
		}
		release()
		clear(secret)
	}
	for name, start := range map[string]workerStart{
		"unknown method":   {Method: "agent", Secret: []byte("x")},
		"empty secret":     {Method: methodPassword},
		"NUL password":     {Method: methodPassword, Secret: []byte("nul\x00")},
		"not a key":        {Method: methodKey, Secret: []byte("not pkcs8")},
		"oversized secret": {Method: methodKey, Secret: make([]byte, sshkey.MaxMaterial+1)},
	} {
		if _, _, err := workerConfig(start); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
	for _, auth := range []sshkey.Credential{nil, (*sshkey.Key)(nil), (*sshkey.Password)(nil)} {
		if _, _, _, err := sessionHandoff(auth, "lab-user", pin); err == nil {
			t.Fatal("a missing credential was handed off")
		}
	}
	if _, _, _, err := sessionHandoff(password, "bad user", pin); err == nil {
		t.Fatal("a credential was handed off for an invalid connection")
	}
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
	valid := workerStart{Version: 2, Host: "ssh.invalid", User: "lab-user", Pin: host.PublicKey().Marshal(), Method: methodPassword, Secret: []byte(syntheticRemotePassword)}
	for _, variant := range []string{"version", "version0", "version3", "host", "secret", "method", "user", "pin", "trailing"} {
		t.Run(variant, func(t *testing.T) {
			start := valid
			switch variant {
			case "version":
				start.Version = 1
			case "version0":
				start.Version = 0
			case "version3":
				start.Version = 3
			case "host":
				start.Host = ""
			case "secret":
				start.Secret = nil
			case "method":
				start.Method = "agent"
			case "user":
				start.User = "bad user"
			case "pin":
				start.Pin = []byte("invalid")
			}
			data := ssh.Marshal(&start)
			if variant == "trailing" {
				data = append(data, 42)
			}
			// The fixture would accept the valid start, so only the defect refuses.
			fixture := newFixture(t, fixtureOptions{host: host, user: user, password: syntheticRemotePassword})
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
