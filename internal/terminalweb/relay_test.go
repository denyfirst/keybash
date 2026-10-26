package terminalweb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// bulkStream emits a fixed amount of remote output, then stays open like a
// shell waiting at its prompt. Input is drained and counted.
type bulkStream struct {
	output io.Reader
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	input  int
}

func newBulkStream(size int) *bulkStream {
	s := &bulkStream{done: make(chan struct{})}
	s.output = io.MultiReader(bytes.NewReader(bytes.Repeat([]byte("x"), size)), s)
	return s
}

// Read on the stream itself is the "prompt": it blocks until Close.
func (s *bulkStream) Read(b []byte) (int, error)     { <-s.done; return 0, io.EOF }
func (s *bulkStream) ReadStderr([]byte) (int, error) { <-s.done; return 0, io.EOF }
func (s *bulkStream) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.input += len(b)
	return len(b), nil
}
func (s *bulkStream) Resize(uint32, uint32) error { return nil }
func (s *bulkStream) Close() error                { s.once.Do(func() { close(s.done) }); return nil }

type bulkOutput struct{ *bulkStream }

func (s bulkOutput) Read(b []byte) (int, error) { return s.output.Read(b) }

// The owned caller (identity) supplies TLS, Origin, MFA and ownership. This
// exercises only the credit transport that Relay adds on top of them.
func relayClient(t *testing.T, stream Stream) *websocket.Conn {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		Relay(r.Context(), conn, stream)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

// A browser that renders and acknowledges as fast as it can must receive
// bulk output (cat of a log, a long build) beyond the former 8 MiB lifetime
// ceiling, and its acknowledgments must not count as typed input.
func TestRelayAcknowledgedBulkOutputHasNoLifetimeCeiling(t *testing.T) {
	const total = 9 * 1024 * 1024
	stream := newBulkStream(total)
	conn := relayClient(t, bulkOutput{stream})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	received := 0
	for expected := uint32(1); received < total; expected++ {
		kind, frame, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("relay closed acknowledged output after %d of %d bytes", received, total)
		}
		if kind != websocket.MessageBinary || len(frame) < 5 || len(frame) > 8196 || binary.BigEndian.Uint32(frame) != expected {
			t.Fatal("relay output frame was malformed or out of order")
		}
		received += len(frame) - 4
		ack, _ := json.Marshal(control{Type: "ack", Sequence: expected})
		if err := conn.Write(ctx, websocket.MessageText, ack); err != nil {
			t.Fatal(err)
		}
	}
	if received != total {
		t.Fatal("relay changed the output length")
	}
	// The session is still interactive after the burst.
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("ls\r")); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); ; {
		stream.mu.Lock()
		typed := stream.input
		stream.mu.Unlock()
		if typed == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("input after bulk output did not reach the stream")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Credit cannot be spent ahead of output: an acknowledgment for a frame the
// relay never sent closes the stream.
func TestRelayRefusesUnsentCredit(t *testing.T) {
	stream := newBulkStream(8192)
	conn := relayClient(t, bulkOutput{stream})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, frame, err := conn.Read(ctx); err != nil || binary.BigEndian.Uint32(frame) != 1 {
		t.Fatal("missing first frame")
	}
	// The next in-order number is still refused: frame 2 was never sent.
	for _, ack := range []string{`{"type":"ack","sequence":1}`, `{"type":"ack","sequence":2}`} {
		if err := conn.Write(ctx, websocket.MessageText, []byte(ack)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-stream.done:
	case <-ctx.Done():
		t.Fatal("unsent credit kept the stream")
	}
}
