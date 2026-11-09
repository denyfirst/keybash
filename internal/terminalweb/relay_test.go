package terminalweb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
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

// reasonStream reports a word for why it ended; with ends it ends by itself,
// as a native session does, otherwise it waits like a shell at its prompt.
type reasonStream struct {
	*bulkStream
	reason Reason
	ends   bool
}

func (s reasonStream) Read(b []byte) (int, error) {
	if s.ends {
		return 0, errors.New("remote ended")
	}
	return s.bulkStream.Read(b)
}
func (s reasonStream) Reason() Reason { return s.reason }

// relayEnding is relayClient with the session's context in the test's hands.
func relayEnding(t *testing.T, stream Stream) (*websocket.Conn, func(error)) {
	t.Helper()
	ends := make(chan context.CancelCauseFunc, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ctx, cancel := context.WithCancelCause(r.Context())
		ends <- cancel
		Relay(ctx, conn, stream)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn, func(cause error) {
		select {
		case end := <-ends:
			end(cause)
		case <-time.After(3 * time.Second):
			t.Fatal("relay did not start")
		}
	}
}

// expectEnding reads what the page would: the fixed reason message, if any,
// and then the socket closing.
func expectEnding(t *testing.T, conn *websocket.Conn, stream *bulkStream, want Reason) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	kind, data, err := conn.Read(ctx)
	if want == "" {
		if err == nil {
			t.Fatalf("an ending with no fixed reason said %q", data)
		}
		return
	}
	if err != nil || kind != websocket.MessageText || string(data) != `{"type":"ended","reason":"`+string(want)+`"}` {
		t.Fatalf("got %q (%v), want the %q reason", data, err, want)
	}
	select {
	case <-stream.done:
	default:
		t.Fatal("the reason was said before the remote side stopped")
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("the socket stayed open after its reason")
	}
}

// A session that ends (signed out, idle, access removed) says why on the
// socket, after its remote side has stopped; nothing else is ever said.
func TestRelaySaysWhyTheSessionEnded(t *testing.T) {
	for _, cause := range []error{ReasonIdle, ReasonExpired, ReasonSignedOut, ReasonAccessChanged} {
		stream := newBulkStream(0)
		conn, end := relayEnding(t, stream)
		end(cause)
		expectEnding(t, conn, stream, cause.(Reason))
	}
	for _, cause := range []error{nil, errors.New("internal detail"), Reason(`<b>x</b>`), Reason("")} {
		stream := newBulkStream(0)
		conn, end := relayEnding(t, stream)
		end(cause)
		expectEnding(t, conn, stream, "")
	}
}

// A stream that ends by itself says its own fixed word; the session's cause
// comes first, since it is why the stream stopped.
func TestRelaySaysWhyAStreamEnded(t *testing.T) {
	for _, reason := range []Reason{ReasonCredentials, ReasonAccount, ReasonTakenOver, ReasonRemoteEnded, ReasonUnreachable, ReasonNotResponding, ReasonRefused} {
		stream := newBulkStream(0)
		conn := relayClient(t, reasonStream{stream, reason, true})
		expectEnding(t, conn, stream, reason)
	}
	for _, reason := range []Reason{"", "Authentication failure (invalid credentials?)", "credentials "} {
		stream := newBulkStream(0)
		conn := relayClient(t, reasonStream{stream, reason, true})
		expectEnding(t, conn, stream, "")
	}
	stream := newBulkStream(0)
	conn, end := relayEnding(t, reasonStream{stream, ReasonCredentials, false})
	end(ReasonAccessChanged)
	expectEnding(t, conn, stream, ReasonAccessChanged)
}

// A stream that stops the moment its session ends can end the relay's own
// context before the session's cause reaches it: a session cancels its many
// watchers one after another. The page is still told the session's reason.
func TestRelaySaysWhyEvenWhenTheStreamStopsFirst(t *testing.T) {
	for i := 0; i < 20; i++ {
		stream := newBulkStream(0)
		ends := make(chan context.CancelCauseFunc, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			ctx, cancel := context.WithCancelCause(r.Context())
			// Other watchers of the same session, as a busy server has, so
			// its cancellation takes a while to reach the relay's context.
			watchers := make([]context.CancelFunc, 0, 20000)
			for range 20000 {
				_, stop := context.WithCancel(ctx)
				watchers = append(watchers, stop)
			}
			defer func() {
				for _, stop := range watchers {
					stop()
				}
			}()
			// The worker stops its stream as soon as the session ends.
			go func() { <-ctx.Done(); _ = stream.Close() }()
			ends <- cancel
			Relay(ctx, conn, stream)
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		(<-ends)(ReasonSignedOut)
		expectEnding(t, conn, stream, ReasonSignedOut)
		_ = conn.CloseNow()
		server.Close()
	}
}
