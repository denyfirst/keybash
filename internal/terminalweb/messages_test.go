package terminalweb

import (
	"bytes"
	"context"
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

// messageStream plays the proxy: messages to the browser go in out, what the
// browser sends arrives on in.
type messageStream struct {
	out    chan []byte
	in     chan []byte
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	reason Reason
}

func newMessageStream() *messageStream {
	return &messageStream{out: make(chan []byte, 8), in: make(chan []byte, 1024), done: make(chan struct{})}
}

func (s *messageStream) ReadMessage() ([]byte, error) {
	select {
	case m := <-s.out:
		return m, nil
	case <-s.done:
		return nil, io.EOF
	}
}

func (s *messageStream) WriteMessage(p []byte) error {
	select {
	case s.in <- append([]byte(nil), p...):
		return nil
	case <-s.done:
		return io.EOF
	}
}

func (s *messageStream) Reason() Reason { s.mu.Lock(); defer s.mu.Unlock(); return s.reason }

func (s *messageStream) Close() error { s.once.Do(func() { close(s.done) }); return nil }

// endItself is the proxy ending the desktop with its own word.
func (s *messageStream) endItself(r Reason) {
	s.mu.Lock()
	s.reason = r
	s.mu.Unlock()
	_ = s.Close()
}

// desktopClient relays a socket to stream under session; finished closes
// when RelayMessages returns.
func desktopClient(t *testing.T, session context.Context, stream MessageStream, admit func([]byte) bool) (*websocket.Conn, chan struct{}) {
	t.Helper()
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		RelayMessages(session, conn, stream, admit)
		close(finished)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadLimit(2 * MaxMessage)
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn, finished
}

func admitAll([]byte) bool { return true }

// closeOf reads until the socket ends and returns its close code and text.
func closeOf(t *testing.T, conn *websocket.Conn) (websocket.StatusCode, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for {
		_, _, err := conn.Read(ctx)
		if err == nil {
			continue
		}
		var closed websocket.CloseError
		if errors.As(err, &closed) {
			return closed.Code, closed.Reason
		}
		return -1, err.Error()
	}
}

func waitFinished(t *testing.T, finished chan struct{}, stream *messageStream) {
	t.Helper()
	select {
	case <-finished:
	case <-time.After(8 * time.Second):
		t.Fatal("the relay did not return")
	}
	select {
	case <-stream.done:
	default:
		t.Fatal("the relay returned with the stream open")
	}
}

// Whole binary messages pass both ways, unchanged.
func TestDesktopMessagesPassWholeBothWays(t *testing.T) {
	stream := newMessageStream()
	conn, _ := desktopClient(t, context.Background(), stream, admitAll)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	up := bytes.Repeat([]byte{7}, MaxMessage)
	if conn.Write(ctx, websocket.MessageBinary, up) != nil {
		t.Fatal("write")
	}
	select {
	case got := <-stream.in:
		if !bytes.Equal(got, up) {
			t.Fatal("the browser's message changed on the way")
		}
	case <-ctx.Done():
		t.Fatal("the browser's message did not arrive")
	}
	down := []byte("from windows")
	stream.out <- down
	kind, got, err := conn.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || !bytes.Equal(got, down) {
		t.Fatalf("the desktop's message arrived as %v %q %v", kind, got, err)
	}
}

// However it ends, the page is told why in the close: the session's cause
// first, then the proxy's own word, then "refused" for what the browser sent.
func TestADesktopSaysWhyItEndedInItsClose(t *testing.T) {
	ctx := context.Background()
	t.Run("the session ends", func(t *testing.T) {
		stream := newMessageStream()
		session, end := context.WithCancelCause(ctx)
		conn, finished := desktopClient(t, session, stream, admitAll)
		end(ReasonIdle)
		if code, text := closeOf(t, conn); code != 4001 || text != "idle" {
			t.Fatalf("closed with %d %q", code, text)
		}
		waitFinished(t, finished, stream)
	})
	t.Run("the proxy ends it", func(t *testing.T) {
		stream := newMessageStream()
		conn, finished := desktopClient(t, ctx, stream, admitAll)
		stream.endItself(ReasonCredentials)
		if code, text := closeOf(t, conn); code != 4005 || text != "credentials" {
			t.Fatalf("closed with %d %q", code, text)
		}
		waitFinished(t, finished, stream)
	})
	for name, send := range map[string]func(*websocket.Conn) error{
		"a text message": func(c *websocket.Conn) error {
			return c.Write(ctx, websocket.MessageText, []byte(`{"type":"ack"}`))
		},
		"an empty message": func(c *websocket.Conn) error {
			return c.Write(ctx, websocket.MessageBinary, nil)
		},
		"more than the budget": func(c *websocket.Conn) error {
			for range desktopMessagesPerSecond + 1 {
				if err := c.Write(ctx, websocket.MessageBinary, []byte{0}); err != nil {
					return nil // already closed: the budget ended it
				}
			}
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			stream := newMessageStream()
			conn, finished := desktopClient(t, ctx, stream, admitAll)
			_ = send(conn)
			if code, text := closeOf(t, conn); code != 4011 || text != "refused" {
				t.Fatalf("closed with %d %q", code, text)
			}
			waitFinished(t, finished, stream)
		})
	}
}

// A message the gateway does not admit (the session is no longer live) ends
// the desktop and never reaches the proxy; nor does one over the limit.
func TestUnadmittedAndOversizedMessagesNeverReachTheProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream := newMessageStream()
	conn, finished := desktopClient(t, context.Background(), stream, func([]byte) bool { return false })
	_ = conn.Write(ctx, websocket.MessageBinary, []byte{1})
	closeOf(t, conn)
	waitFinished(t, finished, stream)
	if len(stream.in) != 0 {
		t.Fatal("an unadmitted message reached the proxy")
	}
	stream = newMessageStream()
	conn, finished = desktopClient(t, context.Background(), stream, admitAll)
	_ = conn.Write(ctx, websocket.MessageBinary, make([]byte, MaxMessage+1))
	closeOf(t, conn)
	waitFinished(t, finished, stream)
	if len(stream.in) != 0 {
		t.Fatal("a message over the limit reached the proxy")
	}
}

// Every reason has its own close code in the private range, and the
// identity notice has one apart from them.
func TestEveryReasonHasItsOwnCloseCode(t *testing.T) {
	seen := map[websocket.StatusCode]bool{CloseIdentityChanged: true}
	for reason := range reasons {
		code, ok := closeCodes[reason]
		if !ok || code < 4000 || code > 4999 || seen[code] {
			t.Fatalf("%s has close code %d", reason, code)
		}
		seen[code] = true
	}
	if _, ok := closeCodes["anything else"]; ok || len(closeCodes) != len(reasons) {
		t.Fatal("a word that is no reason has a close code")
	}
}
