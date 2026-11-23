package terminalweb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// refusingStream is a proxy that can name its refusal.
type refusingStream struct {
	*messageStream
	refusal Refusal
	named   bool
}

func (s *refusingStream) Refusal() (Refusal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refusal, s.named
}

// refuse ends the desktop as the proxy does when it refuses what one side sent.
func (s *refusingStream) refuse(r Refusal) {
	s.mu.Lock()
	s.refusal, s.named = r, true
	s.mu.Unlock()
	s.endItself(ReasonRefused)
}

type relayEnd struct {
	reason  Reason
	refusal Refusal
}

// endedDesktop relays a socket to stream under session and hands back what
// RelayMessages returned.
func endedDesktop(t *testing.T, session context.Context, stream MessageStream) (*websocket.Conn, chan relayEnd) {
	t.Helper()
	ended := make(chan relayEnd, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		reason, refusal := RelayMessages(session, conn, stream, admitAll)
		ended <- relayEnd{reason, refusal}
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn, ended
}

func relayEnded(t *testing.T, ended chan relayEnd) relayEnd {
	t.Helper()
	select {
	case e := <-ended:
		return e
	case <-time.After(8 * time.Second):
		t.Fatal("the relay did not return")
		return relayEnd{}
	}
}

// The relay returns the reason the page was told and, for "refused", which
// side sent what: the proxy's own words, its own words for a browser message
// that is not binary, and "unknown" when the stream names nothing. Any other
// end, or a session's cause over the stream's word, names no refusal.
func TestARefusedDesktopNamesWhatWasRefused(t *testing.T) {
	ctx := context.Background()
	clipboard := Refusal{Side: "windows", What: "clipboard format list"}
	t.Run("the proxy refuses", func(t *testing.T) {
		stream := &refusingStream{messageStream: newMessageStream()}
		conn, ended := endedDesktop(t, ctx, stream)
		stream.refuse(clipboard)
		if code, text := closeOf(t, conn); code != 4011 || text != "refused" {
			t.Fatalf("closed with %d %q", code, text)
		}
		if e := relayEnded(t, ended); e != (relayEnd{ReasonRefused, clipboard}) {
			t.Fatalf("returned %+v", e)
		}
	})
	t.Run("the browser sends text", func(t *testing.T) {
		stream := &refusingStream{messageStream: newMessageStream()}
		conn, ended := endedDesktop(t, ctx, stream)
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"ack"}`))
		closeOf(t, conn)
		if e := relayEnded(t, ended); e != (relayEnd{ReasonRefused, browserMessageRefused}) {
			t.Fatalf("returned %+v", e)
		}
	})
	t.Run("a stream that names nothing", func(t *testing.T) {
		stream := newMessageStream()
		conn, ended := endedDesktop(t, ctx, stream)
		stream.endItself(ReasonRefused)
		closeOf(t, conn)
		if e := relayEnded(t, ended); e != (relayEnd{ReasonRefused, unknownRefusal}) {
			t.Fatalf("returned %+v", e)
		}
	})
	t.Run("an end that is not a refusal", func(t *testing.T) {
		stream := &refusingStream{messageStream: newMessageStream()}
		conn, ended := endedDesktop(t, ctx, stream)
		stream.endItself(ReasonRemoteEnded)
		closeOf(t, conn)
		if e := relayEnded(t, ended); e != (relayEnd{ReasonRemoteEnded, Refusal{}}) {
			t.Fatalf("returned %+v", e)
		}
	})
	t.Run("the session's cause comes first", func(t *testing.T) {
		stream := &refusingStream{messageStream: newMessageStream(), refusal: clipboard, named: true}
		session, end := context.WithCancelCause(ctx)
		conn, ended := endedDesktop(t, session, stream)
		end(ReasonIdle)
		closeOf(t, conn)
		if e := relayEnded(t, ended); e != (relayEnd{ReasonIdle, Refusal{}}) {
			t.Fatalf("returned %+v", e)
		}
	})
}

// The journal's line holds the two words and nothing else. A side outside
// the four, and a word with a quote, a line break, anything outside plain
// ASCII words, or over 64 bytes, is "unknown": text from a session cannot
// reach the journal through it, nor start a second line.
func TestARefusalLineHoldsFixedWordsOnly(t *testing.T) {
	got := Refusal{Side: "windows", What: "clipboard before Windows' is open"}.Line()
	if want := "desktop refused: side=windows reason=\"clipboard before Windows' is open\"\n"; got != want {
		t.Fatalf("line %q, want %q", got, want)
	}
	for _, side := range []string{"browser", "windows", "keybash", "unknown"} {
		if line := (Refusal{Side: side, What: "PDU size"}).Line(); !strings.Contains(line, "side="+side+" ") {
			t.Errorf("side %q: %q", side, line)
		}
	}
	for _, bad := range []Refusal{
		{Side: "", What: ""},
		{Side: "Windows", What: "PDU size"},
		{Side: "windows\ndesktop refused: side=browser", What: "PDU size"},
		{Side: "windows", What: "PDU size\" injected=\"1"},
		{Side: "windows", What: "PDU size\" injected side"},
		{Side: "windows", What: "two\nlines"},
		{Side: "windows", What: "Synthetic clipboard text: héllo"},
		{Side: "windows", What: "Synthetic clipboard text; password=p"},
		{Side: "windows", What: strings.Repeat("a", 65)},
		{Side: "windows", What: "tab\tinside"},
		{Side: "windows", What: "nul\x00inside"},
	} {
		line := bad.Line()
		if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") || strings.Count(line, `"`) != 2 {
			t.Errorf("%+v: %q is not one line of two words", bad, line)
		}
		if bad.Side != "windows" && !strings.Contains(line, "side=unknown ") {
			t.Errorf("%+v: side kept in %q", bad, line)
		}
		if bad.What != "PDU size" && !strings.HasSuffix(line, `reason="unknown"`+"\n") {
			t.Errorf("%+v: word kept in %q", bad, line)
		}
		for _, text := range []string{"Synthetic", "password", "injected", "héllo"} {
			if strings.Contains(line, text) {
				t.Errorf("%q reached the line %q", text, line)
			}
		}
	}
	if (Refusal{Side: "windows", What: strings.Repeat("a", 64)}).Line() == (Refusal{Side: "windows", What: "unknown"}).Line() {
		t.Fatal("a 64-byte word was refused")
	}
}
