package identity

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// journalLines is a journal that hands each write to the test.
type journalLines chan string

func (j journalLines) Write(p []byte) (int, error) { j <- string(p); return len(p), nil }

// A desktop that ends as "refused" leaves one line in the journal: which
// side sent what, in fixed words, whether the proxy refused it or the
// gateway did. A desktop that ends any other way leaves none. Nothing from
// the session reaches the journal: not what crossed the desktop, nor the
// account, the server, its address, the person or the page's proof.
func TestARefusedDesktopLeavesOneJournalLine(t *testing.T) {
	server, origin := tlsFixture(t)
	l, _, c, record, worker := remoteFixture(t, origin)
	journal := make(journalLines, 8)
	l.journal = journal
	l.remote.desktopSettle = 0
	startTLS(t, server, l)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	good := http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}
	var proofs []string
	open := func() (*websocket.Conn, *fixtureMessages) {
		t.Helper()
		raw := grantFixture(t, c, record)
		proofs = append(proofs, raw)
		socket, err := dialDesktop(ctx, server, origin, good)
		if err != nil {
			t.Fatal("a valid desktop socket was refused")
		}
		t.Cleanup(func() { _ = socket.CloseNow() })
		if socket.Write(ctx, websocket.MessageBinary, desktopRequest(t, c.csrf+"."+raw)) != nil {
			t.Fatal("the request could not be sent")
		}
		select {
		case proxy := <-worker.messages:
			<-proxy.first
			return socket, proxy
		case <-ctx.Done():
			t.Fatal("the proxy was not started")
			return nil, nil
		}
	}
	line := func() string {
		t.Helper()
		select {
		case l := <-journal:
			return l
		case <-time.After(5 * time.Second):
			t.Fatal("no journal line")
			return ""
		}
	}
	none := func(what string) {
		t.Helper()
		select {
		case l := <-journal:
			t.Fatalf("%s: a journal line %q", what, l)
		case <-time.After(300 * time.Millisecond):
		}
	}
	var written []string

	// The proxy refuses what Windows sent after text crossed the desktop.
	socket, proxy := open()
	const text = "Synthetic clipboard text 7f3a"
	if socket.Write(ctx, websocket.MessageBinary, []byte(text)) != nil {
		t.Fatal("a desktop message was refused")
	}
	if _, data, err := socket.Read(ctx); err != nil || string(data) != text {
		t.Fatal("the desktop's message did not cross")
	}
	proxy.endItself(terminalweb.ReasonRefused, terminalweb.Refusal{Side: "windows", What: "clipboard format list"})
	if code, word := closeCode(ctx, socket); code != 4011 || word != "refused" {
		t.Fatalf("closed with %d %q", code, word)
	}
	got := line()
	if got != "desktop refused: side=windows reason=\"clipboard format list\"\n" {
		t.Fatalf("journal line %q", got)
	}
	written = append(written, got)
	none("one refusal")

	// Windows ends a desktop: no line.
	socket, proxy = open()
	proxy.endItself(terminalweb.ReasonRemoteEnded, terminalweb.Refusal{})
	if code, _ := closeCode(ctx, socket); code != 4008 {
		t.Fatalf("closed with %d", code)
	}
	none("remote ended")

	// The gateway refuses a browser message that is not binary.
	socket, _ = open()
	_ = socket.Write(ctx, websocket.MessageText, []byte(`{"text":"`+text+`"}`))
	if code, _ := closeCode(ctx, socket); code != 4011 {
		t.Fatalf("closed with %d", code)
	}
	got = line()
	if got != "desktop refused: side=browser reason=\"desktop message not binary\"\n" {
		t.Fatalf("journal line %q", got)
	}
	written = append(written, got)
	none("one refusal")

	all := strings.Join(written, "")
	for _, secret := range append([]string{text, "7f3a", worker.expected, "synthetic-user", "rdp.invalid", "10.34.0.8", "alice", "Synthetic", c.csrf}, proofs...) {
		if strings.Contains(all, secret) {
			t.Errorf("%q reached the journal", secret)
		}
	}
}

// Journal takes one writer, never none and never a second.
func TestJournalTakesOneWriter(t *testing.T) {
	l := &Lab{}
	if Journal(nil)(l) == nil {
		t.Fatal("no writer was taken")
	}
	journal := make(journalLines, 1)
	if Journal(journal)(l) != nil || Journal(make(journalLines, 1))(l) == nil {
		t.Fatal("not exactly one writer")
	}
	// Without a journal nothing is written, and nothing fails.
	(&Lab{}).noteRefusal(terminalweb.Refusal{Side: "windows", What: "PDU size"})
	l.noteRefusal(terminalweb.Refusal{Side: "windows\nside=browser", What: "PDU size"})
	if got := <-journal; got != "desktop refused: side=unknown reason=\"PDU size\"\n" {
		t.Fatalf("journal line %q", got)
	}
}
