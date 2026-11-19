package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/rdcleanpath"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// fixtureMessages plays the proxy for a browser desktop: it keeps the first
// message (the RDCleanPath request the gateway forwards) and echoes the rest.
type fixtureMessages struct {
	first chan []byte
	echo  chan []byte
	done  chan struct{}
	once  sync.Once
	count atomic.Int32
}

func newFixtureMessages() *fixtureMessages {
	return &fixtureMessages{first: make(chan []byte, 1), echo: make(chan []byte, 16), done: make(chan struct{})}
}

func (m *fixtureMessages) WriteMessage(p []byte) error {
	if m.count.Add(1) == 1 {
		m.first <- append([]byte(nil), p...)
		return nil
	}
	select {
	case m.echo <- append([]byte(nil), p...):
		return nil
	case <-m.done:
		return io.EOF
	}
}

func (m *fixtureMessages) ReadMessage() ([]byte, error) {
	select {
	case p := <-m.echo:
		return p, nil
	case <-m.done:
		return nil, io.EOF
	}
}

func (m *fixtureMessages) Reason() terminalweb.Reason { return "" }
func (m *fixtureMessages) Close() error               { m.once.Do(func() { close(m.done) }); return nil }

func (f *fixtureRDPWorker) OpenBrowserRDP(ctx context.Context, r RDPRequest) (terminalweb.MessageStream, error) {
	if r.Password != f.expected || r.Username != "synthetic-user" || r.Target.Hostname() != "rdp.invalid" {
		return nil, errRefused
	}
	f.calls.Add(1)
	m := newFixtureMessages()
	go func() { <-ctx.Done(); _ = m.Close() }()
	if f.messages != nil {
		f.messages <- m
	}
	return m, nil
}

func (d *desktopWorker) OpenBrowserRDP(ctx context.Context, r RDPRequest) (terminalweb.MessageStream, error) {
	d.calls.Add(1)
	m := newFixtureMessages()
	go func() { <-ctx.Done(); _ = m.Close() }()
	return m, nil
}

// x224Request is IronRDP's X.224 connection request for TLS alone.
var x224Request = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00}

// desktopRequest is IronRDP's first message with the page's token.
func desktopRequest(t *testing.T, token string) []byte {
	t.Helper()
	type request struct {
		Version     int64  `asn1:"explicit,tag:0"`
		Destination string `asn1:"explicit,tag:2,utf8"`
		ProxyAuth   string `asn1:"explicit,tag:3,utf8"`
		X224        []byte `asn1:"explicit,tag:6"`
	}
	der, err := asn1.Marshal(request{rdcleanpath.Version, "rdp.invalid", token, x224Request})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func dialDesktop(ctx context.Context, server *httptest.Server, origin string, header http.Header) (*websocket.Conn, error) {
	socket, _, err := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/desktop",
		&websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: header})
	return socket, err
}

func tlsFixture(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	return server, "https://" + server.Listener.Addr().String()
}

func startTLS(t *testing.T, server *httptest.Server, handler http.Handler) {
	t.Helper()
	server.Config.Handler = handler
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
}

// closeCode reads until the socket ends and returns its close code and text.
func closeCode(ctx context.Context, socket *websocket.Conn) (websocket.StatusCode, string) {
	for {
		_, _, err := socket.Read(ctx)
		if err == nil {
			continue
		}
		var closed websocket.CloseError
		if errors.As(err, &closed) {
			return closed.Code, closed.Reason
		}
		return -1, ""
	}
}

// The page's proof travels inside IronRDP's RDCleanPath request, never in the
// address. The proxy gets the same X.224 request with the token removed; then
// messages pass both ways, and signing out ends the desktop with its word.
func TestTheDesktopOpensWithItsProofInsideRDCleanPath(t *testing.T) {
	server, origin := tlsFixture(t)
	l, _, c, record, worker := remoteFixture(t, origin)
	startTLS(t, server, l)
	raw := grantFixture(t, c, record)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, err := dialDesktop(ctx, server, origin, http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}})
	if err != nil {
		t.Fatal("a valid desktop socket was refused")
	}
	defer socket.CloseNow()
	if socket.Write(ctx, websocket.MessageBinary, desktopRequest(t, c.csrf+"."+raw)) != nil {
		t.Fatal("the request could not be sent")
	}
	var proxy *fixtureMessages
	select {
	case proxy = <-worker.messages:
	case <-ctx.Done():
		t.Fatal("the proxy was not started")
	}
	forwarded := <-proxy.first
	request, err := rdcleanpath.Parse(forwarded)
	if err != nil || request.Token != "" || !bytes.Equal(request.X224, x224Request) {
		t.Fatalf("the proxy got %+v, %v", request, err)
	}
	if bytes.Contains(forwarded, []byte(raw)) || bytes.Contains(forwarded, []byte(c.csrf)) || bytes.Contains(forwarded, []byte("rdp.invalid")) {
		t.Fatal("the page's proof or destination reached the proxy")
	}
	if socket.Write(ctx, websocket.MessageBinary, []byte("synthetic rdp")) != nil {
		t.Fatal("a desktop message was refused")
	}
	kind, data, err := socket.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || string(data) != "synthetic rdp" {
		t.Fatalf("the desktop's message came back as %v %q %v", kind, data, err)
	}
	c.expect("DELETE", "/api/session", "{}", 204)
	if code, text := closeCode(ctx, socket); code != 4003 || text != "signed-out" {
		t.Fatalf("signing out closed the desktop with %d %q", code, text)
	}
	if worker.calls.Load() != 1 {
		t.Fatal("the proxy was started more than once")
	}
}

// Without the session, from another origin or site, or without exactly its
// proof in the first message, no proxy starts.
func TestTheDesktopRefusesWithoutItsProof(t *testing.T) {
	server, origin := tlsFixture(t)
	l, _, c, record, worker := remoteFixture(t, origin)
	startTLS(t, server, l)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	good := http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}
	for name, header := range map[string]http.Header{
		"no session":     {"Origin": []string{origin}},
		"another origin": {"Origin": []string{"https://attacker.invalid"}, "Cookie": []string{c.cookie.String()}},
		// The WebSocket library checks only the host; the gateway wants its
		// exact origin, so the same host without TLS is refused too.
		"the same host without TLS": {"Origin": []string{strings.Replace(origin, "https:", "http:", 1)}, "Cookie": []string{c.cookie.String()}},
		"another site":              {"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}, "Sec-Fetch-Site": []string{"cross-site"}},
	} {
		if socket, err := dialDesktop(ctx, server, origin, header); err == nil {
			_ = socket.CloseNow()
			t.Errorf("%s: the socket opened", name)
		}
	}
	// None of these redeems the lease, so one lease serves them all, and
	// then opens its one desktop below.
	raw := grantFixture(t, c, record)
	for name, first := range map[string]func(raw string) (websocket.MessageType, []byte){
		"the guacd proof": func(raw string) (websocket.MessageType, []byte) {
			return websocket.MessageText, []byte(inputJSON(map[string]string{"csrf": c.csrf, "lease": raw}))
		},
		"not RDCleanPath": func(string) (websocket.MessageType, []byte) {
			return websocket.MessageBinary, []byte("not der")
		},
		"no dot": func(raw string) (websocket.MessageType, []byte) {
			return websocket.MessageBinary, desktopRequest(t, c.csrf+raw)
		},
		"another csrf": func(raw string) (websocket.MessageType, []byte) {
			return websocket.MessageBinary, desktopRequest(t, strings.Repeat("A", 43)+"."+raw)
		},
		"another lease": func(string) (websocket.MessageType, []byte) {
			return websocket.MessageBinary, desktopRequest(t, c.csrf+"."+strings.Repeat("A", 43))
		},
	} {
		socket, err := dialDesktop(ctx, server, origin, good)
		if err != nil {
			t.Fatalf("%s: dial %v", name, err)
		}
		kind, data := first(raw)
		_ = socket.Write(ctx, kind, data)
		if _, _, err := socket.Read(ctx); err == nil {
			t.Errorf("%s: the desktop answered", name)
		}
		_ = socket.CloseNow()
	}
	if worker.calls.Load() != 0 {
		t.Fatalf("%d proxies started without their proof", worker.calls.Load())
	}
	// A lease opens one desktop, once.
	for i := range 2 {
		socket, err := dialDesktop(ctx, server, origin, good)
		if err != nil {
			t.Fatal("dial")
		}
		_ = socket.Write(ctx, websocket.MessageBinary, desktopRequest(t, c.csrf+"."+raw))
		if i == 0 {
			<-worker.messages
		} else if _, _, err := socket.Read(ctx); err == nil {
			t.Error("a used lease opened a second desktop")
		}
		_ = socket.CloseNow()
	}
	if worker.calls.Load() != 1 {
		t.Fatalf("a lease started %d proxies", worker.calls.Load())
	}
}

// A server showing another certificate than the approved one ends the
// desktop before the proxy starts, with its own close.
func TestADesktopWhoseServerChangedSaysSoBeforeStarting(t *testing.T) {
	server, origin := tlsFixture(t)
	f, reads, worker := desktopFixtureAt(t, origin)
	startTLS(t, server, f.l)
	id, _ := addDesktop(t, f, reads, "Desk", "10.20.0.8:3389")
	bob, b := f.person("bob", roleUser)
	record := desktopConnection(t, f, bob, b, id)
	reads.set("10.20.0.8:3389", windowsLeaf(t, nil))
	raw := grantFixture(t, bob, record)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, err := dialDesktop(ctx, server, origin, http.Header{"Origin": []string{origin}, "Cookie": []string{bob.cookie.String()}})
	if err != nil {
		t.Fatal("dial")
	}
	defer socket.CloseNow()
	_ = socket.Write(ctx, websocket.MessageBinary, desktopRequest(t, bob.csrf+"."+raw))
	if code, text := closeCode(ctx, socket); code != terminalweb.CloseIdentityChanged || text != "identity-changed" {
		t.Fatalf("closed with %d %q", code, text)
	}
	if worker.calls.Load() != 0 {
		t.Fatal("a proxy started for a server that changed")
	}
}

func TestTheDesktopTokenAndInputRules(t *testing.T) {
	csrf, lease := strings.Repeat("c", 43), strings.Repeat("l", 43)
	if a, b, ok := desktopToken(csrf + "." + lease); !ok || a != csrf || b != lease {
		t.Fatal("a well-formed token was refused")
	}
	for _, bad := range []string{"", csrf + lease, csrf + "." + lease + "x", csrf + "x" + lease[1:] + "."} {
		if _, _, ok := desktopToken(bad); ok {
			t.Errorf("%q was taken as a token", bad)
		}
	}
	// Fast-path input (keys, mouse) is activity; TPKT replies and stray bytes are not.
	if !fastPathInput([]byte{0x04, 0x00}) || fastPathInput([]byte{0x03, 0x00, 0x00, 0x13}) || fastPathInput([]byte{0x00}) {
		t.Fatal("activity is not the person's input")
	}
}
