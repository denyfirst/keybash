package terminalweb

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
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
)

type fakeStream struct {
	reader  *io.PipeReader
	writer  *io.PipeWriter
	done    chan struct{}
	once    sync.Once
	input   chan []byte
	resizes chan [2]uint32
}

func newStream() *fakeStream {
	r, w := io.Pipe()
	return &fakeStream{reader: r, writer: w, done: make(chan struct{}), input: make(chan []byte, 16), resizes: make(chan [2]uint32, 8)}
}
func (s *fakeStream) Read(b []byte) (int, error)     { return s.reader.Read(b) }
func (s *fakeStream) ReadStderr([]byte) (int, error) { <-s.done; return 0, io.EOF }
func (s *fakeStream) Write(b []byte) (int, error) {
	select {
	case s.input <- append([]byte(nil), b...):
		return len(b), nil
	case <-s.done:
		return 0, io.ErrClosedPipe
	}
}
func (s *fakeStream) Resize(c, r uint32) error {
	select {
	case s.resizes <- [2]uint32{c, r}:
		return nil
	case <-s.done:
		return io.ErrClosedPipe
	}
}
func (s *fakeStream) Close() error {
	s.once.Do(func() { close(s.done); _ = s.reader.Close(); _ = s.writer.Close() })
	return nil
}

type fixture struct {
	server *httptest.Server
	lab    *Lab
	code   string
	cookie *http.Cookie
	stream *fakeStream
	calls  atomic.Int32
}

func newLab(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{stream: newStream()}
	f.server = httptest.NewUnstartedServer(nil)
	f.server.Config.ReadHeaderTimeout = 5 * time.Second
	f.server.Config.MaxHeaderBytes = 8192
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	origin := "https://" + f.server.Listener.Addr().String()
	var err error
	f.lab, f.code, err = New(origin, func(context.Context) (Stream, error) { f.calls.Add(1); return f.stream, nil })
	if err != nil {
		t.Fatal(err)
	}
	f.server.Config.Handler = f.lab
	f.server.StartTLS()
	t.Cleanup(func() { _ = f.stream.Close(); f.server.Close() })
	return f
}
func (f *fixture) post(t *testing.T, path, origin, code string, authorized bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.server.URL+path, strings.NewReader(code))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("X-Keybash-Lab", "1")
	req.Header.Set("Content-Type", "text/plain")
	if authorized {
		req.AddCookie(f.cookie)
	}
	response, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}
func (f *fixture) grant(t *testing.T) {
	t.Helper()
	response := f.post(t, "/lab/grant", f.server.URL, f.code, false)
	if response.StatusCode != http.StatusNoContent || len(response.Cookies()) != 1 {
		t.Fatal("lab grant refused")
	}
	f.cookie = response.Cookies()[0]
	if !f.cookie.HttpOnly || !f.cookie.Secure || f.cookie.SameSite != http.SameSiteStrictMode || f.cookie.Path != "/" || f.cookie.Domain != "" {
		t.Fatal("session cookie is not restricted")
	}
}
func (f *fixture) dial(t *testing.T, origin string, cookie *http.Cookie) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	headers := http.Header{"Origin": {origin}}
	if cookie != nil {
		headers.Set("Cookie", cookie.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return websocket.Dial(ctx, strings.Replace(f.server.URL, "https:", "wss:", 1)+"/lab/socket", &websocket.DialOptions{HTTPClient: f.server.Client(), HTTPHeader: headers})
}

func TestLabHTTPSHostOriginAndOneUseGrant(t *testing.T) {
	f := newLab(t)
	for _, test := range []struct{ origin, code string }{{"https://evil.example", f.code}, {"", f.code}, {f.server.URL, strings.Repeat("x", 43)}, {f.server.URL, strings.Repeat("x", 65)}} {
		if response := f.post(t, "/lab/grant", test.origin, test.code, false); response.StatusCode != http.StatusForbidden {
			t.Fatal("unsafe grant accepted")
		}
	}
	f.grant(t)
	if f.post(t, "/lab/grant", f.server.URL, f.code, false).StatusCode != http.StatusForbidden {
		t.Fatal("bootstrap replay accepted")
	}
	for _, path := range []string{"/?secret=x", "/../go.mod", "/vendor/manifest.json"} {
		response, err := f.server.Client().Get(f.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("unexpected asset/query was served")
		}
	}
	request := httptest.NewRequest(http.MethodGet, f.server.URL, nil)
	request.TLS = nil
	w := httptest.NewRecorder()
	f.lab.ServeHTTP(w, request)
	if w.Code != http.StatusForbidden {
		t.Fatal("plaintext request accepted")
	}
	request = httptest.NewRequest(http.MethodGet, f.server.URL, nil)
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	request.RemoteAddr = "127.0.0.1:12345"
	request.Host = "attacker.example"
	w = httptest.NewRecorder()
	f.lab.ServeHTTP(w, request)
	if w.Code != http.StatusForbidden {
		t.Fatal("DNS-rebound host accepted")
	}
	request.Host = f.lab.host
	request.RemoteAddr = "192.0.2.1:12345"
	w = httptest.NewRecorder()
	f.lab.ServeHTTP(w, request)
	if w.Code != http.StatusForbidden {
		t.Fatal("non-loopback peer accepted")
	}
	response, err := f.server.Client().Get(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("asset security headers missing")
	}
}

func TestLabSocketRequiresExactOriginOwnerAndSingleSession(t *testing.T) {
	f := newLab(t)
	for _, origin := range []string{f.server.URL, "https://evil.example", ""} {
		conn, response, err := f.dial(t, origin, nil)
		if conn != nil {
			_ = conn.CloseNow()
		}
		if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
			t.Fatal("unowned socket accepted")
		}
	}
	f.grant(t)
	for _, origin := range []string{"", "https://evil.example", strings.Replace(f.server.URL, "https:", "http:", 1)} {
		conn, _, err := f.dial(t, origin, f.cookie)
		if conn != nil {
			_ = conn.CloseNow()
		}
		if err == nil {
			t.Fatal("wrong-origin owner socket accepted")
		}
	}
	conn, _, err := f.dial(t, f.server.URL, f.cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	other, _, err := f.dial(t, f.server.URL, f.cookie)
	if other != nil {
		_ = other.CloseNow()
	}
	if err == nil {
		t.Fatal("second socket accepted")
	}
	if f.calls.Load() != 1 {
		t.Fatal("refused socket reached terminal factory")
	}
}

func TestLabInputResizeOutputCreditAndLogoutRevocation(t *testing.T) {
	f := newLab(t)
	f.grant(t)
	conn, _, err := f.dial(t, f.server.URL, f.cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	input := []byte("Azərbaycan\x03\x1b[A")
	if err := conn.Write(ctx, websocket.MessageBinary, input); err != nil {
		t.Fatal(err)
	}
	if got := <-f.stream.input; !bytes.Equal(got, input) {
		t.Fatal("input changed in transit")
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","columns":120,"rows":40}`)); err != nil {
		t.Fatal(err)
	}
	if got := <-f.stream.resizes; got != [2]uint32{120, 40} {
		t.Fatal("resize changed")
	}
	writeDone := make(chan struct{})
	go func() { _, _ = f.stream.writer.Write(bytes.Repeat([]byte("a"), 16384)); close(writeDone) }()
	for sequence := uint32(1); sequence <= 2; sequence++ {
		kind, frame, err := conn.Read(ctx)
		if err != nil || kind != websocket.MessageBinary || len(frame) != 8196 || binary.BigEndian.Uint32(frame) != sequence {
			t.Fatal("invalid ordered output")
		}
		if sequence == 1 {
			f.lab.mu.Lock()
			pending := f.lab.active
			f.lab.mu.Unlock()
			if !pending {
				t.Fatal("output session disappeared")
			}
		}
		ack, _ := json.Marshal(control{Type: "ack", Sequence: sequence})
		if err := conn.Write(ctx, websocket.MessageText, ack); err != nil {
			t.Fatal(err)
		}
	}
	<-writeDone
	if f.post(t, "/lab/logout", f.server.URL, "", true).StatusCode != http.StatusNoContent {
		t.Fatal("logout refused")
	}
	select {
	case <-f.stream.done:
	case <-ctx.Done():
		t.Fatal("logout did not revoke active stream")
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("revoked socket still read")
	}
	if next, _, err := f.dial(t, f.server.URL, f.cookie); err == nil {
		_ = next.CloseNow()
		t.Fatal("revoked cookie accepted")
	}
}

func TestLabMalformedOversizedAndUnexpectedAckCloseStream(t *testing.T) {
	for _, data := range [][]byte{[]byte(`{"type":"ack","sequence":1}`), []byte(`{"type":"resize","columns":501,"rows":1}`), []byte(`{"type":"resize","columns":1,"rows":1,"target":"other"}`), []byte(`{} {}`), bytes.Repeat([]byte("x"), 32769)} {
		f := newLab(t)
		f.grant(t)
		conn, _, err := f.dial(t, f.server.URL, f.cookie)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = conn.Write(ctx, websocket.MessageText, data)
		_, _, err = conn.Read(ctx)
		if err == nil {
			t.Fatal("unsafe input accepted")
		}
		select {
		case <-f.stream.done:
		case <-ctx.Done():
			t.Fatal("unsafe input leaked stream")
		}
		cancel()
		_ = conn.CloseNow()
	}
}

func TestLabInvalidConfigurationAndControlBounds(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:1234", "https://evil.example:1234", "https://127.0.0.1:0", "https://127.0.0.1:1234/", "https://user@127.0.0.1:1234", "https://127.0.0.1:1234?x=y"} {
		if lab, _, err := New(origin, func(context.Context) (Stream, error) { return nil, errors.New("synthetic") }); lab != nil || err != ErrInvalidLab {
			t.Fatal("unsafe lab origin accepted")
		}
	}
	for _, data := range []string{"", `null`, `{"type":"input"}`, `{"type":"ack","sequence":0}`, `{"type":"ack","sequence":1,"sequence":2}`, `{"type":"ack","sequence":1,"rows":2}`, `{"type":"resize","columns":-1,"rows":1}`, strings.Repeat(" ", 1025)} {
		if _, ok := parseControl([]byte(data)); ok {
			t.Fatal("invalid control accepted")
		}
	}
	window := flow{credit: make(chan struct{}, 1), sequence: 1}
	if window.acknowledge(2) || !window.acknowledge(1) || window.acknowledge(1) {
		t.Fatal("output credit accepted duplicate/out-of-order acknowledgment")
	}
}

func TestLabExpiryAndRateCloseOwnedStream(t *testing.T) {
	f := newLab(t)
	f.grant(t)
	f.lab.mu.Lock()
	f.lab.expires = time.Now().Add(80 * time.Millisecond)
	f.lab.mu.Unlock()
	conn, _, err := f.dial(t, f.server.URL, f.cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	select {
	case <-f.stream.done:
	case <-time.After(2 * time.Second):
		t.Fatal("absolute expiry did not close active stream")
	}
	if next, _, err := f.dial(t, f.server.URL, f.cookie); err == nil {
		_ = next.CloseNow()
		t.Fatal("expired cookie accepted")
	}
	f = newLab(t)
	f.grant(t)
	conn, _, err = f.dial(t, f.server.URL, f.cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	go func() {
		for {
			select {
			case <-f.stream.input:
			case <-f.stream.done:
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 129; i++ {
		if conn.Write(ctx, websocket.MessageBinary, []byte("x")) != nil {
			break
		}
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("input rate limit was ignored")
	}
	select {
	case <-f.stream.done:
	case <-ctx.Done():
		t.Fatal("rate refusal leaked stream")
	}
}

func TestLabOutputWaitsForMatchingCredit(t *testing.T) {
	f := newLab(t)
	f.grant(t)
	conn, _, err := f.dial(t, f.server.URL, f.cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	go func() { _, _ = f.stream.writer.Write(bytes.Repeat([]byte("x"), 16384)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, frame, err := conn.Read(ctx)
	if err != nil || binary.BigEndian.Uint32(frame) != 1 {
		t.Fatal("missing first frame")
	}
	// The second frame cannot be emitted without rendering credit. An
	// out-of-order credit closes the stream instead of granting capacity.
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"ack","sequence":2}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("unacknowledged output advanced")
	}
}

func TestLabOutputQuotaClosesBeforeExtraData(t *testing.T) {
	f := newLab(t)
	f.lab.outputLimit = 8192
	f.grant(t)
	conn, _, err := f.dial(t, f.server.URL, f.cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	go func() { _, _ = f.stream.writer.Write(bytes.Repeat([]byte("x"), 8193)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, frame, err := conn.Read(ctx)
	if err != nil || len(frame) != 8196 {
		t.Fatal("allowed output boundary was refused")
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"ack","sequence":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("extra output exceeded the quota")
	}
	select {
	case <-f.stream.done:
	case <-ctx.Done():
		t.Fatal("output quota leaked its stream")
	}
}

func FuzzTerminalControl(f *testing.F) {
	for _, seed := range []string{`{"type":"ack","sequence":1}`, `{"type":"resize","columns":100,"rows":30}`, `null`, `{} {}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		command, ok := parseControl(data)
		if !ok {
			return
		}
		if command.Type == "ack" {
			if command.Sequence == 0 || command.Columns != 0 || command.Rows != 0 {
				t.Fatal("invalid ack")
			}
		} else if command.Type != "resize" || command.Sequence != 0 || command.Columns == 0 || command.Columns > 500 || command.Rows == 0 || command.Rows > 200 {
			t.Fatal("invalid resize")
		}
	})
}
