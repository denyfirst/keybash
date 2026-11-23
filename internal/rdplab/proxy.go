package rdplab

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// Keybash's RDP proxy (rdp-proxy/, docs/BROWSER-RDP-PROXY.md) speaks frames on
// the worker's pipes: a type byte, a 32-bit little-endian length and at most
// 64 KiB of payload, both ways. This is the gateway's side of them; the same
// rules are in rdp-proxy/src/frame.rs and setup.rs.
const (
	proxySetup      byte = 1 // gateway to proxy, once, first
	proxyBrowser    byte = 2 // gateway to proxy: one browser message
	proxyDesktop    byte = 3 // proxy to gateway: bytes for the browser
	proxyEnded      byte = 4 // proxy to gateway: why it ended (proxyEnd)
	proxyMaxPayload      = 64 * 1024

	// An Ended frame's first byte for a refusal; the side and what follow.
	proxyRefused byte = 5
)

var (
	errNative      = errors.New("RDP manager refused")
	errProxyClosed = errors.New("rdp proxy closed")
)

// credentialsAllowed is what may reach a proxy at all: an identity with its
// certificate, its digest and name, a user name of letters, digits and "._-@"
// of at most 128 bytes, and a password of valid UTF-8 without NUL of at most
// 4096 bytes.
func credentialsAllowed(pin *Identity, user, password string) bool {
	if pin == nil || len(pin.der) == 0 || pin.pin == [sha256.Size]byte{} || pin.name == "" ||
		len(user) == 0 || len(user) > 128 || len(password) == 0 || len(password) > 4096 || !utf8.ValidString(password) || strings.ContainsRune(password, 0) {
		return false
	}
	for _, c := range user {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c)) {
			return false
		}
	}
	return true
}

func writeProxyFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > proxyMaxPayload || kind < proxySetup || kind > proxyEnded {
		return errNative
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = kind
	binary.LittleEndian.PutUint32(frame[1:5], uint32(len(payload))) // #nosec G115 -- bounded by proxyMaxPayload above.
	copy(frame[5:], payload)
	_, err := w.Write(frame)
	clear(frame)
	return err
}

// readProxyFrame returns io.EOF only when the stream ends between frames.
func readProxyFrame(r io.Reader) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:1]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, io.EOF
		}
		return 0, nil, errNative
	}
	if _, err := io.ReadFull(r, head[1:]); err != nil {
		return 0, nil, errNative
	}
	length := binary.LittleEndian.Uint32(head[1:])
	if head[0] < proxySetup || head[0] > proxyEnded || length > proxyMaxPayload {
		return 0, nil, errNative
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, errNative
	}
	return head[0], payload, nil
}

// proxySetupPayload is setup format 1: version, user, domain, password, flags.
// browserSetup checks the credentials before it.
func proxySetupPayload(user, domain, password string, clipboard bool) ([]byte, error) {
	if len(user) == 0 || len(user) > 128 || len(domain) > 128 || len(password) == 0 || len(password) > 4096 {
		return nil, errNative
	}
	out := []byte{1}
	for _, text := range []string{user, domain, password} {
		if !utf8.ValidString(text) || containsNUL(text) {
			clear(out)
			return nil, errNative
		}
		out = binary.LittleEndian.AppendUint16(out, uint16(len(text))) // #nosec G115 -- each text is at most 4096 bytes, checked above.
		out = append(out, text...)
	}
	flags := byte(0)
	if clipboard {
		flags = 1
	}
	return append(out, flags), nil
}

func containsNUL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return true
		}
	}
	return false
}

// proxyReasons maps the proxy's one-byte end codes to the words the pages
// know. A refusal is never one byte (proxyEnd).
var proxyReasons = map[byte]terminalweb.Reason{
	1: terminalweb.ReasonCredentials,
	3: terminalweb.ReasonUnreachable,
	6: terminalweb.ReasonRemoteEnded,
}

// proxyEnd reads an Ended frame: one byte for an end that is not a refusal,
// or exactly three for a refusal: proxyRefused, the side and what, named with
// the words in refusals.go. Any other end, including a refusal without its
// codes, is "refused" as the proxy's own fault (proxyFrameRefused).
func proxyEnd(payload []byte) (terminalweb.Reason, terminalweb.Refusal) {
	switch {
	case len(payload) == 1:
		if reason, known := proxyReasons[payload[0]]; known {
			return reason, terminalweb.Refusal{}
		}
	case len(payload) == 3 && payload[0] == proxyRefused:
		return terminalweb.ReasonRefused, proxyRefusal(payload[1], payload[2])
	}
	return terminalweb.ReasonRefused, proxyFrameRefused
}

// ProxyStream is one browser desktop through the proxy: whole messages each
// way, at most 64 KiB, and the proxy's reason when it ends.
type ProxyStream struct {
	conn   net.Conn
	write  sync.Mutex
	ended  atomic.Pointer[streamEnd]
	closed atomic.Bool
}

// streamEnd is why a stream ended, and, when that is "refused", which side
// sent what, in fixed words.
type streamEnd struct {
	reason  terminalweb.Reason
	refusal terminalweb.Refusal
}

func newProxyStream(conn net.Conn) *ProxyStream { return &ProxyStream{conn: conn} }

func (s *ProxyStream) end(r terminalweb.Reason, refusal terminalweb.Refusal) {
	s.ended.CompareAndSwap(nil, &streamEnd{reason: r, refusal: refusal})
}

// ReadMessage returns the next bytes for the browser. When the proxy says why
// it ended, or anything malformed arrives, it returns an error and Reason says
// why; for a refusal, Refusal says what.
func (s *ProxyStream) ReadMessage() ([]byte, error) {
	kind, payload, err := readProxyFrame(s.conn)
	switch {
	case errors.Is(err, io.EOF):
		return nil, errProxyClosed
	case err != nil:
		if !s.closed.Load() {
			s.end(terminalweb.ReasonRefused, proxyFrameRefused)
		}
		return nil, errNative
	case kind == proxyDesktop && len(payload) > 0:
		return payload, nil
	case kind == proxyEnded:
		s.end(proxyEnd(payload))
		return nil, errProxyClosed
	default:
		s.end(terminalweb.ReasonRefused, proxyFrameRefused)
		return nil, errNative
	}
}

// WriteMessage passes one browser message to the proxy.
func (s *ProxyStream) WriteMessage(p []byte) error {
	if len(p) == 0 || len(p) > proxyMaxPayload {
		return errNative
	}
	s.write.Lock()
	defer s.write.Unlock()
	return writeProxyFrame(s.conn, proxyBrowser, p)
}

// Reason says why the proxy ended the desktop, if it said.
func (s *ProxyStream) Reason() terminalweb.Reason {
	if e := s.ended.Load(); e != nil {
		return e.reason
	}
	return ""
}

// Refusal names, in fixed words, which side sent what was refused, when the
// desktop ended as "refused".
func (s *ProxyStream) Refusal() (terminalweb.Refusal, bool) {
	if e := s.ended.Load(); e != nil && e.reason == terminalweb.ReasonRefused {
		return e.refusal, true
	}
	return terminalweb.Refusal{}, false
}

var _ terminalweb.RefusingStream = (*ProxyStream)(nil)

// Close ends the worker; it unblocks every read and write.
func (s *ProxyStream) Close() error {
	s.closed.Store(true)
	return s.conn.Close()
}

// OpenBrowserRDP starts the proxy for a desktop whose RDP client runs in the
// browser (ADR 0008, D); the gateway's desktop socket relays to it
// (identity.RDPWorker). The pin is enforced by the proxy's own TLS before
// CredSSP (rdp-proxy/src/pin.rs). The clipboard is on: the
// proxy keeps it to bounded text (docs/BROWSER-RDP-PROXY.md, 2c), and the
// desktop page acts only on the person's own copy and paste
// (docs/BROWSER-RDP-PAGE.md, 3d).
func (w ManagerWorker) OpenBrowserRDP(ctx context.Context, request identity.RDPRequest) (terminalweb.MessageStream, error) {
	if request.Target == nil {
		return nil, errNative
	}
	pin, err := identityFor(request.Target, request.Certificate)
	if err != nil || !pin.boundTo(request.Target) {
		return nil, errNative
	}
	stream, err := w.openBrowserDial(ctx, request.Target.DialContext, pin, request.Username, request.Password)
	if err != nil {
		return nil, err // never a typed nil inside the interface
	}
	return stream, nil
}

var _ identity.RDPWorker = ManagerWorker{}

// browserSetup checks the credentials (credentialsAllowed), then makes the
// setup frame, with the clipboard on.
func browserSetup(pin *Identity, user, password string) ([]byte, error) {
	if !credentialsAllowed(pin, user, password) {
		return nil, errNative
	}
	return proxySetupPayload(user, "", password, true)
}

// Only package _test.go callers can replace this guarded dial for a fixture.
func (w ManagerWorker) openBrowserDial(ctx context.Context, dial func(context.Context) (net.Conn, error), pin *Identity, user, password string) (*ProxyStream, error) {
	if ctx == nil || ctx.Err() != nil || dial == nil {
		return nil, errNative
	}
	payload, err := browserSetup(pin, user, password)
	if err != nil {
		return nil, errNative
	}
	defer clear(payload)
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := connectRDPManager(ctx, setup, w.SocketPath, dial, pin)
	if err != nil {
		return nil, errNative
	}
	if writeProxyFrame(raw, proxySetup, payload) != nil {
		_ = raw.Close()
		return nil, errNative
	}
	return newProxyStream(raw), nil
}
