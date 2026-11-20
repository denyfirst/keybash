//go:build browserlab

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/rdcleanpath"
	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// pageProxy plays Keybash's RDP proxy for the desktop page: each desktop the
// page opens takes the next ending, and the request the gateway forwarded is
// kept for the test to read.
type pageProxy struct {
	mu        sync.Mutex
	endings   []terminalweb.Reason // "" never answers
	forwarded chan []byte
}

func (p *pageProxy) OpenRDP(context.Context, RDPRequest) (terminalweb.Stream, error) {
	return nil, errRefused
}

func (p *pageProxy) OpenBrowserRDP(ctx context.Context, r RDPRequest) (terminalweb.MessageStream, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.endings) == 0 || r.Password != "Synthetic remote password" || r.Username != "synthetic-user" {
		return nil, errRefused
	}
	s := &pageStream{reason: p.endings[0], forwarded: p.forwarded, done: make(chan struct{})}
	p.endings = p.endings[1:]
	go func() { <-ctx.Done(); _ = s.Close() }()
	return s, nil
}

type pageStream struct {
	reason    terminalweb.Reason
	forwarded chan []byte
	done      chan struct{}
	once      sync.Once
	first     sync.Once
}

func (s *pageStream) WriteMessage(m []byte) error {
	s.first.Do(func() {
		s.forwarded <- append([]byte(nil), m...)
		// A proxy that ends with a reason ends right after the request, as
		// it does when Windows refuses the stored password.
		if s.reason != "" {
			_ = s.Close()
		}
	})
	return nil
}
func (s *pageStream) ReadMessage() ([]byte, error) { <-s.done; return nil, io.EOF }
func (s *pageStream) Reason() terminalweb.Reason   { return s.reason }
func (s *pageStream) Close() error                 { s.once.Do(func() { close(s.done) }); return nil }

// The desktop page on IronRDP in a real browser (BROWSER-RDP-PAGE.md, 3d): the
// module compiles under the page's policy, the page's proof reaches the
// gateway inside IronRDP's first message and never the proxy, every ending
// is told in the gateway's words, a changed server says so, and a desktop
// that does not start within 20 seconds says that. No secret is in an
// address, nothing leaves the gateway's origin, and the clipboard is never
// touched unasked.
func TestBrowserDesktopPage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	server, origin := tlsFixture(t)
	store, _, _ := bootstrapped(t)
	f := &adminLab{t: t, store: store, now: time.Now(), target: catalogSSHFixture(t)}
	_, _, codes := enrollFixture(t, store, "alice", f.now)
	proxy := &pageProxy{endings: []terminalweb.Reason{terminalweb.ReasonCredentials, ""}, forwarded: make(chan []byte, 4)}
	l, e := NewRemoteLabWithLimits(origin, store, []RemoteTarget{f.target}, echoSSHWorker{}, proxy, sessionlimits.Default(), TargetNetworks(serverNetworks, serverProtected), WatchCertificates(24*time.Hour))
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	t.Cleanup(func() { _ = l.Close() })
	reads := newFixtureCertificates()
	f.l = l
	l.mu.Lock()
	l.remote.scanRDP = reads.scan
	l.mu.Unlock()
	f.alice = &custodyClient{t: t, l: l}
	f.alice.login()
	f.alice.session("challenge")
	f.alice.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	f.alice.session("ready")
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	id, _ := addDesktop(t, f, reads, "Desk", "10.20.0.8:3389")
	record := desktopConnection(t, f, f.alice, mustLookup(t, store, "alice"), id)
	control, e := token()
	if e != nil {
		t.Fatal("fixture control failed")
	}
	startTLS(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server now shows another certificate; only this test can say so.
		if r.URL.Path == "/__fixture/server-changed" {
			if r.Method != "POST" || r.Header.Get("X-Fixture-Control") != control {
				w.WriteHeader(403)
				return
			}
			reads.set("10.20.0.8:3389", windowsLeaf(t, nil))
			w.WriteHeader(204)
			return
		}
		l.ServeHTTP(w, r)
	}))
	config, _ := json.Marshal(struct{ Origin, Record, Cookie, Value, Control string }{origin, record, f.alice.cookie.Name, f.alice.cookie.Value, control})
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "desktop-page-browser-test.mjs")) // #nosec G204 -- fixed synthetic browser driver and stdin-only fixture data.
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("the desktop page's browser checks failed")
	}
	// Both desktops the proxy saw got IronRDP's request for TLS alone, with
	// neither the page's proof nor a destination.
	if len(proxy.forwarded) != 2 {
		t.Fatalf("the proxy saw %d desktops", len(proxy.forwarded))
	}
	for range 2 {
		forwarded := <-proxy.forwarded
		request, err := rdcleanpath.Parse(forwarded)
		if err != nil || request.Token != "" || len(request.X224) == 0 || bytes.Contains(forwarded, []byte(f.alice.csrf)) {
			t.Fatalf("the proxy got %x", forwarded)
		}
	}
}
