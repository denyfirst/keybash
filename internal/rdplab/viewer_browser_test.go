//go:build browserlab

package rdplab

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

func browserViewer(t *testing.T, ctx context.Context, node string, factory terminalweb.Factory, screenshot string, env []string) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.IdleTimeout = 10 * time.Second
	server.Config.MaxHeaderBytes = 8192
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	lab, code, err := terminalweb.NewDesktop("https://"+server.Listener.Addr().String(), factory)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = lab
	server.StartTLS()
	defer server.Close()
	script := filepath.Join("..", "..", "web", "desktop-browser-test.mjs")
	if _, e := os.Stat(script); e != nil {
		script = filepath.Join("web", "desktop-browser-test.mjs")
	}
	command := exec.CommandContext(ctx, node, script) // #nosec G204 -- fixed test runtime/script, no browser-selected command.
	if env != nil {
		command.Env = env
	}
	data, _ := json.Marshal(struct{ Origin, Code, Screenshot string }{server.URL, code, screenshot})
	command.Stdin = bytes.NewReader(data)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if command.Run() != nil {
		t.Fatal("browser RDP verification failed")
	}
}

func TestBrowserRDPViewerLab(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	png := fixturePNG(t)
	// Synthetic rendering/transport on any test workstation; the real native
	// Linux case is separately required. No native worker or user account here.
	factory := func(c context.Context) (terminalweb.Stream, error) {
		s, remote, _ := viewerFixture(t)
		go func() { <-c.Done(); _ = s.Close() }()
		go func() {
			for _, in := range []instruction{{"size", "0", "1024", "768"}, {"rect", "0", "0", "0", "1024", "768"}, {"cfill", "14", "0", "160", "160", "160", "255"},
				{"img", "0", "14", "-1", "image/png", "0", "0"}, {"blob", "0", base64.StdEncoding.EncodeToString(png)}, {"end", "0"}, {"copy", "-1", "0", "0", "2", "2", "14", "0", "4", "4"}, {"sync", "123", "1"}} {
				if writeInstruction(remote, in) != nil {
					return
				}
			}
		}()
		return s, nil
	}
	browserViewer(t, ctx, "node", factory, os.Getenv("KEYBASH_DESKTOP_SCREENSHOT"), nil)
}
