//go:build browserlab

package sshtransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

func TestBrowserTerminalLab(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	server := httptest.NewUnstartedServer(nil)
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.IdleTimeout = 10 * time.Second
	server.Config.MaxHeaderBytes = 8192
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	host, user := syntheticSigner(t), syntheticSigner(t)
	factory := func(sessionCtx context.Context) (terminalweb.Stream, error) {
		fixture := newFixture(t, browserFixtureOptions(t, host, user))
		return connect(sessionCtx, "ssh-lab.example", func(context.Context) (net.Conn, error) { return fixture.client, nil }, labConfig(host, user))
	}
	lab, code, err := terminalweb.New("https://"+server.Listener.Addr().String(), factory)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = lab
	server.StartTLS()
	defer server.Close()
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "browser-test.mjs"))
	input, _ := json.Marshal(struct{ Origin, Code, Mode string }{server.URL, code, runtime.GOOS})
	command.Stdin = bytes.NewReader(input)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		t.Fatal("browser lab verification failed")
	}
}
