//go:build browserlab

package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBrowserPasswordLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	server := httptest.NewUnstartedServer(nil)
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.IdleTimeout = 10 * time.Second
	server.Config.MaxHeaderBytes = 8192
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	lab, err := NewLab("https://"+server.Listener.Addr().String(), accounts(t))
	if err != nil {
		t.Fatal("browser identity fixture refused")
	}
	defer lab.Close()
	server.Config.Handler = lab
	server.StartTLS()
	defer server.Close()
	data, _ := json.Marshal(struct{ Origin, Username, Password, Replacement, Screenshot string }{
		server.URL, "alice", alicePassword, nextPassword, os.Getenv("KEYBASH_LOGIN_SCREENSHOT"),
	})
	script := filepath.Join("..", "..", "web", "auth-browser-test.mjs")
	command := exec.CommandContext(ctx, "node", script) // #nosec G204 -- fixed test runtime/script; synthetic passwords only via stdin.
	command.Stdin = bytes.NewReader(data)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("browser password login failed")
	}
}
