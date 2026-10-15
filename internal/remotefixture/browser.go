//go:build linux && browserlab

// Package remotefixture is compiled only for synthetic browser laboratory tests.
package remotefixture

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

	"github.com/denyfirst/keybash/internal/identity"
)

func Run(t *testing.T, ctx context.Context, target identity.RemoteTarget, ssh identity.SSHWorker, rdp identity.RDPWorker, secret, node string, env []string) {
	t.Helper()
	base := t.TempDir()
	data, keys := filepath.Join(base, "data"), filepath.Join(base, "keys")
	for _, dir := range []string{data, keys} {
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("private remote fixture mkdir failed")
		}
	}
	store, code, e := identity.InitializeFiles(data, filepath.Join(keys, "instance.key"))
	if e != nil {
		t.Fatal("remote fixture store failed")
	}
	defer store.Close()
	server := httptest.NewUnstartedServer(nil)
	l, e := identity.NewRemoteLab("https://"+server.Listener.Addr().String(), store, []identity.RemoteTarget{target}, ssh, rdp)
	if e != nil {
		t.Fatal("remote fixture authorization failed")
	}
	defer l.Close()
	server.Config.Handler = l
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.IdleTimeout = 10 * time.Second
	server.Config.MaxHeaderBytes = 8192
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, _ := json.Marshal(struct{ Origin, Code, Password, Mode, Secret, Target string }{server.URL, code, "Synthetic owned account password 73!", target.Protocol, secret, target.ID})
	command := exec.CommandContext(ctx, node, filepath.Join("..", "..", "web", "owned-browser-test.mjs")) // #nosec G204 -- test-only fixed script, generated synthetic secrets via stdin, no real credentials.
	command.Env = env
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("owned remote browser checks failed")
	}
}
