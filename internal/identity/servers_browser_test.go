//go:build browserlab

package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sessionlimits"
	"golang.org/x/crypto/ssh"
)

// TestBrowserServersPage drives the Servers page as an administrator: add a
// server after comparing its fingerprint, choose who may use it, see it in
// the connection form, and remove it. Scans are answered by a table, as in
// the store tests; nothing is dialled.
func TestBrowserServersPage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	store, _, _, code := custodyFixture(t)
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	catalog := catalogSSHFixture(t)
	l, e := NewRemoteLabWithLimits(origin, store, []RemoteTarget{catalog}, echoSSHWorker{}, nil, sessionlimits.Default(), TargetNetworks(serverNetworks, serverProtected))
	if e != nil {
		t.Fatal("servers browser fixture refused")
	}
	defer l.Close()
	scans := &fixtureScans{keys: map[netip.AddrPort]ssh.PublicKey{}}
	key := hostKeyFixture(t)
	scans.set("10.20.0.7:22", key)
	l.mu.Lock()
	l.remote.scan = scans.scan
	l.mu.Unlock()
	server.Config.Handler = l
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, _ := json.Marshal(struct{ Origin, Code, Password, Catalog, Fingerprint string }{origin, code, alicePassword, catalog.ID, ssh.FingerprintSHA256(key)})
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "servers-browser-test.mjs")) // #nosec G204 -- fixed synthetic browser driver and stdin-only fixture data.
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("servers page browser checks failed")
	}
	scans.mu.Lock()
	defer scans.mu.Unlock()
	if scans.calls < 2 {
		t.Fatal("the page did not read the server's identity before adding it")
	}
}
