//go:build browserlab

package identity

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
// the connection form, and remove it. Then a desktop: add it with the line from
// its console, see Windows renew its certificate, and accept the new one the
// same way. Last, a desktop added without the check, and checked later. Reads
// are answered by tables, as in the store tests; nothing is dialled.
func TestBrowserServersPage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Second)
	defer cancel()
	store, _, _, code := custodyFixture(t)
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	catalog := catalogSSHFixture(t)
	l, e := NewRemoteLabWithLimits(origin, store, []RemoteTarget{catalog}, echoSSHWorker{}, &desktopWorker{}, sessionlimits.Default(), TargetNetworks(serverNetworks, serverProtected), WatchCertificates(24*time.Hour))
	if e != nil {
		t.Fatal("servers browser fixture refused")
	}
	defer l.Close()
	scans := &fixtureScans{keys: map[netip.AddrPort]ssh.PublicKey{}}
	key := hostKeyFixture(t)
	scans.set("10.20.0.7:22", key)
	reads := newFixtureCertificates()
	first, renewed, side := windowsLeaf(t, nil), windowsLeaf(t, nil), windowsLeaf(t, nil)
	reads.set("10.20.0.8:3389", first)
	reads.set("10.20.0.10:3389", side)
	l.mu.Lock()
	l.remote.scan = scans.scan
	l.remote.scanRDP = reads.scan
	l.mu.Unlock()
	server.Config.Handler = l
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, _ := json.Marshal(struct{ Origin, Code, Password, Catalog, Fingerprint, Desktop, Renewed, Side string }{origin, code, alicePassword, catalog.ID, ssh.FingerprintSHA256(key), certificatePrint(first), certificatePrint(renewed), certificatePrint(side)})
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "servers-browser-test.mjs")) // #nosec G204 -- fixed synthetic browser driver and stdin-only fixture data.
	command.Stdin = bytes.NewReader(config)
	command.Stderr = os.Stderr
	output, e := command.StdoutPipe()
	if e != nil || command.Start() != nil {
		t.Fatal("servers page browser checks did not start")
	}
	// The driver says when it wants Windows to have renewed its certificate;
	// the gateway then finds out by itself, as it does on its schedule.
	lines := bufio.NewScanner(output)
	for lines.Scan() {
		if lines.Text() == "KB_RENEW" {
			// Windows renews months after the adding, not within the same
			// minute of reads, so this one's limit does not reach the check.
			l.mu.Lock()
			delete(l.attempts, "scan:alice")
			l.mu.Unlock()
			reads.set("10.20.0.8:3389", renewed)
			l.readCertificates(ctx)
			continue
		}
		fmt.Println(lines.Text())
	}
	if command.Wait() != nil {
		t.Fatal("servers page browser checks failed")
	}
	scans.mu.Lock()
	defer scans.mu.Unlock()
	if scans.calls < 2 {
		t.Fatal("the page did not read the server's identity before adding it")
	}
}
