//go:build browserlab

package identity

// Interactive workstation preview. Every simulated worker and the portable
// storage seam stay in _test.go: no demo switch enters the shipped command.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func runInteractiveDemo(t *testing.T, interactive bool) {
	t.Helper()
	lifetime := 90 * time.Second
	if interactive {
		lifetime = time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), lifetime)
	defer cancel()
	store, _, _, code := custodyFixture(t)
	server := httptest.NewUnstartedServer(nil)
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.IdleTimeout = 10 * time.Second
	server.Config.MaxHeaderBytes = 8192
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("demo entropy failed")
	}
	block, err := ssh.MarshalPrivateKey(key, "ephemeral interactive demo")
	if err != nil {
		t.Fatal("demo key encoding failed")
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal("demo signer failed")
	}
	desktop := remoteTargetFixture(t)
	desktop.Name = "Desktop demo (simulation, not Windows)"
	terminal := desktop
	terminal.ID, terminal.Name, terminal.Protocol = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "Linux SSH UI demo (simulation)", "ssh"
	terminal.Identity = signer.PublicKey().Marshal()
	worker := &demoWorker{}
	lab, err := NewRemoteLab("https://"+server.Listener.Addr().String(), store, []RemoteTarget{terminal, desktop}, worker, worker)
	if err != nil {
		t.Fatal("demo admission failed")
	}
	defer lab.Close()
	server.Config.Handler = lab
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, err := json.Marshal(struct {
		Origin, Code, Password, SSHSecret, RDPSecret, SSH, RDP, SSHFingerprint, RDPFingerprint string
		Interactive                                                                            bool
	}{server.URL, code, "Synthetic Keybash demo password 73!", string(pem.EncodeToMemory(block)), demoRemotePassword, terminal.ID, desktop.ID, ssh.FingerprintSHA256(signer.PublicKey()), demoCertificateFingerprint(desktop.Identity), interactive})
	if err != nil {
		t.Fatal("demo configuration failed")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("demo driver unavailable")
	}
	command := exec.CommandContext(ctx, "node", filepath.Join(filepath.Dir(source), "..", "..", "web", "demo-browser.mjs")) // #nosec G204 -- fixed test driver; synthetic data only through stdin.
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err = command.Run(); err != nil && !(interactive && ctx.Err() != nil) {
		t.Fatal("interactive demo/browser check failed")
	}
}

func demoCertificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

func TestInteractiveDemo(t *testing.T) {
	if os.Getenv("KEYBASH_INTERACTIVE_DEMO") != "1" {
		t.Skip("opt-in workstation preview; use scripts/demo.ps1")
	}
	runInteractiveDemo(t, true)
}

func TestInteractiveDemoBrowser(t *testing.T) { runInteractiveDemo(t, false) }
