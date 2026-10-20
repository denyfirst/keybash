//go:build browserlab

package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

type portableSSHWorker struct{ echo fixtureRDPWorker }

func (f *portableSSHWorker) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, _ []byte, user string, _ ssh.Signer) (terminalweb.Stream, error) {
	return f.echo.OpenRDP(ctx, RDPRequest{Target: target, Username: user, Password: f.echo.expected})
}
func TestBrowserOwnedRemotePortable(t *testing.T) { runOwnedPortable(t, false, false) }
func TestBrowserServerTrustWorkflow(t *testing.T) { runOwnedPortable(t, true, false) }
func TestBrowserCapacityWorkflow(t *testing.T)    { runOwnedPortable(t, false, true) }
func runOwnedPortable(t *testing.T, review, capacity bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	store, _, _, code := custodyFixture(t)
	server := httptest.NewUnstartedServer(nil)
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture key failed")
	}
	block, e := ssh.MarshalPrivateKey(key, "synthetic")
	if e != nil {
		t.Fatal("fixture encoding failed")
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal("fixture signer failed")
	}
	target := remoteTargetFixture(t)
	target.Protocol = "ssh"
	target.Identity = signer.PublicKey().Marshal()
	worker := &portableSSHWorker{echo: fixtureRDPWorker{expected: "synthetic"}}
	limits := sessionlimits.Default()
	if capacity {
		limits = sessionlimits.Limits{Total: 16, PerOwner: 1}
	}
	l, e := NewRemoteLabWithLimits("https://"+server.Listener.Addr().String(), store, []RemoteTarget{target}, worker, nil, limits)
	if e != nil {
		t.Fatal("owned portable fixture refused")
	}
	defer l.Close()
	server.Config.Handler = l
	control, updatedFingerprint := "", ""
	if review {
		control, e = token()
		if e != nil {
			t.Fatal("fixture control failed")
		}
		_, next, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal("fixture replacement failed")
		}
		nextSigner, e := ssh.NewSignerFromKey(next)
		if e != nil {
			t.Fatal("fixture replacement signer failed")
		}
		updated := target
		updated.Identity = nextSigner.PublicKey().Marshal()
		updated.Target = networkFixture(t, "rdp.invalid", 3390, "10.34.0.9")
		updatedFingerprint = ssh.FingerprintSHA256(nextSigner.PublicKey())
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/__fixture/trust-change" {
				if r.Method != "POST" || r.Header.Get("X-Fixture-Control") != control {
					w.WriteHeader(403)
					return
				}
				// Synthetic catalog replacement exists only in this test. Runtime
				// operator configuration is immutable until a restart logs out all.
				l.mu.Lock()
				l.remote.targets[target.ID] = updated
				l.mu.Unlock()
				w.WriteHeader(204)
				return
			}
			l.ServeHTTP(w, r)
		})
	}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, _ := json.Marshal(struct {
		Origin, Code, Password, Mode, Secret, Target, Fingerprint, UpdatedFingerprint, Control string
		CapacityTest                                                                           bool
	}{server.URL, code, "Synthetic owned account password 73!", "ssh", string(pem.EncodeToMemory(block)), target.ID, ssh.FingerprintSHA256(signer.PublicKey()), updatedFingerprint, control, capacity})
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "owned-browser-test.mjs")) // #nosec G204 -- fixed synthetic browser driver and stdin-only fixture data.
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("portable owned UI checks failed")
	}
	if capacity && worker.echo.calls.Load() != 1 {
		t.Fatal("busy browser started an extra worker")
	}
}
