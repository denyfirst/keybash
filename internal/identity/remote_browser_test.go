//go:build browserlab

package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

// portableSSHWorker is a counted echo terminal for the fixture's one account
// and server.
type portableSSHWorker struct{ calls atomic.Int32 }

func (w *portableSSHWorker) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, key []byte, user string, c sshkey.Credential) (terminalweb.Stream, error) {
	password, ok := c.(*sshkey.Password)
	if !ok || user != "synthetic-user" || target.Hostname() != "rdp.invalid" {
		return nil, errRefused
	}
	if value, e := password.Bytes(); e != nil || string(value) != portablePassword {
		return nil, errRefused
	}
	w.calls.Add(1)
	return echoSSHWorker{}.OpenSSH(ctx, target, key, user, c)
}

// portablePassword is the account's password the browser types once.
const portablePassword = "Synthetic owned account SSH password 41!"

func TestBrowserOwnedRemotePortable(t *testing.T) { runOwnedPortable(t, false, false) }
func TestBrowserServerTrustWorkflow(t *testing.T) { runOwnedPortable(t, true, false) }
func TestBrowserCapacityWorkflow(t *testing.T)    { runOwnedPortable(t, false, true) }
func runOwnedPortable(t *testing.T, review, capacity bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	store, _, _, code := custodyFixture(t)
	server := httptest.NewUnstartedServer(nil)
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture key failed")
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal("fixture signer failed")
	}
	target := remoteTargetFixture(t)
	target.Protocol, target.Name = "ssh", "Owned remote"
	target.Identity = signer.PublicKey().Marshal()
	worker := &portableSSHWorker{}
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
		updatedFingerprint = ssh.FingerprintSHA256(nextSigner.PublicKey())
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/__fixture/trust-change" {
				if r.Method != "POST" || r.Header.Get("X-Fixture-Control") != control {
					w.WriteHeader(403)
					return
				}
				// The server's key changes and an administrator accepts it, as
				// the Servers page does after comparing it on the console.
				admin, e := store.lookup("alice")
				if e != nil || store.repinServer(admin.ID, target.ID, nextSigner.PublicKey().Marshal()) != nil {
					w.WriteHeader(500)
					return
				}
				l.mu.Lock()
				_ = l.reloadServersLocked()
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
	}{server.URL, code, "Synthetic owned account password 73!", "ssh", portablePassword, target.ID, ssh.FingerprintSHA256(signer.PublicKey()), updatedFingerprint, control, capacity})
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "owned-browser-test.mjs")) // #nosec G204 -- fixed synthetic browser driver and stdin-only fixture data.
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("portable owned UI checks failed")
	}
	if capacity && worker.calls.Load() != 1 {
		t.Fatal("busy browser started an extra worker")
	}
}
