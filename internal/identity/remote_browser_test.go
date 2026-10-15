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
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

type portableSSHWorker struct{ echo fixtureRDPWorker }

func (f *portableSSHWorker) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, _ []byte, user string, _ ssh.Signer) (terminalweb.Stream, error) {
	return f.echo.OpenRDP(ctx, RDPRequest{Target: target, Username: user, Password: f.echo.expected})
}
func TestBrowserOwnedRemotePortable(t *testing.T) {
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
	l, e := NewRemoteLab("https://"+server.Listener.Addr().String(), store, []RemoteTarget{target}, worker, nil)
	if e != nil {
		t.Fatal("owned portable fixture refused")
	}
	defer l.Close()
	server.Config.Handler = l
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, _ := json.Marshal(struct{ Origin, Code, Password, Mode, Secret, Target string }{server.URL, code, "Synthetic owned account password 73!", "ssh", string(pem.EncodeToMemory(block)), target.ID})
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "owned-browser-test.mjs")) // #nosec G204 -- fixed synthetic browser driver and stdin-only fixture data.
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("portable owned UI checks failed")
	}
}
