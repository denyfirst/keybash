//go:build linux && browserlab

package sshtransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/remotefixture"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

type ownedSSHFixture struct {
	t          *testing.T
	host, user ssh.Signer
	closed     atomic.Bool
}

func (f *ownedSSHFixture) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, pin []byte, user string, signer ssh.Signer) (terminalweb.Stream, error) {
	fixture := newFixture(f.t, fixtureOptions{host: f.host, user: f.user, shellFixture: func(c ssh.Channel) { _, _ = io.Copy(c, c) }})
	// The ONLY loopback substitution is in this test. Production Worker uses
	// Connect -> NamedTarget -> policy/literal dial with no override flag.
	terminal, e := connect(ctx, target.Hostname(), func(context.Context) (net.Conn, error) { return fixture.client, nil }, Config{User: user, HostKey: pin, Signer: signer, Columns: 100, Rows: 30})
	if e == nil {
		go func() { <-ctx.Done(); _ = terminal.Close(); f.closed.Store(true) }()
	}
	return terminal, e
}
func TestBrowserOwnedSSHConnectionAndLogout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture key failed")
	}
	user, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal("fixture signer failed")
	}
	block, e := ssh.MarshalPrivateKey(key, "synthetic")
	if e != nil {
		t.Fatal("fixture encoding failed")
	}
	host := syntheticSigner(t)
	ip := netip.MustParseAddr("10.44.0.2")
	policy, e := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 22)}, nil)
	if e != nil {
		t.Fatal("fixture policy failed")
	}
	target, e := targetguard.NewNamedTarget(policy, "ssh.invalid", 22, []netip.Addr{ip})
	if e != nil {
		t.Fatal("fixture target failed")
	}
	worker := &ownedSSHFixture{t: t, host: host, user: user}
	remotefixture.Run(t, ctx, identity.RemoteTarget{ID: strings.Repeat("a", 32), Name: "Owned SSH", Protocol: "ssh", Target: target, Identity: host.PublicKey().Marshal()}, worker, nil, string(pem.EncodeToMemory(block)), "node", nil)
	deadline := time.Now().Add(time.Second)
	for !worker.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !worker.closed.Load() {
		t.Fatal("account logout failed to cancel SSH")
	}
}
