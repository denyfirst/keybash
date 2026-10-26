//go:build linux && amd64 && sshprocesslab

package sshtransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/remotefixture"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

func processFixtureKey(t *testing.T) (*sshkey.Key, []byte) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("entropy failed")
	}
	key, err := sshkey.New(private)
	if err != nil {
		t.Fatal("valid key refused")
	}
	block, err := ssh.MarshalPrivateKey(private, "synthetic process lab")
	clear(private)
	if err != nil {
		t.Fatal("key encoding failed")
	}
	t.Cleanup(key.Close)
	return key, pem.EncodeToMemory(block)
}
func processFixtureManager(t *testing.T) ProcessWorker {
	t.Helper()
	path := os.Getenv("KEYBASH_SSH_WORKER")
	if os.Geteuid() != 0 || !strings.HasPrefix(path, "/tmp/keybash-ssh-process.") || !strings.HasSuffix(path, "/worker") {
		t.Fatal("requires isolated CI manager")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("worker image missing")
	}
	return ProcessWorker{Path: path, Digest: sha256.Sum256(data)}
}

func TestSSHProcessIsolatedAuthenticationAndRevocation(t *testing.T) {
	manager := processFixtureManager(t)
	user, _ := processFixtureKey(t)
	host := syntheticSigner(t)
	closed := make(chan struct{})
	fixture := newFixture(t, fixtureOptions{host: host, user: user, shellFixture: func(c ssh.Channel) { defer close(closed); _, _ = io.Copy(c, c) }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := manager.open(ctx, "ssh.invalid", func(context.Context) (net.Conn, error) { return fixture.client, nil }, host.PublicKey().Marshal(), "lab-user", user)
	if err != nil {
		t.Fatal("valid isolated worker refused")
	}
	defer stream.Close()
	text := []byte("isolated SSH input: əöğ\r\n")
	if n, err := stream.Write(text); err != nil || n != len(text) {
		t.Fatal("process input refused")
	}
	got := make([]byte, len(text))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, text) {
		t.Fatal("process input/output changed")
	}
	if stream.Resize(140, 40) != nil || stream.Resize(501, 40) == nil {
		t.Fatal("process resize boundary failed")
	}
	if _, err := stream.Write(make([]byte, MaxInputBytes+1)); err == nil {
		t.Fatal("excess process input accepted")
	}
	cancel()
	if stream.Close() != nil {
		t.Fatal("worker process did not join after revocation")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("revoked child retained target connection")
	}
	if n, err := stream.Read(make([]byte, 32)); n != 0 || err == nil {
		t.Fatal("revoked process output remained readable")
	}
}

func TestSSHProcessChangedPinNeverAuthenticates(t *testing.T) {
	manager := processFixtureManager(t)
	user, _ := processFixtureKey(t)
	host := syntheticSigner(t)
	fixture := newFixture(t, fixtureOptions{host: host, user: user})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := manager.open(ctx, "ssh.invalid", func(context.Context) (net.Conn, error) { return fixture.client, nil }, syntheticSigner(t).PublicKey().Marshal(), "lab-user", user)
	if stream != nil {
		_ = stream.Close()
	}
	if err == nil {
		t.Fatal("changed process host pin accepted")
	}
	if ctx.Err() != nil {
		t.Fatal("pin refusal stalled instead of completing")
	}
	if fixture.auth.Load() != 0 {
		t.Fatal("worker used credential before server verification")
	}
}

func TestSSHProcessRequiresConfiguredKeyAuthentication(t *testing.T) {
	manager := processFixtureManager(t)
	user, _ := processFixtureKey(t)
	host := syntheticSigner(t)
	fixture := newFixture(t, fixtureOptions{host: host, user: user, noAuth: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := manager.open(ctx, "ssh.invalid", func(context.Context) (net.Conn, error) { return fixture.client, nil }, host.PublicKey().Marshal(), "lab-user", user)
	if stream != nil {
		_ = stream.Close()
	}
	if err == nil || ctx.Err() != nil {
		t.Fatal("worker accepted none authentication or refusal stalled")
	}
}

func TestSSHProcessImageAndPolicyRefuseBeforeDial(t *testing.T) {
	manager := processFixtureManager(t)
	user, _ := processFixtureKey(t)
	host := syntheticSigner(t)
	for _, w := range []ProcessWorker{{Path: manager.Path}, {Path: manager.Path, Digest: sha256.Sum256([]byte("wrong"))}, {Path: "/tmp/does-not-exist", Digest: manager.Digest}} {
		called := false
		stream, err := w.open(context.Background(), "ssh.invalid", func(context.Context) (net.Conn, error) { called = true; return nil, ErrProcess }, host.PublicKey().Marshal(), "lab-user", user)
		if stream != nil {
			_ = stream.Close()
		}
		if err == nil || called {
			t.Fatal("invalid worker image reached target dial")
		}
	}
	ip := netip.MustParseAddr("10.44.0.2")
	policy, err := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 22)}, nil)
	if err != nil {
		t.Fatal("fixture policy failed")
	}
	target, err := targetguard.NewNamedTarget(policy, "ssh.invalid", 22, []netip.Addr{ip})
	if err != nil {
		t.Fatal("fixture target failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if stream, err := manager.OpenSSH(ctx, target, host.PublicKey().Marshal(), "lab-user", user); err == nil || stream != nil {
		t.Fatal("canceled process launch accepted")
	}
}

type processOwnedFixture struct {
	t          *testing.T
	manager    ProcessWorker
	host, user ssh.Signer
	closed     chan struct{}
}

func (f *processOwnedFixture) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, pin []byte, user string, auth sshkey.Credential) (terminalweb.Stream, error) {
	fixture := newFixture(f.t, fixtureOptions{host: f.host, user: f.user})
	// Only this _test.go seam substitutes a loopback peer. Runtime OpenSSH
	// always calls NamedTarget.DialContext before descriptor handoff.
	stream, err := f.manager.open(ctx, target.Hostname(), func(context.Context) (net.Conn, error) { return fixture.client, nil }, pin, user, auth)
	if err == nil {
		go func() { <-ctx.Done(); _ = stream.Close(); close(f.closed) }()
	}
	return stream, err
}
func TestSSHProcessOwnedBrowser(t *testing.T) {
	manager := processFixtureManager(t)
	user, secret := processFixtureKey(t)
	host := syntheticSigner(t)
	ip := netip.MustParseAddr("10.44.0.2")
	policy, err := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 22)}, nil)
	if err != nil {
		t.Fatal("fixture policy failed")
	}
	target, err := targetguard.NewNamedTarget(policy, "ssh.invalid", 22, []netip.Addr{ip})
	if err != nil {
		t.Fatal("fixture target failed")
	}
	f := &processOwnedFixture{t: t, manager: manager, host: host, user: user, closed: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	remotefixture.Run(t, ctx, identity.RemoteTarget{ID: strings.Repeat("c", 32), Name: "Isolated SSH process", Protocol: "ssh", Target: target, Identity: host.PublicKey().Marshal()}, f, nil, string(secret), "node", nil)
	select {
	case <-f.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("account logout failed to revoke worker process")
	}
}
