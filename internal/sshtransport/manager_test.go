package sshtransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"github.com/denyfirst/keybash/internal/sshkey"
)

func TestSSHManagerRefusalIsNilBeforeDial(t *testing.T) {
	user := syntheticSigner(t)
	w := ManagerWorker{SocketPath: "relative/untrusted.sock"}
	called := false
	dial := func(context.Context) (net.Conn, error) { called = true; return nil, ErrProcess }
	for _, ctx := range []context.Context{nil, context.Background()} {
		stream, err := w.open(ctx, "ssh.invalid", dial, syntheticSigner(t).PublicKey().Marshal(), "lab-user", user)
		if err == nil || stream != nil || called {
			t.Fatal("manager refusal reached dial or returned typed nil")
		}
	}
	if stream, err := w.OpenSSH(context.Background(), nil, nil, "", nil); err == nil || stream != nil {
		t.Fatal("nil manager target accepted")
	}
	// A valid session key still cannot authorize a relative/missing manager.
	_, raw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("entropy failed")
	}
	key, err := sshkey.New(raw)
	if err != nil {
		t.Fatal("key fixture failed")
	}
	defer key.Close()
	stream, err := w.open(context.Background(), "ssh.invalid", dial, syntheticSigner(t).PublicKey().Marshal(), "lab-user", key)
	if err == nil || stream != nil || called {
		t.Fatal("untrusted manager path reached dial")
	}
}
