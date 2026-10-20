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

func TestSSHManagerCapacityValidation(t *testing.T) {
	for _, value := range []int{0, 1, 10, 128} {
		got, valid := managerCapacity(value)
		if !valid || got < 1 || value != 0 && got != value || value == 0 && got != 8 {
			t.Fatal("valid manager capacity ignored or refused")
		}
	}
	for _, value := range []int{-1, 129} {
		if _, valid := managerCapacity(value); valid {
			t.Fatal("unbounded manager capacity accepted")
		}
	}
}

func TestSSHWorkerIdentityValidation(t *testing.T) {
	for _, pair := range [][2]uint32{{0, 0}, {65531, 65531}, {1001, 1002}, {2147483647, 2147483647}} {
		uid, gid, ok := workerIdentity(pair[0], pair[1])
		if !ok || uid == 0 || gid == 0 || pair[0] != 0 && (uid != pair[0] || gid != pair[1]) {
			t.Fatal("valid worker identity lost or refused")
		}
	}
	for _, pair := range [][2]uint32{{0, 1}, {1, 0}, {2147483648, 1}, {1, 2147483648}} {
		if _, _, ok := workerIdentity(pair[0], pair[1]); ok {
			t.Fatal("unsafe worker identity accepted")
		}
	}
}
