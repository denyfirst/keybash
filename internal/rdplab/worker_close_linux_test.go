//go:build linux && amd64

package rdplab

import (
	"context"
	"io"
	"os"
	"testing"
	"time"
)

// proxyPipes are a desktop's two pipes: the gateway's ends and the proxy's.
func proxyPipes(t *testing.T) (in, out, proxyIn, proxyOut *os.File) {
	t.Helper()
	proxyIn, in, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	out, proxyOut, err = os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	t.Cleanup(func() { _ = proxyIn.Close(); _ = proxyOut.Close() })
	return in, out, proxyIn, proxyOut
}

// A closed desktop's worker finishes by itself: the proxy reads the end of its
// input while the lease still stands, tells Windows the session is over and
// exits, and only then is the lease revoked. Nothing more crosses meanwhile.
func TestAClosedDesktopEndsBeforeItsLeaseIsRevoked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in, out, proxyIn, proxyOut := proxyPipes(t)
	done := make(chan struct{})
	revokedAtEnd := make(chan bool, 1)
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, proxyIn)
		revokedAtEnd <- ctx.Err() != nil
		_ = proxyOut.Close()
	}()
	c := newRDPConnection(ctx, cancel, in, out, done)
	began := time.Now()
	if c.Close() != nil {
		t.Fatal("close failed")
	}
	if <-revokedAtEnd {
		t.Fatal("the lease was revoked before the proxy read the end of its input")
	}
	if ctx.Err() == nil {
		t.Fatal("the lease outlived the closed desktop")
	}
	if took := time.Since(began); took > time.Second {
		t.Fatalf("close waited %v for a worker that had finished", took)
	}
	if _, e := c.Write([]byte{1}); e == nil {
		t.Fatal("a closed desktop took input")
	}
	if _, e := c.Read(make([]byte, 1)); e == nil {
		t.Fatal("a closed desktop gave output")
	}
}

// A worker that does not finish is revoked after goodbyeWait, and the
// manager's kill reaps it; a lease revoked from outside is not waited for.
func TestAClosedDesktopIsRevokedWithinTheGoodbyeWait(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		in, out, _, _ := proxyPipes(t)
		done := make(chan struct{})
		context.AfterFunc(ctx, func() { close(done) })
		c := newRDPConnection(ctx, cancel, in, out, done)
		if revoked {
			cancel()
		}
		began := time.Now()
		if c.Close() != nil {
			t.Fatal("close failed")
		}
		took := time.Since(began)
		switch {
		case revoked && took > 500*time.Millisecond:
			t.Fatalf("a revoked lease waited %v", took)
		case !revoked && (took < goodbyeWait || took > goodbyeWait+time.Second):
			t.Fatalf("a worker that did not finish was revoked after %v", took)
		}
		cancel()
	}
}
