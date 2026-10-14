package rdplab

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"sync"

	"github.com/denyfirst/keybash/internal/targetguard"
)

// Private single-use raw stream capability. The worker never supplies a target
// name, IP, port or new dial request. The actual TLS stays end-to-end.
type nativeBroker struct {
	mu   sync.Mutex
	used bool
	dial func(context.Context) (net.Conn, error)
}

func newNativeBroker(target *targetguard.NamedTarget, identity *Identity) (*nativeBroker, error) {
	if target == nil || identity == nil || identity.name == "" || identity.name != target.Hostname() || len(identity.der) == 0 || identity.pin == [sha256.Size]byte{} {
		return nil, errNative
	}
	return &nativeBroker{dial: target.DialContext}, nil
}

func (b *nativeBroker) serve(ctx context.Context, worker net.Conn) error {
	if worker == nil {
		return errNative
	}
	defer worker.Close()
	if b == nil || ctx == nil {
		return errNative
	}
	b.mu.Lock()
	used := b.used
	b.used = true
	b.mu.Unlock()
	if used || b.dial == nil || ctx.Err() != nil {
		return errNative
	}
	stopWorker := context.AfterFunc(ctx, func() { _ = worker.Close() })
	defer stopWorker()
	target, err := b.dial(ctx)
	if target != nil {
		defer target.Close()
	}
	if err != nil || target == nil || ctx.Err() != nil {
		return errNative
	}
	stopTarget := context.AfterFunc(ctx, func() { _ = target.Close() })
	defer stopTarget()
	done := make(chan struct{}, 2)
	copyDirection := func(dst net.Conn, src net.Conn) {
		_, _ = io.CopyBuffer(dst, io.LimitReader(src, 16*1024*1024), make([]byte, 32*1024))
		_ = dst.Close()
		_ = src.Close()
		done <- struct{}{}
	}
	go copyDirection(target, worker)
	go copyDirection(worker, target)
	<-done
	<-done
	return nil
}
