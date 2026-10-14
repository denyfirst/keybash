package rdplab

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/targetguard"
)

func TestNativeBrokerBindsIdentityToGuardedTarget(t *testing.T) {
	id := labIdentity(t)
	endpoint := netip.MustParseAddrPort("10.40.0.7:3389")
	policy, err := targetguard.New([]netip.AddrPort{endpoint}, nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := targetguard.NewNamedTarget(policy, id.name, 3389, []netip.Addr{endpoint.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newNativeBroker(target, id); err != nil {
		t.Fatal("valid bound broker refused")
	}
	other, err := targetguard.NewNamedTarget(policy, "different.invalid", 3389, []netip.Addr{endpoint.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		t *targetguard.NamedTarget
		i *Identity
	}{{nil, id}, {target, nil}, {other, id}, {target, &Identity{}}} {
		if _, err := newNativeBroker(pair.t, pair.i); err != errNative {
			t.Fatal("unbound identity accepted")
		}
	}
}

func TestNativeBrokerRawUnicodeSingleUseAndCancellation(t *testing.T) {
	worker, bridge := net.Pipe()
	target, server := net.Pipe()
	defer worker.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	broker := &nativeBroker{dial: func(context.Context) (net.Conn, error) { calls++; return target, nil }}
	done := make(chan error, 1)
	go func() { done <- broker.serve(ctx, bridge) }()
	text := []byte("opaque TLS bytes \x00 Azərbaycan 😀\r\n")
	writeDone := make(chan error, 1)
	go func() { _, err := worker.Write(text); writeDone <- err }()
	got := make([]byte, len(text))
	if _, err := io.ReadFull(server, got); err != nil || string(got) != string(text) {
		t.Fatal("broker changed bytes")
	}
	if <-writeDone != nil {
		t.Fatal("write failed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("broker cancellation blocked")
	}
	second, secondWorker := net.Pipe()
	defer second.Close()
	if broker.serve(context.Background(), secondWorker) != errNative || calls != 1 {
		t.Fatal("single-use broker dialed again")
	}
}
