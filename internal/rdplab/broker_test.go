package rdplab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// A desktop's raw stream passes the former 16 MiB per-direction total intact;
// the end of one direction closes both.
func TestNativeBrokerLongStreamAndEndClosesBothDirections(t *testing.T) {
	const total = 24 * 1024 * 1024
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse_%t", reverse), func(t *testing.T) {
			worker, bridge := net.Pipe()
			target, server := net.Pipe()
			defer worker.Close()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			broker := &nativeBroker{dial: func(context.Context) (net.Conn, error) { return target, nil }}
			done := make(chan error, 1)
			go func() { done <- broker.serve(ctx, bridge) }()
			source, destination := worker, server
			if reverse {
				source, destination = server, worker
			}
			wrote := make(chan struct{})
			go func() {
				_, _ = io.Copy(source, bytes.NewReader(make([]byte, total)))
				_ = source.Close()
				close(wrote)
			}()
			count, err := io.Copy(io.Discard, destination)
			if err != nil || count != total || ctx.Err() != nil {
				t.Fatalf("broker relayed %d of %d bytes", count, total)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("ended direction leaked broker")
			}
			select {
			case <-wrote:
			case <-ctx.Done():
				t.Fatal("ended direction leaked writer")
			}
		})
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
	go func() { _, err := server.Write(text); writeDone <- err }()
	if _, err := io.ReadFull(worker, got); err != nil || string(got) != string(text) || <-writeDone != nil {
		t.Fatal("broker changed reverse bytes")
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

func TestNativeBrokerFailedAndCanceledDialsCloseOwnedConnections(t *testing.T) {
	for _, reason := range []string{"failed", "late-cancel", "already-canceled"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			worker, bridge := net.Pipe()
			target, server := net.Pipe()
			defer worker.Close()
			defer target.Close()
			defer server.Close()
			calls := 0
			broker := &nativeBroker{dial: func(context.Context) (net.Conn, error) {
				calls++
				if reason == "late-cancel" {
					cancel()
					return target, nil
				}
				return target, errors.New("private network diagnostics")
			}}
			if reason == "already-canceled" {
				cancel()
			}
			if err := broker.serve(ctx, bridge); err != errNative {
				t.Fatal("failed/canceled dial accepted or disclosed diagnostics")
			}
			if reason == "already-canceled" {
				if calls != 0 {
					t.Fatal("canceled broker dialed")
				}
			} else {
				_ = server.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				if _, err := server.Read(b[:]); err != io.EOF {
					t.Fatal("owned target leaked")
				}
			}
			var b [1]byte
			if _, err := worker.Read(b[:]); err != io.EOF {
				t.Fatal("owned worker leaked")
			}
		})
	}
}
