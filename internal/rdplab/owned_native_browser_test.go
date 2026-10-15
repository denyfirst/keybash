//go:build linux && nativelab && browserlab

package rdplab

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/remotefixture"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

type ownedNativeWorker struct {
	t               *testing.T
	prefix, address string
	marker          *nativeMarker
	closed          atomic.Bool
}

func (f *ownedNativeWorker) OpenRDP(ctx context.Context, request identity.RDPRequest) (terminalweb.Stream, error) {
	pin, e := NewIdentity(request.Target.Hostname(), request.Certificate)
	if e != nil {
		return nil, e
	}
	control, process, brokerDone := launchNativeWorker(f.t, ctx, f.prefix, pin, func(c context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(c, "tcp", f.address) })
	plan, e := newNativePlan(pin, request.Username, request.Password)
	if e != nil {
		return nil, e
	}
	stream, e := nativeConnect(ctx, control, plan)
	if e != nil {
		return nil, e
	}
	select {
	case <-f.marker.ready:
	case <-ctx.Done():
		stream.close()
		return nil, errNative
	}
	go func() {
		<-ctx.Done()
		select {
		case <-brokerDone:
		case <-time.After(time.Second):
			return
		}
		select {
		case <-process.done:
			f.closed.Store(true)
		case <-time.After(time.Second):
		}
	}()
	return newViewerStream(stream), nil
}
func TestNativeRDPOwnedIdentityVaultAndBrowser(t *testing.T) {
	prefix := nativePrefix(t)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal("fixture key failed")
	}
	cert, _ := labCertificate(t, nil, key)
	address, marker := nativePeerWithInput(t, ctx, prefix, cert, "Synthetic-owned-NLA-password")
	ip := netip.MustParseAddr("10.44.0.3")
	policy, e := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 3389)}, nil)
	if e != nil {
		t.Fatal("fixture policy failed")
	}
	target, e := targetguard.NewNamedTarget(policy, "synthetic-rdp.invalid", 3389, []netip.Addr{ip})
	if e != nil {
		t.Fatal("fixture target failed")
	}
	worker := &ownedNativeWorker{t: t, prefix: prefix, address: address, marker: marker}
	env := []string{"PATH=/usr/bin:/bin", "LANG=C", "PLAYWRIGHT_BROWSERS_PATH=" + os.Getenv("KEYBASH_NATIVE_BROWSER_CACHE")}
	remotefixture.Run(t, ctx, identity.RemoteTarget{ID: strings.Repeat("a", 32), Name: "Owned RDP", Protocol: "rdp", Target: target, Identity: cert.Certificate[0]}, nil, worker, "Synthetic-owned-NLA-password", prefix+"/bin/node", env)
	for _, received := range []<-chan struct{}{marker.keys, marker.mouse} {
		select {
		case <-received:
		default:
			t.Fatal("owned browser input did not reach native peer")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for !worker.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !worker.closed.Load() {
		t.Fatal("account logout failed to revoke native worker/broker")
	}
}
