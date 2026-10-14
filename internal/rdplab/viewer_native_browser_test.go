//go:build linux && nativelab && browserlab

package rdplab

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
)

func TestNativeRDPBrowserDesktopAndRevocation(t *testing.T) {
	prefix := nativePrefix(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := labCertificate(t, nil, key)
	identity, err := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	address, authenticated := nativePeer(t, ctx, prefix, cert, "Synthetic-NLA-password")
	var revoked atomic.Bool
	factory := func(c context.Context) (terminalweb.Stream, error) {
		control, process, brokerDone := launchNativeWorker(t, c, prefix, identity, func(d context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(d, "tcp", address) })
		plan, e := newNativePlan(identity, "synthetic-user", "Synthetic-NLA-password")
		if e != nil {
			return nil, e
		}
		stream, e := nativeConnect(c, control, plan)
		if e != nil {
			return nil, e
		}
		select {
		case <-authenticated:
		case <-c.Done():
			stream.close()
			return nil, errNative
		}
		go func() {
			<-c.Done()
			select {
			case <-brokerDone:
			case <-time.After(time.Second):
				return
			}
			select {
			case <-process.done:
				revoked.Store(true)
			case <-time.After(time.Second):
			}
		}()
		return newViewerStream(stream), nil
	}
	env := []string{"PATH=/usr/bin:/bin", "LANG=C", "PLAYWRIGHT_BROWSERS_PATH=" + os.Getenv("KEYBASH_NATIVE_BROWSER_CACHE")}
	browserViewer(t, ctx, prefix+"/bin/node", factory, "", env)
	deadline := time.Now().Add(2 * time.Second)
	for !revoked.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !revoked.Load() {
		t.Fatal("browser logout did not revoke native worker/broker")
	}
}
