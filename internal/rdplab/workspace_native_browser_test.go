//go:build linux && nativelab && browserlab

package rdplab

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"net"
	"os"
	"testing"
	"time"
)

func TestNativeRDPWorkspaceClipboardAndDisplay(t *testing.T) {
	prefix := nativePrefix(t)
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	cert, _ := labCertificate(t, nil, key)
	pin, e := NewIdentity("synthetic-rdp.invalid", cert.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	address, marker := nativePeerWithInput(t, ctx, prefix, cert, "Synthetic-workspace-NLA-password")
	factory := func(c context.Context) (terminalweb.Stream, error) {
		control, _, _ := launchNativeWorker(t, c, prefix, pin, func(d context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(d, "tcp", address) })
		plan, e := newNativePlan(pin, "synthetic-user", "Synthetic-workspace-NLA-password")
		if e != nil {
			return nil, e
		}
		plan.workspace = true
		stream, e := nativeConnect(c, control, plan)
		if e != nil {
			return nil, e
		}
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("fixed native viewer classification: %s", stream.failure)
			}
		})
		select {
		case <-marker.ready:
		case <-c.Done():
			stream.close()
			return nil, errNative
		}
		return newViewerStream(stream), nil
	}
	env := []string{"PATH=/usr/bin:/bin", "LANG=C", "PLAYWRIGHT_BROWSERS_PATH=" + os.Getenv("KEYBASH_NATIVE_BROWSER_CACHE")}
	browserViewer(t, ctx, prefix+"/bin/node", factory, "", env, true)
	for _, received := range []<-chan struct{}{marker.clipboard, marker.resized} {
		select {
		case <-received:
		default:
			t.Fatal("actual native clipboard or display-control evidence missing")
		}
	}
	t.Log("Actual native CLIPRDR Unicode in both directions and DISPLAYCONTROL resize reached the browser")
}
