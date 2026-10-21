//go:build browserlab

package rdplab

import (
	"context"
	"encoding/base64"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"strconv"
	"testing"
	"time"
)

func TestBrowserRDPWorkspacePortable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	pasted := make(chan string, 1)
	factory := func(c context.Context) (terminalweb.Stream, error) {
		s, remote, input := viewerFixture(t)
		s.workspace = true
		s.native.workspace = true
		// Recreate the initial capability notification, which is gateway-owned.
		s.ready.Reset(encodedInstruction(t, instruction{"keybash", "1", "text", "display-update"}))
		go func() { <-c.Done(); _ = s.Close() }()
		go func() {
			for _, in := range []instruction{{"size", "0", "1024", "768"}, {"rect", "0", "0", "0", "1024", "768"}, {"cfill", "14", "0", "160", "160", "160", "255"}, {"clipboard", "8", "text/plain"}, {"blob", "8", base64.StdEncoding.EncodeToString([]byte("Remote Azərbaycan 🔑 <img src=x onerror=alert(1)>"))}, {"end", "8"}, {"sync", "123", "1"}} {
				if writeInstruction(remote, in) != nil {
					return
				}
			}
		}()
		go func() {
			var clip clipboard
			sequence := 124
			for in := range input {
				switch in[0] {
				case "clipboard", "blob", "end":
					text, complete, e := clip.accept(in)
					if e == nil && complete {
						pasted <- text
					}
				case "size":
					_ = writeInstruction(remote, instruction{"size", "0", in[1], in[2]})
					_ = writeInstruction(remote, instruction{"sync", strconv.Itoa(sequence), "1"})
					sequence++
				}
			}
		}()
		return s, nil
	}
	browserViewer(t, ctx, "node", factory, "", nil, true)
	select {
	case text := <-pasted:
		if text != "Local Azərbaycan 🔑\nline" {
			t.Fatal("browser paste bytes changed")
		}
	default:
		t.Fatal("browser failed to paste")
	}
}
