//go:build browserlab

package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserDurableCustody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	store, _, _, code := custodyFixture(t)
	server := httptest.NewUnstartedServer(nil)
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.IdleTimeout = 10 * time.Second
	server.Config.MaxHeaderBytes = 8192
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	origin := "https://" + server.Listener.Addr().String()
	control, e := token()
	if e != nil {
		t.Fatal("fixture entropy failed")
	}
	var now atomic.Int64
	now.Store(time.Now().Unix())
	var mu sync.Mutex
	newLab := func() *Lab {
		l, e := NewPersistent(origin, store)
		if e != nil {
			t.Fatal("persistent browser fixture refused")
		}
		l.mu.Lock()
		l.now = func() time.Time { return time.Unix(now.Load(), 0) }
		l.mu.Unlock()
		return l
	}
	lab := newLab()
	defer func() { mu.Lock(); defer mu.Unlock(); _ = lab.Close() }()
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authenticated synthetic fixture controls exist only in this test file.
		// No runtime endpoint can advance time or restart the application.
		if r.URL.Path == "/__fixture/tick" || r.URL.Path == "/__fixture/restart" {
			if r.Method != "POST" || r.Header.Get("X-Fixture-Control") != control {
				w.WriteHeader(403)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if r.URL.Path == "/__fixture/tick" {
				now.Add(61)
			} else {
				_ = lab.Close()
				lab = newLab()
			}
			jsonReply(w, struct{ Unix int64 }{now.Load()})
			return
		}
		mu.Lock()
		current := lab
		mu.Unlock()
		current.ServeHTTP(w, r)
	})
	server.StartTLS()
	defer server.Close()
	data, _ := json.Marshal(struct {
		Origin, Code, Username, Password, Control, Screenshot string
		Unix                                                  int64
	}{server.URL, code, "alice", alicePassword, control, os.Getenv("KEYBASH_CUSTODY_SCREENSHOT"), now.Load()})
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "custody-browser-test.mjs")) // #nosec G204 -- fixed synthetic browser fixture, configuration via stdin only.
	command.Stdin = bytes.NewReader(data)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("browser durable custody checks failed")
	}
}
