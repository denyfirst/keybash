//go:build linux

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/keybash/internal/identity"
)

func TestOperatorLinuxInitBootstrapAndOfflineRecovery(t *testing.T) {
	base := t.TempDir()
	data, keys := filepath.Join(base, "data"), filepath.Join(base, "keys")
	for _, dir := range []string{data, keys} {
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("fixture mkdir failed")
		}
	}
	key := filepath.Join(keys, "instance.key")
	args := []string{"--data", data, "--key-file", key}
	var output bytes.Buffer
	call := func(command string, input string, extra ...string) error {
		return run(append(append([]string{command}, args...), extra...), strings.NewReader(input), &output)
	}
	if call("init", "") != nil {
		t.Fatal("valid private Linux init refused")
	}
	code := strings.TrimSpace(output.String())
	if len(code) != 43 {
		t.Fatal("bootstrap code missing")
	}
	output.Reset()
	if call("bootstrap-renew", "") != nil || strings.TrimSpace(output.String()) == code {
		t.Fatal("offline bootstrap renewal failed")
	}
	code = strings.TrimSpace(output.String())
	output.Reset()
	store, e := identity.OpenFiles(data, key)
	if e != nil {
		t.Fatal("initialized store refused")
	}
	lab, e := identity.NewPersistent("https://127.0.0.1:8443", store)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	password := "Synthetic operator fixture password 68!"
	body, _ := json.Marshal(map[string]string{"code": code, "username": "alice", "password": password})
	r := httptest.NewRequest("POST", "https://127.0.0.1:8443/api/bootstrap", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.RemoteAddr = "127.0.0.1:7890"
	r.Header.Set("Origin", "https://127.0.0.1:8443")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Keybash-Request", "1")
	w := httptest.NewRecorder()
	lab.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal("operator-to-browser bootstrap refused")
	}
	_ = lab.Close()
	_ = store.Close()
	if call("bootstrap-renew", "") == nil {
		t.Fatal("operator reopened registration")
	}
	if call("account-add", "bob\n"+password+"\n") != nil {
		t.Fatal("operator account add refused")
	}
	if call("account-add", "bob\n"+password+"\n") == nil {
		t.Fatal("duplicate account accepted")
	}
	if call("account-recover", "alice\nSynthetic replacement fixture 83!\n", "--lost-mfa") != nil {
		t.Fatal("operator recovery refused")
	}
	if output.Len() != 0 {
		t.Fatal("operator leaked account or secret")
	}
	if call("serve-lab", "", "--listen", "0.0.0.0:8443") == nil {
		t.Fatal("public listener accepted")
	}
}
