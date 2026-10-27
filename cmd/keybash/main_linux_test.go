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
	// Each operation that leaves an account without a factor prints exactly one
	// fresh one-time setup code, and never the account name or password.
	setupCode := func(what string) string {
		t.Helper()
		printed := output.String()
		output.Reset()
		code := strings.TrimSuffix(printed, "\n")
		if len(code) != 43 || strings.ContainsAny(code, "\n ") || strings.Contains(printed, password) || strings.Contains(printed, "bob") {
			t.Fatalf("%s printed something other than one setup code", what)
		}
		return code
	}
	if call("account-add", "bob\n"+password+"\n") != nil {
		t.Fatal("operator account add refused")
	}
	added := setupCode("account add")
	if call("account-add", "bob\n"+password+"\n") == nil || output.Len() != 0 {
		t.Fatal("duplicate account accepted or printed a code")
	}
	if call("account-recover", "alice\nSynthetic replacement fixture 83!\n", "--lost-mfa") != nil {
		t.Fatal("operator recovery refused")
	}
	if recovered := setupCode("lost-factor recovery"); recovered == added {
		t.Fatal("setup codes were reused")
	}
	if call("serve-lab", "", "--listen", "0.0.0.0:8443") == nil {
		t.Fatal("public listener accepted")
	}
}

// A whole recovery on a clean host: the backup file and the instance key's
// recovery code are all that move; every account must enroll MFA again.
func TestOperatorLinuxBackupKeyRecoveryAndRestore(t *testing.T) {
	base := t.TempDir()
	dirs := map[string]string{}
	for _, name := range []string{"data", "keys", "offsite", "data2", "keys2", "data3", "keys3", "data4"} {
		dirs[name] = filepath.Join(base, name)
		if os.Mkdir(dirs[name], 0700) != nil {
			t.Fatal("fixture mkdir failed")
		}
	}
	key, key2, key3 := filepath.Join(dirs["keys"], "instance.key"), filepath.Join(dirs["keys2"], "instance.key"), filepath.Join(dirs["keys3"], "instance.key")
	call := func(command, input string, extra ...string) (string, error) {
		var output bytes.Buffer
		e := run(append([]string{command}, extra...), strings.NewReader(input), &output)
		return output.String(), e
	}
	at := func(data, key string, extra ...string) []string {
		return append([]string{"--data", data, "--key-file", key}, extra...)
	}
	code, e := call("init", "", at(dirs["data"], key)...)
	if e != nil {
		t.Fatal("valid private Linux init refused")
	}
	store, e := identity.OpenFiles(dirs["data"], key)
	if e != nil {
		t.Fatal("initialized store refused")
	}
	lab, e := identity.NewPersistent("https://127.0.0.1:8443", store)
	if e != nil {
		t.Fatal("persistent lab refused")
	}
	password := "Synthetic operator fixture password 68!"
	body, _ := json.Marshal(map[string]string{"code": strings.TrimSpace(code), "username": "alice", "password": password})
	r := httptest.NewRequest("POST", "https://127.0.0.1:8443/api/bootstrap", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.RemoteAddr = "127.0.0.1:7890"
	r.Header.Set("Origin", "https://127.0.0.1:8443")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Keybash-Request", "1")
	w := httptest.NewRecorder()
	lab.ServeHTTP(w, r)
	_ = lab.Close()
	_ = store.Close()
	if w.Code != 204 {
		t.Fatal("operator-to-browser bootstrap refused")
	}
	if _, e := call("account-add", "bob\n"+password+"\n", at(dirs["data"], key)...); e != nil {
		t.Fatal("operator account add refused")
	}

	recovery, e := call("key-export", "", at(dirs["data"], key)...)
	recovery = strings.TrimSpace(recovery)
	if e != nil || !strings.HasPrefix(recovery, "KB1-") || len(recovery) != 73 {
		t.Fatal("instance key recovery code missing")
	}
	beside := filepath.Join(dirs["keys"], "custody.backup")
	if _, e := call("backup", "", at(dirs["data"], key, "--out", beside)...); e == nil {
		t.Fatal("backup written beside its key")
	}
	if _, e := os.Lstat(beside); !os.IsNotExist(e) {
		t.Fatal("refused backup left a file beside the key")
	}
	if _, e := call("backup", "", at(dirs["data"], key)...); e == nil {
		t.Fatal("backup without an output file accepted")
	}
	backup := filepath.Join(dirs["offsite"], "custody.backup")
	printed, e := call("backup", "", at(dirs["data"], key, "--out", backup)...)
	if e != nil || !strings.Contains(printed, "2 accounts, 0 credentials, 0 connections") || strings.Contains(printed, recovery) {
		t.Fatal("valid backup refused or misreported")
	}
	if info, e := os.Stat(backup); e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup file is not private")
	}
	raw, _ := os.ReadFile(backup)
	keyBytes, _ := os.ReadFile(key)
	if bytes.Contains(raw, []byte("alice")) || bytes.Contains(raw, keyBytes) {
		t.Fatal("backup carries a name or the key in plaintext")
	}
	if _, e := call("backup", "", at(dirs["data"], key, "--out", backup)...); e == nil {
		t.Fatal("existing backup replaced")
	}

	// The clean host: a mistyped code writes nothing; the right one, in any case.
	mistyped := []byte(recovery)
	mistyped[10] = map[bool]byte{true: 'B', false: 'A'}[mistyped[10] == 'A']
	if _, e := call("key-import", string(mistyped), at(dirs["data2"], key2)...); e == nil {
		t.Fatal("mistyped recovery code imported")
	}
	if _, e := os.Lstat(key2); !os.IsNotExist(e) {
		t.Fatal("refused import wrote a key")
	}
	if _, e := call("key-import", strings.ToLower(recovery)+"\n", at(dirs["data2"], key2)...); e != nil {
		t.Fatal("valid recovery code refused")
	}
	if restoredKey, e := os.ReadFile(key2); e != nil || !bytes.Equal(restoredKey, keyBytes) {
		t.Fatal("imported key differs from the original")
	}
	if _, e := call("key-import", recovery, at(dirs["data2"], key2)...); e == nil {
		t.Fatal("existing key replaced")
	}
	if _, e := call("restore", "", at(dirs["data2"], key2, "--out", backup)...); e == nil {
		t.Fatal("restore accepted an output flag")
	}
	printed, e = call("restore", "", at(dirs["data2"], key2, "--in", backup)...)
	lines := strings.Split(strings.TrimSuffix(printed, "\n"), "\n")
	if e != nil || len(lines) != 4 || !strings.Contains(lines[0], "2 accounts") || !strings.HasPrefix(lines[2], "alice\t") || !strings.HasPrefix(lines[3], "bob\t") || len(lines[2]) != len("alice\t")+43 || strings.Contains(printed, password) {
		t.Fatalf("restore refused or printed %d lines", len(lines))
	}
	restored, e := identity.OpenFiles(dirs["data2"], key2)
	if e != nil {
		t.Fatal("restored store does not open")
	}
	_ = restored.Close()
	if _, e := call("restore", "", at(dirs["data2"], key2, "--in", backup)...); e == nil {
		t.Fatal("restore replaced an existing database")
	}
	// Another instance's key opens nothing and leaves nothing behind.
	if _, e := call("init", "", at(dirs["data3"], key3)...); e != nil {
		t.Fatal("second init refused")
	}
	if _, e := call("restore", "", at(dirs["data4"], key3, "--in", backup)...); e == nil {
		t.Fatal("backup restored with another instance's key")
	}
	if left, e := os.ReadDir(dirs["data4"]); e != nil || len(left) != 0 {
		t.Fatal("refused restore left files behind")
	}
}
