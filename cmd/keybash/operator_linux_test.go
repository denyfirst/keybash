//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh"
)

// Runs the actual CLI with a separate UID. There is no fixture dial override or
// remote credential: this measures provisioning -> MFA -> configured metadata,
// TLS/Host/ownership boundaries and SIGTERM, not an actual target connection.
func TestOperatorCatalogCLIUnprivilegedTLS(t *testing.T) {
	binary := os.Getenv("KEYBASH_OPERATOR_BINARY")
	if os.Geteuid() != 0 || binary == "" {
		t.Skip("required root/compiled-CLI execution is in operator-config-lab.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	base := t.TempDir()
	for _, path := range []string{base, filepath.Dir(base)} {
		if os.Chmod(path, 0755) != nil {
			t.Fatal("fixture parent failed")
		}
	}
	data, keyDir := filepath.Join(base, "data"), filepath.Join(base, "keys")
	for _, path := range []string{data, keyDir} {
		if os.Mkdir(path, 0700) != nil || os.Chown(path, 65533, 65533) != nil {
			t.Fatal("fixture private path failed")
		}
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ssh.NewPublicKey(pub)
	catalog, _ := json.Marshal(map[string]any{"version": 1, "capacity": map[string]int{"total": 16, "per_owner": 4}, "protected_networks": []string{"10.99.0.0/16"}, "targets": []any{
		map[string]any{"id": strings.Repeat("a", 32), "name": "Operator fixture", "protocol": "ssh", "hostname": "ssh.invalid", "port": 22,
			"addresses": []string{"10.44.0.8"}, "ssh_host_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}}})
	config := filepath.Join(base, "targets.json")
	if os.WriteFile(config, catalog, 0644) != nil { // #nosec G306 -- public root-owned fixture catalog, not credentials.
		t.Fatal("fixture catalog failed")
	}
	var check bytes.Buffer
	if run([]string{"check-targets", "--config", config}, nil, &check) != nil || check.String() != "Target configuration valid (1 servers; capacity 16 total, 4 per owner).\n" {
		t.Fatal("valid offline CLI catalog refused")
	}
	keyFile := filepath.Join(keyDir, "instance.key")
	common := []string{"--data", data, "--key-file", keyFile}
	command := func(args ...string) *exec.Cmd {
		t.Helper()
		c := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- fixed compiled test CLI supplied only by the root CI script.
		c.Env = []string{}
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 65533}}
		return c
	}
	initArgs := append([]string{"init"}, common...)
	raw, err := command(initArgs...).Output()
	if err != nil || len(strings.TrimSpace(string(raw))) != 43 {
		t.Fatal("unprivileged CLI initialization failed")
	}
	code := strings.TrimSpace(string(raw))
	cert := &x509.Certificate{SerialNumber: big.NewInt(19), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPath, tlsKey := filepath.Join(base, "tls.pem"), filepath.Join(base, "tls-key.pem")
	if os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644) != nil || // #nosec G306 -- public fixture certificate.
		os.WriteFile(tlsKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600) != nil || os.Chown(tlsKey, 65533, 65533) != nil {
		t.Fatal("fixture TLS files failed")
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	_ = reservation.Close()
	args := append([]string{"serve-ssh-lab"}, common...)
	args = append(args, "--config", config, "--ssh-manager", filepath.Join(base, "manager.sock"), "--listen", address, "--tls-cert", certPath, "--tls-key", tlsKey)
	check.Reset()
	if run(args, nil, &check) == nil || check.Len() != 0 {
		t.Fatal("root remote gateway accepted")
	}
	child := command(args...)
	var diagnostics bytes.Buffer
	child.Stdout, child.Stderr = &diagnostics, &diagnostics
	if child.Start() != nil {
		t.Fatal("fixture CLI start failed")
	}
	wait := make(chan error, 1)
	go func() { wait <- child.Wait() }()
	defer func() { _ = child.Process.Kill() }()
	certParsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(certParsed)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second}
	origin := "https://" + address
	ready := false
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get(origin + "/api/setup")
		if err == nil {
			_ = response.Body.Close()
			ready = response.StatusCode == 200
			break
		}
		select {
		case <-wait:
			t.Fatal("unprivileged configured CLI exited before readiness")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("unprivileged configured CLI failed readiness")
	}
	csrf := ""
	call := func(method, path string, body any, status int) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		request, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Keybash-Request", "1")
		request.Header.Set("X-Keybash-CSRF", csrf)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("configured CLI HTTP failed")
		}
		defer response.Body.Close()
		raw, err = io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(raw) > 16384 || response.StatusCode != status {
			t.Fatalf("configured CLI %s %s got %d, want %d", method, path, response.StatusCode, status)
		}
		return raw
	}
	call("GET", "/api/targets", nil, 401)
	call("GET", "/api/remote/capacity", nil, 401)
	call("POST", "/api/bootstrap", map[string]string{"code": code, "username": "alice", "password": "Synthetic operator integration password 86!"}, 204)
	var session struct{ CSRF string }
	if json.Unmarshal(call("GET", "/api/session", nil, 200), &session) != nil || session.CSRF == "" {
		t.Fatal("configured CLI session proof missing")
	}
	csrf = session.CSRF
	call("GET", "/api/targets", nil, 403)
	call("GET", "/api/remote/capacity", nil, 403)
	var seed struct{ Secret string }
	if json.Unmarshal(call("POST", "/api/mfa/enrollment", map[string]string{}, 200), &seed) != nil {
		t.Fatal("fixture factor failed")
	}
	otp, err := totp.GenerateCode(seed.Secret, time.Now())
	if err != nil {
		t.Fatal("fixture factor generation failed")
	}
	call("POST", "/api/mfa/confirm", map[string]string{"code": otp}, 200)
	var capacity struct {
		Total    int
		PerOwner int `json:"per_owner"`
	}
	if json.Unmarshal(call("GET", "/api/remote/capacity", nil, 200), &capacity) != nil || capacity.Total != 16 || capacity.PerOwner != 4 {
		t.Fatal("configured CLI capacity ignored")
	}
	var targets []struct{ ID, Name, Protocol string }
	if json.Unmarshal(call("GET", "/api/targets", nil, 200), &targets) != nil || len(targets) != 1 || targets[0].ID != strings.Repeat("a", 32) || targets[0].Protocol != "ssh" {
		t.Fatal("configured CLI catalog missing after MFA")
	}
	var detail struct {
		Hostname  string
		Port      int
		Addresses []string
	}
	if json.Unmarshal(call("GET", "/api/targets/"+targets[0].ID, nil, 200), &detail) != nil || detail.Hostname != "ssh.invalid" || detail.Port != 22 || len(detail.Addresses) != 1 || detail.Addresses[0] != "10.44.0.8" {
		t.Fatal("configured CLI network binding changed")
	}
	if child.Process.Signal(syscall.SIGTERM) != nil {
		t.Fatal("fixture shutdown signal failed")
	}
	select {
	case err := <-wait:
		if err != nil || diagnostics.Len() != 0 {
			t.Fatal("configured CLI SIGTERM failed or logged sensitive state")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("configured CLI SIGTERM did not exit")
	}
}
