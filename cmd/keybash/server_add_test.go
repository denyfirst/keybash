package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/denyfirst/keybash/internal/operatorconfig"
	"golang.org/x/crypto/ssh"
)

func serverAddKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("key")
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal("signer")
	}
	return signer, signer.PublicKey()
}

func serverAddCatalog(t *testing.T) []byte {
	t.Helper()
	_, key := serverAddKey(t)
	raw, err := json.Marshal(map[string]any{"version": 1, "protected_networks": []string{"10.99.0.0/16"}, "targets": []any{map[string]any{
		"id": strings.Repeat("a", 32), "name": "Əsas server", "protocol": "ssh", "hostname": "10.44.0.8", "port": 22,
		"ssh_host_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}}})
	if err != nil {
		t.Fatal("catalog")
	}
	if _, err := operatorconfig.ParseCatalog(bytes.NewReader(raw)); err != nil {
		t.Fatal("fixture catalog refused")
	}
	return raw
}

// sshListener answers SSH with the given host keys and counts any attempt to
// authenticate, which the probe must never make.
func sshListener(t *testing.T, keys ...ssh.Signer) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	var attempts atomic.Int32
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			attempts.Add(1)
			return nil, errors.New("no")
		},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			attempts.Add(1)
			return nil, errors.New("no")
		},
	}
	for _, key := range keys {
		config.AddHostKey(key)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen")
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _, _, _, _ = ssh.NewServerConn(conn, config); _ = conn.Close() }()
		}
	}()
	return netip.MustParseAddrPort(listener.Addr().String()), &attempts
}

func TestServerAddReadsOnlyTheEd25519HostKey(t *testing.T) {
	signer, want := serverAddKey(t)
	address, attempts := sshListener(t, signer)
	got, err := probeHostKey(context.Background(), address)
	if err != nil || !bytes.Equal(got.Marshal(), want.Marshal()) {
		t.Fatal("probe did not return the server's ed25519 host key")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("rsa")
	}
	rsaSigner, _ := ssh.NewSignerFromKey(rsaKey)
	rsaOnly, _ := sshListener(t, rsaSigner)
	if _, err := probeHostKey(context.Background(), rsaOnly); err == nil {
		t.Fatal("a server without an ed25519 host key was accepted")
	}
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen")
	}
	go func() {
		conn, e := plain.Accept()
		if e == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 400 nope\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	defer func() { _ = plain.Close() }()
	if _, err := probeHostKey(context.Background(), netip.MustParseAddrPort(plain.Addr().String())); err == nil {
		t.Fatal("a non-SSH listener produced a host key")
	}
	if attempts.Load() != 0 {
		t.Fatal("the probe tried to authenticate")
	}
}

func TestServerAddBuildsOnlyALoadableCatalog(t *testing.T) {
	raw := serverAddCatalog(t)
	_, key := serverAddKey(t)
	id := strings.Repeat("b", 32)
	next, err := withServer(raw, id, "Veb server", netip.MustParseAddrPort("10.44.0.9:2222"), key)
	if err != nil {
		t.Fatal("valid server refused")
	}
	catalog, err := operatorconfig.ParseCatalog(bytes.NewReader(next))
	if err != nil || len(catalog.Targets) != 2 || catalog.Targets[1].ID != id || catalog.Targets[1].Name != "Veb server" || catalog.Targets[0].ID != strings.Repeat("a", 32) {
		t.Fatal("new catalog does not hold the old target and the new one")
	}
	var root struct {
		Protected []string `json:"protected_networks"`
	}
	if json.Unmarshal(next, &root) != nil || len(root.Protected) != 1 || root.Protected[0] != "10.99.0.0/16" {
		t.Fatal("protected networks changed")
	}
	for _, bad := range []struct {
		name    string
		address string
	}{
		{"Veb server", "10.44.0.8:22"},   // already there
		{"Veb server", "10.99.1.2:22"},   // protected network
		{"Veb server", "127.0.0.1:22"},   // loopback
		{"Veb server", "169.254.1.1:22"}, // link-local
		{"", "10.44.0.9:22"},             // no name
		{"line\nbreak", "10.44.0.9:22"},  // control character
	} {
		if _, err := withServer(raw, id, bad.name, netip.MustParseAddrPort(bad.address), key); err == nil {
			t.Fatalf("unsafe server accepted: %q %s", bad.name, bad.address)
		}
	}
	if _, err := withServer(raw, strings.Repeat("a", 32), "Veb server", netip.MustParseAddrPort("10.44.0.9:22"), key); err == nil {
		t.Fatal("a repeated ID was accepted")
	}
}

func TestServerAddChangesNothingUntilConfirmed(t *testing.T) {
	raw := serverAddCatalog(t)
	signer, key := serverAddKey(t)
	_ = signer
	print := ssh.FingerprintSHA256(key)
	type outcome struct {
		probed, replaced bool
		previous, next   []byte
	}
	attempt := func(host string, port int, expected, answer string) (outcome, string, error) {
		var o outcome
		var out bytes.Buffer
		err := serverAdd(context.Background(), "/etc/keybash/targets.json", "Veb server", host, port, expected, strings.NewReader(answer), &out,
			func(string) ([]byte, error) { return raw, nil },
			func(context.Context, netip.AddrPort) (ssh.PublicKey, error) { o.probed = true; return key, nil },
			func(_ string, previous, next []byte) error {
				o.replaced, o.previous, o.next = true, previous, next
				return nil
			})
		return o, out.String(), err
	}
	o, out, err := attempt("10.44.0.9", 22, "", "yes\n")
	if err != nil || !o.replaced || !bytes.Equal(o.previous, raw) || !strings.Contains(out, print) || !strings.Contains(out, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub") {
		t.Fatal("confirmed server was not added with its fingerprint shown")
	}
	if c, e := operatorconfig.ParseCatalog(bytes.NewReader(o.next)); e != nil || len(c.Targets) != 2 {
		t.Fatal("written catalog does not load")
	}
	if o, _, err = attempt("10.44.0.9", 22, print, ""); err != nil || !o.replaced {
		t.Fatal("matching compared fingerprint refused")
	}
	if o, _, err = attempt("10.44.0.9", 2222, "", "yes\n"); err != nil || !o.replaced {
		t.Fatal("a server on another port was refused")
	}
	for _, answer := range []string{"", "no\n", "y\n", "YES\n", "yes please\n"} {
		if o, _, err = attempt("10.44.0.9", 22, "", answer); err == nil || o.replaced {
			t.Fatalf("answer %q changed the catalog", answer)
		}
	}
	if o, _, err = attempt("10.44.0.9", 22, "SHA256:"+strings.Repeat("A", 43), ""); err == nil || o.replaced {
		t.Fatal("a different compared fingerprint changed the catalog")
	}
	for _, input := range []struct {
		host string
		port int
	}{{"10.99.0.5", 22}, {"127.0.0.1", 22}, {"ssh.example", 22}, {"10.44.0.9 ", 22}, {"010.44.0.9", 22}, {"10.44.0.9", 0}, {"10.44.0.9", 65536}, {"10.44.0.8", 22}} {
		if o, _, err = attempt(input.host, input.port, "", "yes\n"); err == nil || o.probed || o.replaced {
			t.Fatalf("%s:%d was probed or added", input.host, input.port)
		}
	}
}

func TestServerAddFlagsBelongToServerAdd(t *testing.T) {
	for _, args := range [][]string{
		{"check-targets", "--config=/etc/keybash/targets.json", "--name=x"},
		{"check-targets", "--config=/etc/keybash/targets.json", "--host=10.0.0.1"},
		{"check-targets", "--config=/etc/keybash/targets.json", "--port=2222"},
		{"init", "--data=/x", "--key-file=/y", "--fingerprint=SHA256:x"},
		{"server-add", "--config=/etc/keybash/targets.json", "--name=x"},             // no host
		{"server-add", "--config=/etc/keybash/targets.json", "--host=10.0.0.1"},      // no name
		{"server-add", "--name=x", "--host=10.0.0.1"},                                // no catalog
		{"server-add", "--config=/x", "--name=x", "--host=10.0.0.1", "--data=/data"}, // a foreign flag
	} {
		if run(args, strings.NewReader("yes\n"), &bytes.Buffer{}) == nil {
			t.Fatalf("%v was accepted", args)
		}
	}
}
