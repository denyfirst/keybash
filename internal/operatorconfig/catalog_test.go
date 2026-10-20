package operatorconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func fixture(t testing.TB) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	entry := map[string]any{"id": strings.Repeat("a", 32), "name": "Əsas server", "protocol": "ssh", "hostname": "ssh.invalid", "port": 22,
		"addresses": []string{"10.44.0.8"}, "ssh_host_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}
	raw, err := json.Marshal(map[string]any{"version": 1, "protected_networks": []string{"10.99.0.0/16"}, "targets": []any{entry}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestOperatorCatalogSSHAndNetworkBinding(t *testing.T) {
	raw := []byte(fixture(t))
	targets, err := Parse(bytes.NewReader(raw))
	if err != nil || len(targets) != 1 {
		t.Fatal("valid SSH catalog refused")
	}
	clear(raw)
	target := targets[0]
	if target.Name != "Əsas server" || target.Protocol != "ssh" || target.ID != strings.Repeat("a", 32) || target.Target.Hostname() != "ssh.invalid" {
		t.Fatal("catalog changed target metadata")
	}
	snapshot := target.Target.Snapshot()
	if snapshot.Port != 22 || len(snapshot.Addresses) != 1 || snapshot.Addresses[0] != "10.44.0.8" {
		t.Fatal("catalog lost network binding")
	}
	key, err := ssh.ParsePublicKey(target.Identity)
	if err != nil || key.Type() != ssh.KeyAlgoED25519 {
		t.Fatal("catalog lost public host identity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := target.Target.DialContext(ctx); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled configured target reached network")
	}
}

func TestOperatorCatalogRejectsAmbiguousAndForbidden(t *testing.T) {
	good := fixture(t)
	cases := []struct{ old, next string }{
		{`"version":1`, `"version":1,"version":1`},
		{`"version":1`, `"version":1,"ver\u0073ion":1`},
		{`"version":1`, `"Version":1`}, {`"version":1`, `"version":1.0`}, {`"version":1`, `"version":"1"`},
		{`"version":1`, `"version":1,"password":"canary-do-not-echo"`},
		{`"port":22`, `"port":22,"port":23`}, {`"port":22`, `"port":0`}, {`"port":22`, `"port":65536`},
		{`"port":22`, `"port":22.0`}, {`"port":22`, `"port":null`}, {`"port":22`, `"port":"22"`},
		{`"protocol":"ssh"`, `"protocol":"SSH"`}, {`"protocol":"ssh"`, `"protocol":"http"`},
		{`"protocol":"ssh"`, `"protocol":"ssh","rdp_certificate":"AA=="`},
		{`"hostname":"ssh.invalid"`, `"hostname":"https://ssh.invalid"`},
		{`"hostname":"ssh.invalid"`, `"hostname":"10.44.0.8"`},
		{`"hostname":"ssh.invalid"`, `"hostname":"ssh.invalid","worker":"/bin/sh"`},
		{`"name":"Əsas server"`, `"name":"\ud800"`}, {`"name":"Əsas server"`, `"name":"\u202espoof"`},
		{`"name":"Əsas server"`, `"name":" line\n"`},
		{strings.Repeat("a", 32), strings.Repeat("A", 32)},
		{`["10.99.0.0/16"]`, `[]`}, {`["10.99.0.0/16"]`, `null`},
		{`["10.99.0.0/16"]`, `["10.99.0.1/16"]`},
		{`["10.99.0.0/16"]`, `["10.99.0.0/16","10.99.0.0/16"]`},
		{`["10.44.0.8"]`, `[]`}, {`["10.44.0.8"]`, `["10.44.0.8","10.44.0.8"]`},
		{`["10.44.0.8"]`, `["10.99.0.8"]`}, {`["10.44.0.8"]`, `["127.0.0.1"]`},
		{`["10.44.0.8"]`, `["169.254.169.254"]`}, {`["10.44.0.8"]`, `["100.100.100.200"]`},
		{`["10.44.0.8"]`, `["168.63.129.16"]`}, {`["10.44.0.8"]`, `["::ffff:10.44.0.8"]`},
		{`["10.44.0.8"]`, `["64:ff9b::a2c:8"]`}, {`["10.44.0.8"]`, `["fe80::1%eth0"]`},
		{`ssh-ed25519 `, `no-port-forwarding ssh-ed25519 `},
	}
	for i, tc := range cases {
		if !strings.Contains(good, tc.old) {
			t.Fatalf("fixture replacement missing %d", i)
		}
		raw := strings.Replace(good, tc.old, tc.next, 1)
		result, err := Parse(strings.NewReader(raw))
		if err != ErrConfiguration || result != nil {
			t.Fatalf("invalid catalog accepted at case %d", i)
		}
	}
	for _, raw := range []string{"", "null", "[]", good + "{}", good + "x", strings.Repeat(" ", MaxBytes+1), strings.Replace(good, "Əsas", string([]byte{255}), 1)} {
		if targets, err := Parse(strings.NewReader(raw)); err != ErrConfiguration || targets != nil {
			t.Fatal("malformed or excess catalog accepted")
		}
	}
	if _, err := Parse(nil); err != ErrConfiguration {
		t.Fatal("nil reader accepted")
	}
}

func TestOperatorCatalogWholeSnapshotLimits(t *testing.T) {
	var root map[string]any
	if json.Unmarshal([]byte(fixture(t)), &root) != nil {
		t.Fatal("fixture decode failed")
	}
	entry := root["targets"].([]any)[0].(map[string]any)
	check := func(allowed bool) {
		t.Helper()
		raw, _ := json.Marshal(root)
		result, err := Parse(bytes.NewReader(raw))
		if allowed && (err != nil || len(result) == 0) || !allowed && (err != ErrConfiguration || result != nil) {
			t.Fatal("catalog limit or whole-snapshot refusal changed")
		}
	}
	root["targets"] = []any{entry, entry}
	check(false)
	root["targets"] = []any{entry}
	entry["addresses"] = []string{"2001:db8::8", "10.44.0.8"}
	check(true)
	addresses := make([]string, 17)
	for i := range addresses {
		addresses[i] = "10.44.0." + big.NewInt(int64(i+1)).String()
	}
	entry["addresses"] = addresses[:16]
	check(true)
	entry["addresses"] = addresses
	check(false)
	entry["addresses"] = []string{"10.44.0.8"}
	entries := make([]any, 257)
	for i := range entries {
		clone := make(map[string]any)
		for k, v := range entry {
			clone[k] = v
		}
		clone["id"] = big.NewInt(int64(i + 1)).Text(16)
		clone["id"] = strings.Repeat("0", 32-len(clone["id"].(string))) + clone["id"].(string)
		entries[i] = clone
	}
	root["targets"] = entries[:256]
	check(true)
	root["targets"] = entries
	check(false)
}

func TestOperatorCatalogSSHKeyConstraints(t *testing.T) {
	var root map[string]any
	if json.Unmarshal([]byte(fixture(t)), &root) != nil {
		t.Fatal("fixture decode failed")
	}
	entry := root["targets"].([]any)[0].(map[string]any)
	approved := entry["ssh_host_key"].(string)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", approved + " comment", approved + "\n", approved + "\n" + approved,
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other))), strings.Repeat("x", 1024), "-----BEGIN OPENSSH PRIVATE KEY-----"} {
		entry["ssh_host_key"] = value
		raw, _ := json.Marshal(root)
		if targets, err := Parse(bytes.NewReader(raw)); err != ErrConfiguration || targets != nil {
			t.Fatal("unsupported SSH host identity accepted")
		}
	}
}

func TestOperatorCatalogRDPCertificate(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	var root map[string]any
	if json.Unmarshal([]byte(fixture(t)), &root) != nil {
		t.Fatal("fixture decode failed")
	}
	entry := root["targets"].([]any)[0].(map[string]any)
	delete(entry, "ssh_host_key")
	entry["protocol"], entry["port"] = "rdp", 3389
	cert := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "synthetic"}, DNSNames: []string{"ssh.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	check := func(allowed bool) {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, private)
		if err != nil {
			t.Fatal(err)
		}
		entry["rdp_certificate"] = base64.StdEncoding.EncodeToString(der)
		raw, _ := json.Marshal(root)
		targets, err := Parse(bytes.NewReader(raw))
		if allowed {
			if err != nil || len(targets) != 1 || !bytes.Equal(targets[0].Identity, der) || targets[0].Protocol != "rdp" {
				t.Fatal("valid RDP catalog refused")
			}
		} else if err != ErrConfiguration || targets != nil {
			t.Fatal("invalid RDP certificate accepted")
		}
	}
	check(true)
	cert.NotAfter = time.Now().Add(-time.Minute)
	check(false)
	cert.NotAfter = time.Now().Add(time.Hour)
	cert.DNSNames = []string{"other.invalid"}
	check(false)
	cert.DNSNames = []string{"ssh.invalid"}
	cert.BasicConstraintsValid = true
	cert.IsCA = true
	check(false)
	cert.IsCA = false
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	check(false)
	entry["rdp_certificate"] = "not-a-certificate"
	raw, _ := json.Marshal(root)
	if targets, err := Parse(bytes.NewReader(raw)); err != ErrConfiguration || targets != nil {
		t.Fatal("invalid certificate encoding accepted")
	}
}

func FuzzOperatorCatalog(f *testing.F) {
	seed := fixture(f)
	f.Add([]byte(seed))
	f.Add([]byte(strings.Replace(seed, `"version":1`, `"version":1,"capacity":{"total":16,"per_owner":4}`, 1)))
	f.Add([]byte(`{"version":1,"protected_networks":["10.99.0.0/16"],"targets":[]}`))
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Add([]byte(`{"targets":[{"name":"\ud800"}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		catalog, err := ParseCatalog(bytes.NewReader(raw))
		if err != nil && (err != ErrConfiguration || catalog.Targets != nil || catalog.Capacity.Valid()) {
			t.Fatal("parser leaked partial authority or diagnostics")
		}
		if err == nil && (len(catalog.Targets) == 0 || len(catalog.Targets) > 256 || !catalog.Capacity.Valid()) {
			t.Fatal("parser returned invalid authority count")
		}
	})
}
