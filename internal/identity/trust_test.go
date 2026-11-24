package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/targetguard"
	"golang.org/x/crypto/ssh"
)

func networkFixture(t *testing.T, host string, port uint16, addresses ...string) *targetguard.NamedTarget {
	t.Helper()
	ips := make([]netip.Addr, len(addresses))
	endpoints := make([]netip.AddrPort, len(addresses))
	for i, s := range addresses {
		ips[i] = netip.MustParseAddr(s)
		endpoints[i] = netip.AddrPortFrom(ips[i], port)
	}
	policy, e := targetguard.New(endpoints, nil)
	if e != nil {
		t.Fatal("network fixture refused")
	}
	target, e := targetguard.NewNamedTarget(policy, host, port, ips)
	if e != nil {
		t.Fatal("named fixture refused")
	}
	return target
}

func TestServerTrustFingerprintFormatsAndNetworkBinding(t *testing.T) {
	target := remoteTargetFixture(t)
	sum := sha256.Sum256(target.Identity)
	if identityFingerprint(target) != "SHA256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("RDP fingerprint differs from certificate DER digest")
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("entropy failed")
	}
	signer, e := ssh.NewSignerFromKey(private)
	if e != nil {
		t.Fatal("signer failed")
	}
	sshTarget := target
	sshTarget.Protocol = "ssh"
	sshTarget.Identity = signer.PublicKey().Marshal()
	if identityFingerprint(sshTarget) != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal("SSH fingerprint differs from OpenSSH format")
	}
	for _, good := range []string{identityFingerprint(target), identityFingerprint(sshTarget)} {
		if !validFingerprint(good) {
			t.Fatal("valid fingerprint refused")
		}
	}
	for _, bad := range []string{"", "SHA256:", strings.ToLower(identityFingerprint(sshTarget)), identityFingerprint(sshTarget) + "=", identityFingerprint(target) + " ", "SHA256:" + strings.Repeat("!", 43), "SHA256:" + strings.Repeat("A", 64)} {
		if validFingerprint(bad) {
			t.Fatal("malformed fingerprint accepted")
		}
	}
	base := target
	base.Target = networkFixture(t, "rdp.invalid", 3389, "10.34.0.8", "10.34.0.9")
	ordered := base
	ordered.Target = networkFixture(t, "RDP.Invalid.", 3389, "10.34.0.9", "10.34.0.8")
	if approvalFingerprint(base) != approvalFingerprint(ordered) {
		t.Fatal("equivalent network snapshot lost approval")
	}
	for _, change := range []struct {
		host string
		port uint16
		ips  []string
	}{{"other.invalid", 3389, []string{"10.34.0.8", "10.34.0.9"}}, {"rdp.invalid", 3390, []string{"10.34.0.8", "10.34.0.9"}}, {"rdp.invalid", 3389, []string{"10.34.0.8"}}, {"rdp.invalid", 3389, []string{"10.34.0.10", "10.34.0.9"}}} {
		changed := base
		changed.Target = networkFixture(t, change.host, change.port, change.ips...)
		if approvalFingerprint(base) == approvalFingerprint(changed) {
			t.Fatal("network change retained server approval")
		}
	}
}

// A server with no target, ID or identity is never usable.
func TestServerTrustNeedsAWholeTarget(t *testing.T) {
	target := remoteTargetFixture(t)
	for name, broken := range map[string]RemoteTarget{"no target": {ID: target.ID, Protocol: "rdp", Identity: target.Identity}, "no ID": {Protocol: "rdp", Target: target.Target, Identity: target.Identity},
		"no identity": {ID: target.ID, Protocol: "rdp", Target: target.Target}, "another protocol": {ID: target.ID, Protocol: "vnc", Target: target.Target, Identity: target.Identity}, "nothing": {}} {
		if usableTarget(broken, time.Now()) {
			t.Fatalf("a server with %s is usable", name)
		}
	}
	if !usableTarget(target, time.Now()) {
		t.Fatal("a whole server is not usable")
	}
}
