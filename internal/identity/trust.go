package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Version 2 binds identity approval to the complete immutable network target.
// Changing only a port/IP set must invalidate a lease granted before it too.
func approvalFingerprint(t RemoteTarget) string {
	network, _ := json.Marshal(t.Target.Snapshot())
	data := append([]byte("keybash/approval/v2/"+t.ID+"/"+t.Protocol+"/"), network...)
	data = append(data, 0)
	digest := sha256.Sum256(append(data, t.Identity...))
	return hex.EncodeToString(digest[:])
}

func identityFingerprint(t RemoteTarget) string {
	digest := sha256.Sum256(t.Identity)
	if t.Protocol == "ssh" {
		return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	}
	if t.Protocol == "rdp" {
		return "SHA256:" + hex.EncodeToString(digest[:])
	}
	return ""
}

func validFingerprint(value string) bool {
	raw, ok := strings.CutPrefix(value, "SHA256:")
	if !ok {
		return false
	}
	if len(raw) == 43 {
		b, e := base64.RawStdEncoding.DecodeString(raw)
		return e == nil && len(b) == 32 && base64.RawStdEncoding.EncodeToString(b) == raw
	}
	if len(raw) == 64 {
		b, e := hex.DecodeString(raw)
		return e == nil && len(b) == 32 && hex.EncodeToString(b) == raw
	}
	return false
}

func usableTarget(t RemoteTarget, now time.Time) bool {
	if t.Target == nil || t.ID == "" || len(t.Identity) == 0 {
		return false
	}
	if t.Protocol == "ssh" {
		return true
	} // constructor admits only copied Ed25519 keys.
	if t.Protocol != "rdp" {
		return false
	}
	cert, e := x509.ParseCertificate(t.Identity)
	return e == nil && !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
}

// UsableAt reports whether the target's approved identity can authorize a
// connection at now. An RDP certificate outside its validity period cannot;
// the target still loads and shows as unavailable.
func (t RemoteTarget) UsableAt(now time.Time) bool { return usableTarget(t, now) }
