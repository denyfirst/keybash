package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/targetguard"
)

// Version 2 binds identity approval to the complete immutable network target.
// Changing only a port/IP set must invalidate a saved connection too.
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

func acceptTargetProof(t RemoteTarget, fingerprint, approval string, now time.Time) bool {
	return usableTarget(t, now) && validFingerprint(fingerprint) && fingerprint == identityFingerprint(t) && approval == approvalFingerprint(t)
}

func connectionTrusted(c connection, t RemoteTarget, now time.Time) bool {
	return c.Target == t.ID && acceptTargetProof(t, c.Fingerprint, c.Approval, now)
}

type targetView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	targetguard.Snapshot
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	Approval    string `json:"approval"`
	Available   bool   `json:"available"`
}

func describeTarget(t RemoteTarget, now time.Time) targetView {
	algorithm := "ssh-ed25519"
	if t.Protocol == "rdp" {
		algorithm = "TLS leaf certificate · SHA-256 DER"
	}
	return targetView{t.ID, t.Name, t.Protocol, t.Target.Snapshot(), algorithm, identityFingerprint(t), approvalFingerprint(t), usableTarget(t, now)}
}

type connectionView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Target      string `json:"target"`
	Credential  string `json:"credential"`
	Fingerprint string `json:"fingerprint"`
	Revision    string `json:"revision"`
	Trust       string `json:"trust"`
}

func describeConnection(c connection, t RemoteTarget, now time.Time) connectionView {
	state := "changed"
	if !usableTarget(t, now) {
		state = "unavailable"
	} else if c.Fingerprint == "" {
		state = "unverified"
	} else if connectionTrusted(c, t, now) {
		state = "verified"
	}
	return connectionView{c.ID, c.Name, c.Target, c.Credential, c.Fingerprint, strconv.FormatUint(c.Revision, 10), state}
}
