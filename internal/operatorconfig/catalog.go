// Package operatorconfig reads an offline administrator approval catalog. It
// performs no network, discovery, credential or worker operation.
package operatorconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/rdplab"
	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/targetguard"
	"golang.org/x/crypto/ssh"
)

const MaxBytes = 256 * 1024

var ErrConfiguration = errors.New("operator target configuration refused")

// Catalog carries network approvals and admission limits from one checked file.
type Catalog struct {
	Targets  []identity.RemoteTarget
	Capacity sessionlimits.Limits
}

// ParseCatalog validates bounded public metadata. Parsing untrusted bytes alone
// does not establish administrator authority: runtime callers use LoadCatalog. There
// are no credentials, environment expansion, includes, URLs or file references.
func ParseCatalog(input io.Reader) (Catalog, error) {
	var zero Catalog
	if input == nil {
		return zero, ErrConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(input, MaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) {
		return zero, ErrConfiguration
	}
	root, err := object(raw, "version", "protected_networks", "targets", "capacity")
	if err != nil || (len(root) != 3 && len(root) != 4) || string(bytes.TrimSpace(root["version"])) != "1" {
		return zero, ErrConfiguration
	}
	limits, err := parseCapacity(root["capacity"])
	if err != nil {
		return zero, ErrConfiguration
	}
	prefixes, err := array(root["protected_networks"], 64)
	if err != nil {
		return zero, ErrConfiguration
	}
	protected := make([]netip.Prefix, 0, len(prefixes))
	seenPrefixes := make(map[netip.Prefix]bool)
	for _, raw := range prefixes {
		value, err := text(raw)
		prefix, pe := netip.ParsePrefix(value)
		if err != nil || pe != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() || value != prefix.String() || seenPrefixes[prefix] {
			return zero, ErrConfiguration
		}
		seenPrefixes[prefix] = true
		protected = append(protected, prefix)
	}
	entries, err := array(root["targets"], 256)
	if err != nil {
		return zero, ErrConfiguration
	}
	targets := make([]identity.RemoteTarget, 0, len(entries))
	ids := make(map[string]bool)
	for _, raw := range entries {
		target, err := parseTarget(raw, protected)
		if err != nil || ids[target.ID] {
			return zero, ErrConfiguration
		}
		ids[target.ID] = true
		targets = append(targets, target)
	}
	return Catalog{Targets: targets, Capacity: limits}, nil
}

func parseCapacity(raw []byte) (sessionlimits.Limits, error) {
	if raw == nil {
		return sessionlimits.Default(), nil
	}
	var limits sessionlimits.Limits
	fields, err := object(raw, "total", "per_owner")
	if err != nil || len(fields) != 2 || json.Unmarshal(fields["total"], &limits.Total) != nil ||
		json.Unmarshal(fields["per_owner"], &limits.PerOwner) != nil || !limits.Valid() {
		return sessionlimits.Limits{}, ErrConfiguration
	}
	return limits, nil
}

func parseTarget(raw []byte, protected []netip.Prefix) (identity.RemoteTarget, error) {
	var zero identity.RemoteTarget
	fields, err := object(raw, "id", "name", "protocol", "hostname", "port", "addresses", "ssh_host_key", "rdp_certificate")
	if err != nil || len(fields) != 7 {
		return zero, ErrConfiguration
	}
	id, e1 := text(fields["id"])
	name, e2 := text(fields["name"])
	protocol, e3 := text(fields["protocol"])
	host, e4 := text(fields["hostname"])
	decoded, e5 := hex.DecodeString(id)
	var port uint16
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != id ||
		!validName(name) || json.Unmarshal(fields["port"], &port) != nil || port == 0 {
		return zero, ErrConfiguration
	}
	addresses, err := array(fields["addresses"], 16)
	if err != nil {
		return zero, ErrConfiguration
	}
	pins := make([]netip.Addr, 0, len(addresses))
	endpoints := make([]netip.AddrPort, 0, len(addresses))
	seen := make(map[netip.Addr]bool)
	for _, raw := range addresses {
		value, e := text(raw)
		ip, pe := netip.ParseAddr(value)
		if e != nil || pe != nil || ip.Zone() != "" || ip.Is4In6() || value != ip.String() || seen[ip] {
			return zero, ErrConfiguration
		}
		seen[ip] = true
		pins = append(pins, ip)
		endpoints = append(endpoints, netip.AddrPortFrom(ip, port))
	}
	policy, err := targetguard.New(endpoints, protected)
	if err != nil {
		return zero, ErrConfiguration
	}
	target, err := targetguard.NewNamedTarget(policy, host, port, pins)
	if err != nil {
		return zero, ErrConfiguration
	}
	var approved []byte
	switch protocol {
	case "ssh":
		value, e := text(fields["ssh_host_key"])
		if e != nil || fields["rdp_certificate"] != nil || len(value) > 256 {
			return zero, ErrConfiguration
		}
		key, comment, options, rest, e := ssh.ParseAuthorizedKey([]byte(value))
		if e != nil || key.Type() != ssh.KeyAlgoED25519 || comment != "" || len(options) != 0 || len(rest) != 0 ||
			value != strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n") {
			return zero, ErrConfiguration
		}
		approved = key.Marshal()
	case "rdp":
		value, e := text(fields["rdp_certificate"])
		if e != nil || fields["ssh_host_key"] != nil || len(value) > base64.StdEncoding.EncodedLen(32*1024) {
			return zero, ErrConfiguration
		}
		approved, e = base64.StdEncoding.Strict().DecodeString(value)
		if e != nil || base64.StdEncoding.EncodeToString(approved) != value {
			return zero, ErrConfiguration
		}
		if _, e = rdplab.NewIdentity(target.Hostname(), approved); e != nil {
			return zero, ErrConfiguration
		}
	default:
		return zero, ErrConfiguration
	}
	return identity.RemoteTarget{ID: id, Name: name, Protocol: protocol, Target: target, Identity: approved}, nil
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 160 || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func text(raw []byte) (string, error) {
	var value string
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil || strings.ContainsRune(value, utf8.RuneError) {
		return "", ErrConfiguration
	}
	return value, nil
}

func array(raw []byte, limit int) ([]json.RawMessage, error) {
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) == 0 || len(values) > limit {
		return nil, ErrConfiguration
	}
	return values, nil
}

// Decode exact case-sensitive keys, including escaped duplicates. No recursive
// object walking or unbounded schema expansion; arrays have separate limits.
func object(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrConfiguration
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		known := false
		for _, candidate := range allowed {
			known = known || key == candidate
		}
		if err != nil || !ok || !known || fields[key] != nil {
			return nil, ErrConfiguration
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrConfiguration
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrConfiguration
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrConfiguration
	}
	return fields, nil
}
