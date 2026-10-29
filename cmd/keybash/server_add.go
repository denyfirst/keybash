package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/denyfirst/keybash/internal/operatorconfig"
	"golang.org/x/crypto/ssh"
)

// server-add puts one SSH server, addressed by IP, into the root-owned
// operator catalog, so nobody writes its JSON or copies a host key by hand.
// It reads the server's Ed25519 host key itself, shows the fingerprint and
// changes nothing until the operator confirms it, by typing "yes" after
// comparing it on the server, or by passing the fingerprint they compared.
// The new catalog must load as the services load it before it replaces the
// old one; the services read it when they start.

var errHostKeyRead = errors.New("host key read")

// probeHostKey runs an SSH handshake only as far as the server's host key,
// offering ssh-ed25519 alone (the one kind the catalog pins), then hangs up.
// No user authentication is attempted.
func probeHostKey(ctx context.Context, address netip.AddrPort) (ssh.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	var key ssh.PublicKey
	config := &ssh.ClientConfig{User: "keybash-host-key", HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		HostKeyCallback: func(_ string, _ net.Addr, offered ssh.PublicKey) error { key = offered; return errHostKeyRead }}
	if _, _, _, err = ssh.NewClientConn(conn, address.String(), config); !errors.Is(err, errHostKeyRead) || key == nil || key.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("no ed25519 host key")
	}
	return key, nil
}

// withServer returns the catalog with one more SSH target. Only the targets
// list changes; the result must load as a catalog with that one target more,
// and no existing target may already be this address and port.
func withServer(raw []byte, id, name string, address netip.AddrPort, key ssh.PublicKey) ([]byte, error) {
	before, err := operatorconfig.ParseCatalog(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	for _, target := range before.Targets {
		snapshot := target.Target.Snapshot()
		for _, existing := range snapshot.Addresses {
			if existing == address.Addr().String() && snapshot.Port == address.Port() {
				return nil, errors.New("this server is already in the catalog")
			}
		}
	}
	var root map[string]json.RawMessage
	var targets []json.RawMessage
	if json.Unmarshal(raw, &root) != nil || json.Unmarshal(root["targets"], &targets) != nil {
		return nil, operatorconfig.ErrConfiguration
	}
	entry, err := json.Marshal(map[string]any{"id": id, "name": name, "protocol": "ssh", "hostname": address.Addr().String(),
		"port": address.Port(), "ssh_host_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))})
	if err != nil {
		return nil, err
	}
	if root["targets"], err = json.Marshal(append(targets, entry)); err != nil {
		return nil, err
	}
	next, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	next = append(next, '\n')
	after, err := operatorconfig.ParseCatalog(bytes.NewReader(next))
	if err != nil || len(after.Targets) != len(before.Targets)+1 || after.Targets[len(after.Targets)-1].ID != id {
		return nil, operatorconfig.ErrConfiguration
	}
	return next, nil
}

// serverAdd checks name and address against the catalog with a stand-in
// key before any network contact, so a protected or malformed address is
// refused without being probed; then reads the real key and asks.
func serverAdd(ctx context.Context, path, name, host string, port int, expected string, input io.Reader, output io.Writer,
	load func(string) ([]byte, error), probe func(context.Context, netip.AddrPort) (ssh.PublicKey, error), replace func(string, []byte, []byte) error) error {
	addr, err := netip.ParseAddr(host)
	if err != nil || port < 1 || port > 65535 || addr.String() != host || expected != "" && !strings.HasPrefix(expected, "SHA256:") {
		return operatorconfig.ErrConfiguration
	}
	address := netip.AddrPortFrom(addr, uint16(port))
	raw, err := load(path)
	if err != nil {
		return err
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return err
	}
	standIn, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	placeholder, err := ssh.NewPublicKey(standIn)
	if err != nil {
		return err
	}
	if _, err = withServer(raw, hex.EncodeToString(id[:]), name, address, placeholder); err != nil {
		return err
	}
	key, err := probe(ctx, address)
	if err != nil {
		return err
	}
	next, err := withServer(raw, hex.EncodeToString(id[:]), name, address, key)
	if err != nil {
		return err
	}
	fingerprint := ssh.FingerprintSHA256(key)
	if _, err = fmt.Fprintf(output, "Server:   %s\nAddress:  %s\nHost key: %s\n\nCompare it on the server's own console:\n  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub\n\n", name, address, fingerprint); err != nil {
		return err
	}
	if expected != "" {
		if expected != fingerprint {
			_, _ = fmt.Fprintln(output, "The fingerprint you compared is different. Nothing was changed.")
			return operatorconfig.ErrConfiguration
		}
	} else {
		if _, err = fmt.Fprint(output, "Type yes if it is the same: "); err != nil {
			return err
		}
		line, _ := bufio.NewReader(io.LimitReader(input, 64)).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			_, _ = fmt.Fprintln(output, "Not confirmed. Nothing was changed.")
			return operatorconfig.ErrConfiguration
		}
	}
	if err = replace(path, raw, next); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Added. Restart Keybash so it reads the new list (open sessions close):\n  systemctl restart keybash-ssh-manager keybash-gateway\n")
	return err
}
