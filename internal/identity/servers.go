package identity

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/denyfirst/keybash/internal/targetguard"
	"golang.org/x/crypto/ssh"
)

var errHostKeyRead = errors.New("host key read")

// scanHostKey reads an SSH server's Ed25519 host key through the guarded
// target: the handshake offers only Ed25519 and Curve25519, proves the server
// holds the key it shows, and stops before authentication. It reads at most
// 64 KiB within 10 seconds.
func scanHostKey(ctx context.Context, target *targetguard.NamedTarget) (ssh.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, e := target.DialContext(ctx)
	if e != nil {
		return nil, errRefused
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return readHostKey(&cappedConn{Conn: conn, left: 64 << 10})
}

func readHostKey(conn net.Conn) (ssh.PublicKey, error) {
	var key ssh.PublicKey
	config := &ssh.ClientConfig{User: "keybash-host-key", HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Config:          ssh.Config{KeyExchanges: []string{ssh.KeyExchangeCurve25519}}, // its libssh.org alias comes with it
		HostKeyCallback: func(_ string, _ net.Addr, offered ssh.PublicKey) error { key = offered; return errHostKeyRead }}
	if _, _, _, e := ssh.NewClientConn(conn, "server", config); !errors.Is(e, errHostKeyRead) || key == nil || key.Type() != ssh.KeyAlgoED25519 {
		return nil, errRefused
	}
	return key, nil
}

// cappedConn ends a connection's input after a fixed number of bytes.
type cappedConn struct {
	net.Conn
	left int
}

func (c *cappedConn) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, io.EOF
	}
	n, e := c.Conn.Read(p[:min(len(p), c.left)])
	c.left -= n
	return n, e
}
