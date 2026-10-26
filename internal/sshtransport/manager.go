package sshtransport

import (
	"context"
	"net"
	"time"

	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// ManagerConfig is local administrator configuration. It is never accepted
// from the browser or sent by ManagerWorker. Only Linux/amd64 is supported.
type ManagerConfig struct {
	SocketPath             string
	Worker                 ProcessWorker
	GatewayUID, GatewayGID uint32
	MaxSessions            int // zero selects the legacy default; never unlimited
}

const managerSlots = sessionlimits.DefaultTotal

func managerCapacity(value int) (int, bool) {
	if value == 0 {
		value = managerSlots
	}
	return value, value >= 1 && value <= sessionlimits.MaxTotal
}

// ManagerWorker uses a separate privileged launcher. The gateway remains an
// unprivileged process and retains all target/owner/credential authorization.
type ManagerWorker struct{ SocketPath string }

func (w ManagerWorker) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, pin []byte, user string, auth sshkey.Credential) (terminalweb.Stream, error) {
	if target == nil || target.Hostname() == "" {
		return nil, ErrProcess
	}
	return w.open(ctx, target.Hostname(), target.DialContext, pin, user, auth)
}

// Only _test.go callers substitute the guarded TCP dial for synthetic peers.
func (w ManagerWorker) open(ctx context.Context, host string, dial func(context.Context) (net.Conn, error), pin []byte, user string, auth sshkey.Credential) (terminalweb.Stream, error) {
	if ctx == nil || ctx.Err() != nil || dial == nil {
		return nil, ErrProcess
	}
	validated, method, secret, err := sessionHandoff(auth, user, pin)
	if err != nil {
		return nil, ErrProcess
	}
	defer clear(secret)
	setup, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	s, err := connectSSHManager(ctx, setup, w.SocketPath, host, dial, validated, user, method, secret)
	if err != nil || s == nil {
		if s != nil {
			_ = s.Close()
		}
		return nil, ErrProcess
	}
	return s, nil
}
