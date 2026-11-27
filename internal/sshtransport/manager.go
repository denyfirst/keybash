package sshtransport

import (
	"context"
	"errors"
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

// OpenFiles opens a Files session (ADR 0011): the same admission, pin and
// credential as a terminal, but the worker asks the server for SFTP only and
// allows only what mode says.
func (w ManagerWorker) OpenFiles(ctx context.Context, target *targetguard.NamedTarget, pin []byte, user string, auth sshkey.Credential, mode terminalweb.FilesMode) (terminalweb.FilesStream, error) {
	if target == nil || target.Hostname() == "" || !terminalweb.ValidFilesMode(mode) {
		return nil, ErrProcess
	}
	s, err := w.openKind(ctx, target.Hostname(), target.DialContext, pin, user, auth, workerKind{files: true, mode: mode})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Only _test.go callers substitute the guarded TCP dial for synthetic peers.
func (w ManagerWorker) open(ctx context.Context, host string, dial func(context.Context) (net.Conn, error), pin []byte, user string, auth sshkey.Credential) (terminalweb.Stream, error) {
	s, err := w.openKind(ctx, host, dial, pin, user, auth, workerKind{})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// openKind opens a worker for a terminal or a Files session.
func (w ManagerWorker) openKind(ctx context.Context, host string, dial func(context.Context) (net.Conn, error), pin []byte, user string, auth sshkey.Credential, session workerKind) (*processStream, error) {
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
	s, err := connectSSHManager(ctx, setup, w.SocketPath, host, dial, validated, user, method, secret, session)
	if err != nil || s == nil {
		if s != nil {
			_ = s.Close()
		}
		if errors.Is(err, ErrRefused) {
			return nil, refusedReason(method)
		}
		return nil, ErrProcess
	}
	return s, nil
}

// refusedReason is the one word the page gets when the server refused the
// account's credential: which kind it was, never the server's own text.
func refusedReason(method string) terminalweb.Reason {
	if method == methodPassword {
		return terminalweb.ReasonCredentials
	}
	return terminalweb.ReasonKey
}
