package sshtransport

import (
	"context"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

// Worker is the stock guarded/pinned SSH adapter for the identity gateway.
// This library adapter is not yet a separate OS sandbox/process launcher.
type Worker struct{}

func (Worker) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, pin []byte, user string, signer ssh.Signer) (terminalweb.Stream, error) {
	return Connect(ctx, target, Config{User: user, HostKey: pin, Signer: signer, Columns: 100, Rows: 30})
}
