package sshtransport

import (
	"context"

	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// Worker is the stock guarded/pinned SSH adapter for the identity gateway.
// This library adapter is not yet a separate OS sandbox/process launcher.
type Worker struct{}

func (Worker) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, pin []byte, user string, auth sshkey.Credential) (terminalweb.Stream, error) {
	config := Config{User: user, HostKey: pin, Columns: 100, Rows: 30}
	switch credential := auth.(type) {
	case *sshkey.Key:
		if credential == nil {
			return nil, ErrInvalidConfig
		}
		config.Signer = credential
	case *sshkey.Password:
		if credential == nil {
			return nil, ErrInvalidConfig
		}
		password, err := credential.Bytes()
		if err != nil {
			return nil, ErrInvalidConfig
		}
		defer clear(password)
		config.Password = password
	default:
		return nil, ErrInvalidConfig
	}
	return Connect(ctx, target, config)
}
