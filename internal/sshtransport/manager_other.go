//go:build !linux || !amd64

package sshtransport

import (
	"context"
	"net"
)

func ServeSSHManager(context.Context, ManagerConfig) error { return ErrProcess }

func connectSSHManager(context.Context, context.Context, string, string, func(context.Context) (net.Conn, error), []byte, string, string, []byte) (*processStream, error) {
	return nil, ErrProcess
}
