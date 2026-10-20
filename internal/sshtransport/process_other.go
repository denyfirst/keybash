//go:build !linux || !amd64

package sshtransport

import (
	"context"
	"io"
	"net"
)

func launchSSHProcess(context.Context, context.Context, ProcessWorker, string, func(context.Context) (net.Conn, error), []byte, string, []byte) (*processStream, error) {
	return nil, ErrProcess
}
func RunProcessWorker(string, uint32, uint32, io.ReadCloser, io.WriteCloser) error { return ErrProcess }
