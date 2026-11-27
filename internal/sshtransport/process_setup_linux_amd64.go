//go:build linux && amd64

package sshtransport

import (
	"context"
	"os"
	"time"

	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

func newProcessStream(ctx context.Context, cancel context.CancelFunc, in, out *os.File, done <-chan struct{}) *processStream {
	s := &processStream{ctx: ctx, cancel: cancel, in: in, out: out, done: done}
	s.stdout = processOutput{ctx: ctx, queue: make(chan []byte, 2)}
	s.stderr = processOutput{ctx: ctx, queue: make(chan []byte, 2)}
	s.replies = make(chan terminalweb.FileReply, 2)
	context.AfterFunc(ctx, func() { _ = in.Close(); _ = out.Close() })
	return s
}

func finishProcessSetup(s *processStream, setup context.Context, host string, pin []byte, user, method string, secret []byte, session workerKind) error {
	stopSetup := context.AfterFunc(setup, s.cancel)
	defer stopSetup()
	deadline, _ := setup.Deadline()
	if s.out.SetReadDeadline(deadline) != nil || s.in.SetWriteDeadline(deadline) != nil {
		return ErrProcess
	}
	kind, hello, err := readWorkerFrame(s.out)
	if err != nil || kind != frameHello || string(hello) != workerHello {
		return ErrProcess
	}
	kindWord, modeWord := session.wire()
	start := ssh.Marshal(&workerStart{Version: workerVersion, Host: host, User: user, Pin: pin, Method: method, Secret: secret, Kind: kindWord, Mode: modeWord})
	err = writeWorkerFrame(s.in, frameStart, start)
	clear(start)
	if err != nil {
		return ErrProcess
	}
	kind, data, err := readWorkerFrame(s.out)
	if err == nil && kind == frameRefused && len(data) == 0 && setup.Err() == nil && s.ctx.Err() == nil {
		return ErrRefused
	}
	if err != nil || kind != frameReady || len(data) != 0 || setup.Err() != nil || s.ctx.Err() != nil {
		return ErrProcess
	}
	if !stopSetup() || s.out.SetReadDeadline(time.Time{}) != nil || s.in.SetWriteDeadline(time.Time{}) != nil {
		return ErrProcess
	}
	if session.files {
		go s.filesDemux()
	} else {
		go s.demux()
	}
	return nil
}
