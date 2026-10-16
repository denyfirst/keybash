package sshtransport

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

// ProcessWorker is a Linux/amd64 privileged laboratory manager, NOT a public
// root gateway or installed service. Binary/hash come from trusted operator
// configuration. Other systems, missing sandbox tools and arbitrary signers
// refuse. The existing custody-only CLI does not enable this launcher.
type ProcessWorker struct {
	Path   string
	Digest [sha256.Size]byte
}

func (w ProcessWorker) OpenSSH(ctx context.Context, target *targetguard.NamedTarget, pin []byte, user string, signer ssh.Signer) (terminalweb.Stream, error) {
	if target == nil || target.Hostname() == "" {
		return nil, ErrProcess
	}
	return w.open(ctx, target.Hostname(), target.DialContext, pin, user, signer)
}

// The private dial seam permits synthetic TCP fixtures only in _test.go.
func (w ProcessWorker) open(ctx context.Context, host string, dial func(context.Context) (net.Conn, error), pin []byte, user string, signer ssh.Signer) (terminalweb.Stream, error) {
	key, ok := signer.(*sshkey.Key)
	if ctx == nil || ctx.Err() != nil || !ok || key == nil || dial == nil {
		return nil, ErrProcess
	}
	validated, err := validateConfig(Config{User: user, HostKey: pin, Signer: key, Columns: 100, Rows: 30})
	if err != nil {
		return nil, ErrProcess
	}
	pin = validated
	seed, err := key.Seed()
	if err != nil {
		return nil, ErrProcess
	}
	defer clear(seed)
	setup, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	stream, err := launchSSHProcess(ctx, setup, w, host, dial, pin, user, seed)
	if err != nil || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		return nil, ErrProcess
	}
	return stream, nil
}

type processStream struct {
	ctx            context.Context
	cancel         context.CancelFunc
	in, out        *os.File
	done           <-chan struct{}
	writeMu        sync.Mutex
	stdout, stderr processOutput
}
type processOutput struct {
	mu    sync.Mutex
	queue chan []byte
	rest  []byte
	ctx   context.Context
}

func (s *processStream) Read(p []byte) (int, error)       { return s.stdout.read(p) }
func (s *processStream) ReadStderr(p []byte) (int, error) { return s.stderr.read(p) }
func (o *processOutput) read(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if o.ctx.Err() != nil {
		o.rest = nil
		return 0, io.EOF
	}
	if len(o.rest) == 0 {
		select {
		case <-o.ctx.Done():
			return 0, io.EOF
		case data, ok := <-o.queue:
			if !ok || o.ctx.Err() != nil {
				return 0, io.EOF
			}
			o.rest = data
		}
	}
	n := copy(p, o.rest)
	o.rest = o.rest[n:]
	return n, nil
}
func (s *processStream) send(kind byte, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.ctx.Err() != nil || s.in.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
		return ErrProcess
	}
	if err := writeWorkerFrame(s.in, kind, data); err != nil {
		s.cancel()
		return ErrProcess
	}
	return nil
}
func (s *processStream) Write(p []byte) (int, error) {
	if len(p) > MaxInputBytes {
		return 0, ErrInvalidInput
	}
	if s.send(frameInput, p) != nil {
		return 0, ErrProcess
	}
	return len(p), nil
}
func (s *processStream) Resize(columns, rows uint32) error {
	if !validSize(columns, rows) {
		return ErrInvalidInput
	}
	var data [8]byte
	binary.BigEndian.PutUint32(data[:], columns)
	binary.BigEndian.PutUint32(data[4:], rows)
	return s.send(frameResize, data[:])
}
func (s *processStream) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	select {
	case <-s.done:
		return nil
	case <-time.After(2 * time.Second):
		return ErrProcess
	}
}
func (s *processStream) demux() {
	defer close(s.stdout.queue)
	defer close(s.stderr.queue)
	total := 0
	for {
		kind, data, err := readWorkerFrame(s.out)
		if errors.Is(err, io.EOF) {
			_ = s.in.Close()
			_ = s.out.Close()
			return // clean EOF drains output; explicit revocation drops queues.
		}
		if err != nil || len(data) == 0 || len(data) > workerOutputLimit-total {
			s.cancel()
			return
		}
		total += len(data)
		queue := s.stdout.queue
		if kind == frameErrorOutput {
			queue = s.stderr.queue
		} else if kind != frameOutput {
			s.cancel()
			return
		}
		select {
		case queue <- data:
		case <-s.ctx.Done():
			return
		}
	}
}
