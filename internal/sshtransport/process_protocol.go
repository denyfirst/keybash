package sshtransport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/denyfirst/keybash/internal/sshkey"
	"golang.org/x/crypto/ssh"
)

var ErrProcess = errors.New("SSH worker unavailable")

const (
	frameHello       byte = 1
	frameStart       byte = 2
	frameReady       byte = 3
	frameInput       byte = 4
	frameResize      byte = 5
	frameOutput      byte = 6
	frameErrorOutput byte = 7
	frameFailed      byte = 8
	// v2: the start frame carries one credential (a key or a password) rather
	// than an Ed25519 seed. A v1 peer is refused at the greeting.
	workerHello = "keybash-ssh-worker/v2"
	// Host, user and pin are small; the secret is at most sshkey.MaxMaterial.
	startFrameLimit = 12 * 1024
	methodKey       = "key"
	methodPassword  = "password"
)

func frameLimit(kind byte) int {
	switch kind {
	case frameHello:
		return len(workerHello)
	case frameStart:
		return startFrameLimit
	case frameReady, frameFailed:
		return 0
	case frameResize:
		return 8
	case frameInput:
		return MaxInputBytes
	case frameOutput, frameErrorOutput:
		return 8192
	default:
		return -1
	}
}
func readWorkerFrame(r io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, io.EOF
		}
		return 0, nil, ErrProcess
	}
	limit := frameLimit(header[0])
	size := binary.BigEndian.Uint32(header[1:])
	if limit < 0 {
		return 0, nil, ErrProcess
	}
	if size > MaxInputBytes || uint64(size) > uint64(limit) {
		return 0, nil, ErrProcess
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(r, data); err != nil {
		clear(data)
		return 0, nil, ErrProcess
	}
	return header[0], data, nil
}
func writeWorkerFrame(w io.Writer, kind byte, data []byte) error {
	length := len(data)
	if length > 32768 {
		return ErrProcess
	}
	if frameLimit(kind) < 0 || length > frameLimit(kind) {
		return ErrProcess
	}
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(length))
	if n, err := w.Write(header[:]); err != nil || n != len(header) {
		return ErrProcess
	}
	if len(data) > 0 {
		if n, err := w.Write(data); err != nil || n != len(data) {
			return ErrProcess
		}
	}
	return nil
}

type workerStart struct {
	Version    uint32
	Host, User string
	Pin        []byte
	Method     string // methodKey (PKCS#8) or methodPassword
	Secret     []byte
}

// sessionHandoff validates one session credential against the connection
// settings and encodes it for a worker's startup frame. The caller clears
// the returned secret.
func sessionHandoff(auth sshkey.Credential, user string, pin []byte) ([]byte, string, []byte, error) {
	config := Config{User: user, HostKey: pin, Columns: 100, Rows: 30}
	method := ""
	var password []byte
	switch credential := auth.(type) {
	case *sshkey.Key:
		if credential == nil {
			return nil, "", nil, ErrProcess
		}
		config.Signer, method = credential, methodKey
	case *sshkey.Password:
		if credential == nil {
			return nil, "", nil, ErrProcess
		}
		value, err := credential.Bytes()
		if err != nil {
			return nil, "", nil, ErrProcess
		}
		password, config.Password, method = value, value, methodPassword
	default:
		return nil, "", nil, ErrProcess
	}
	validated, err := validateConfig(config)
	if err != nil {
		clear(password)
		return nil, "", nil, ErrProcess
	}
	if method == methodPassword {
		return validated, method, password, nil
	}
	material, err := config.Signer.(*sshkey.Key).Material()
	if err != nil {
		return nil, "", nil, ErrProcess
	}
	return validated, method, material, nil
}

// workerConfig is the worker's side of sessionHandoff. The returned release
// drops the decoded credential once the session no longer needs it.
func workerConfig(start workerStart) (Config, func(), error) {
	config := Config{User: start.User, HostKey: append([]byte(nil), start.Pin...), Columns: 100, Rows: 30}
	if len(start.Secret) == 0 || len(start.Secret) > sshkey.MaxMaterial {
		return Config{}, nil, ErrProcess
	}
	switch start.Method {
	case methodKey:
		key, err := sshkey.FromMaterial(start.Secret)
		if err != nil {
			return Config{}, nil, ErrProcess
		}
		config.Signer = key
		return config, key.Close, nil
	case methodPassword:
		if !sshkey.ValidPassword(string(start.Secret)) {
			return Config{}, nil, ErrProcess
		}
		config.Password = append([]byte(nil), start.Secret...)
		return config, func() { clear(config.Password) }, nil
	}
	return Config{}, nil, ErrProcess
}

// serveSSHWorker is private. Its only runtime caller has already checked the
// Linux sandbox; raw is the one inherited authorized TCP descriptor. No dial.
func serveSSHWorker(ctx context.Context, input io.ReadCloser, output io.WriteCloser, raw net.Conn) error {
	defer input.Close()
	defer output.Close()
	defer raw.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = input.Close(); _ = output.Close(); _ = raw.Close() })
	defer stop()
	startup := time.AfterFunc(5*time.Second, func() { _ = input.Close() })
	kind, data, err := readWorkerFrame(input)
	startup.Stop()
	if err != nil || kind != frameStart {
		return ErrProcess
	}
	var start workerStart
	err = ssh.Unmarshal(data, &start)
	if err != nil || start.Version != 2 || len(start.Host) == 0 || len(start.Host) > 253 {
		clear(start.Secret)
		clear(data)
		return ErrProcess
	}
	config, release, err := workerConfig(start)
	clear(start.Secret)
	clear(data)
	if err != nil {
		return ErrProcess
	}
	terminal, err := connect(ctx, start.Host, func(context.Context) (net.Conn, error) { return raw, nil }, config)
	release()
	if err != nil {
		_ = writeWorkerFrame(output, frameFailed, nil)
		return ErrProcess
	}
	defer terminal.Close()
	if writeWorkerFrame(output, frameReady, nil) != nil {
		return ErrProcess
	}
	var workers, readers sync.WaitGroup
	var outMu sync.Mutex
	// Output has no lifetime total: each frame is bounded, the pipe and the
	// gateway's queues backpressure the SSH channel window, and the owner
	// session's lifetime and revocation end the process.
	readOutput := func(kind byte, source io.Reader) {
		defer readers.Done()
		buffer := make([]byte, 8192)
		for {
			n, e := source.Read(buffer)
			if n > 0 {
				outMu.Lock()
				e = writeWorkerFrame(output, kind, buffer[:n])
				outMu.Unlock()
				if e != nil {
					cancel()
					return
				}
			}
			if e != nil {
				if !errors.Is(e, io.EOF) {
					cancel()
				}
				return
			}
		}
	}
	readers.Add(2)
	workers.Go(func() { readOutput(frameOutput, terminal) })
	workers.Go(func() { readOutput(frameErrorOutput, terminal.channel.Stderr()) })
	workers.Go(func() { readers.Wait(); cancel() })
	workers.Go(func() {
		defer cancel()
		for {
			kind, data, err := readWorkerFrame(input)
			if err != nil {
				return
			}
			switch kind {
			case frameInput:
				_, err = terminal.Write(data)
			case frameResize:
				if len(data) != 8 {
					return
				}
				err = terminal.Resize(binary.BigEndian.Uint32(data), binary.BigEndian.Uint32(data[4:]))
			default:
				return
			}
			clear(data)
			if err != nil {
				return
			}
		}
	})
	<-ctx.Done()
	_ = terminal.Close()
	_ = input.Close()
	_ = output.Close()
	workers.Wait()
	return nil
}
