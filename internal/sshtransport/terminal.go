// Package sshtransport opens a single authenticated remote SSH PTY. It does
// not open a host-local shell or expose forwarding, exec, or agent APIs.
package sshtransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"golang.org/x/crypto/ssh"
)

var (
	ErrInvalidConfig = errors.New("invalid SSH configuration")
	ErrHostKey       = errors.New("SSH server identity rejected")
	ErrUnavailable   = errors.New("SSH connection unavailable")
	ErrSession       = errors.New("SSH session unavailable")
	ErrInvalidInput  = errors.New("invalid terminal input")
)

const (
	MaxInputBytes = 32 * 1024
	MaxColumns    = 500
	MaxRows       = 200
)

// Config is trusted configuration, not an unchecked browser request. HostKey
// is an independently approved Ed25519 SSH wire-format public key, never TOFU.
// Exactly one credential authenticates: Signer (Ed25519, ECDSA or RSA of at
// least 2048 bits signing only with SHA-2) or Password, both from the
// authorized credential provider, never the host's SSH agent. Neither is
// offered before the host key is verified, and there is no fallback between
// them.
type Config struct {
	User     string
	HostKey  []byte
	Signer   ssh.Signer
	Password []byte
	Columns  uint32
	Rows     uint32
}

// Terminal owns one SSH connection and one remote PTY. Read and ReadStderr
// must be consumed by its owner; SSH channel windows provide backpressure.
// Close is idempotent and context cancellation closes the entire connection.
type Terminal struct {
	client  *ssh.Client
	channel ssh.Channel
	closed  chan struct{}
	once    sync.Once
}

// Connect uses only the guarded target's connection. The parent context is the
// session lifetime, not just setup: cancel it to stop the active remote channel.
func Connect(ctx context.Context, target *targetguard.NamedTarget, config Config) (*Terminal, error) {
	if target == nil || target.Hostname() == "" {
		return nil, ErrInvalidConfig
	}
	return connect(ctx, target.Hostname(), target.DialContext, config)
}

// connect's dial seam is package-private and used only by synthetic tests.
func connect(ctx context.Context, identity string, dial func(context.Context) (net.Conn, error), config Config) (*Terminal, error) {
	pin, err := validateConfig(config)
	if err != nil || ctx == nil || dial == nil || identity == "" {
		return nil, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := dial(setup)
	if err != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, setupError(setup, err)
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = raw.Close()
		}
	}()
	stopSetup := context.AfterFunc(setup, func() { _ = raw.Close() })
	defer stopSetup()
	deadline, _ := setup.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, setupError(setup, err)
	}
	var verified, used atomic.Bool
	algorithms := ssh.SupportedAlgorithms()
	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM, ssh.HMACSHA256, ssh.HMACSHA512},
		},
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(pin, key.Marshal()) {
				return ErrHostKey
			}
			verified.Store(true)
			return nil
		},
		Auth: authMethods(config, &verified, &used),
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, identity, sshConfig)
	if err != nil {
		return nil, setupError(setup, err)
	}
	// x/crypto attempts "none" first. Do not open a PTY on a server that
	// reports authentication success without using the configured credential.
	if !used.Load() {
		_ = conn.Close()
		return nil, ErrUnavailable
	}
	client := ssh.NewClient(conn, channels, requests)
	channel, channelRequests, err := client.OpenChannel("session", nil)
	if err != nil {
		_ = client.Close()
		return nil, setupError(setup, err)
	}
	terminal := &Terminal{client: client, channel: channel, closed: make(chan struct{})}
	ready := false
	defer func() {
		if !ready {
			_ = terminal.Close()
		}
	}()
	go terminal.handleRequests(channelRequests)
	pty := struct {
		Term                         string
		Columns, Rows, Width, Height uint32
		Modes                        string
	}{"xterm-256color", config.Columns, config.Rows, 0, 0, "\x00"}
	if ok, err := channel.SendRequest("pty-req", true, ssh.Marshal(pty)); err != nil || !ok {
		return nil, setupError(setup, err)
	}
	if ok, err := channel.SendRequest("shell", true, nil); err != nil || !ok {
		return nil, setupError(setup, err)
	}
	if !stopSetup() {
		return nil, setupError(setup, nil)
	}
	if err := setup.Err(); err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// One bounded watcher per terminal; no persistent AfterFunc closure after
	// owner/remote close. The setup deadline does not kill an active session.
	go func() {
		select {
		case <-ctx.Done():
			_ = terminal.Close()
		case <-terminal.closed:
		}
	}()
	ready, transferred = true, true
	return terminal, nil
}

func validateConfig(config Config) ([]byte, error) {
	if len(config.User) == 0 || len(config.User) > 128 || len(config.HostKey) == 0 || len(config.HostKey) > 256 || (config.Signer == nil) == (len(config.Password) == 0) || !validSize(config.Columns, config.Rows) {
		return nil, ErrInvalidConfig
	}
	for _, c := range []byte(config.User) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '@') {
			return nil, ErrInvalidConfig
		}
	}
	key, err := ssh.ParsePublicKey(config.HostKey)
	if err != nil || key.Type() != ssh.KeyAlgoED25519 {
		return nil, ErrInvalidConfig
	}
	if config.Signer != nil {
		// RSA needs a signer that can be held to SHA-2; a plain Sign would
		// produce SHA-1 "ssh-rsa" signatures.
		_, algorithmCapable := config.Signer.(ssh.AlgorithmSigner)
		if !sshkey.Allowed(config.Signer.PublicKey()) || config.Signer.PublicKey().Type() == ssh.KeyAlgoRSA && !algorithmCapable {
			return nil, ErrInvalidConfig
		}
	} else if !sshkey.ValidPassword(string(config.Password)) {
		return nil, ErrInvalidConfig
	}
	return append([]byte(nil), key.Marshal()...), nil
}

// authMethods offers the one configured credential, and only after the host
// key has been verified against its pin.
func authMethods(config Config, verified, used *atomic.Bool) []ssh.AuthMethod {
	if config.Signer != nil {
		base := &verifiedSigner{Signer: config.Signer, verified: verified, signed: used}
		if inner, ok := config.Signer.(ssh.AlgorithmSigner); ok {
			return []ssh.AuthMethod{ssh.PublicKeys(&verifiedAlgorithmSigner{verifiedSigner: base, inner: inner, algorithms: sshkey.AlgorithmsFor(config.Signer.PublicKey())})}
		}
		return []ssh.AuthMethod{ssh.PublicKeys(base)}
	}
	password := string(config.Password)
	return []ssh.AuthMethod{ssh.PasswordCallback(passwordAnswer(password, verified, used)), ssh.KeyboardInteractive(promptAnswer(password, verified, used))}
}

func passwordAnswer(password string, verified, used *atomic.Bool) func() (string, error) {
	return func() (string, error) {
		if !verified.Load() {
			return "", ErrHostKey
		}
		used.Store(true)
		return password, nil
	}
}

// PAM servers ask for a password through keyboard-interactive. Only a single
// hidden prompt is answered with it; anything else (a visible prompt, a
// second question such as a one-time code) refuses rather than guessing.
func promptAnswer(password string, verified, used *atomic.Bool) ssh.KeyboardInteractiveChallenge {
	return func(_, _ string, questions []string, echos []bool) ([]string, error) {
		if !verified.Load() {
			return nil, ErrHostKey
		}
		if len(questions) == 0 {
			return []string{}, nil
		}
		if len(questions) != 1 || len(echos) != 1 || echos[0] {
			return nil, ErrUnavailable
		}
		used.Store(true)
		return []string{password}, nil
	}
}

type verifiedSigner struct {
	ssh.Signer
	verified, signed *atomic.Bool
}

func (s *verifiedSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	if !s.verified.Load() {
		return nil, ErrHostKey
	}
	signature, err := s.Signer.Sign(random, data)
	if err == nil {
		s.signed.Store(true)
	}
	return signature, err
}

// verifiedAlgorithmSigner keeps a key to its allowed algorithms, so the client
// negotiates SHA-2 for RSA and never falls back to a weaker default.
type verifiedAlgorithmSigner struct {
	*verifiedSigner
	inner      ssh.AlgorithmSigner
	algorithms []string
}

func (s *verifiedAlgorithmSigner) Algorithms() []string { return slices.Clone(s.algorithms) }
func (s *verifiedAlgorithmSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(random, data, s.algorithms[0])
}
func (s *verifiedAlgorithmSigner) SignWithAlgorithm(random io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if !s.verified.Load() {
		return nil, ErrHostKey
	}
	if !slices.Contains(s.algorithms, algorithm) {
		return nil, ErrInvalidConfig
	}
	signature, err := s.inner.SignWithAlgorithm(random, data, algorithm)
	if err == nil {
		s.signed.Store(true)
	}
	return signature, err
}

func setupError(ctx context.Context, err error) error {
	if cancelErr := ctx.Err(); cancelErr != nil {
		return cancelErr
	}
	// A transport deadline may fire before the context timer goroutine is
	// scheduled. Preserve timeout semantics even while ctx.Err is still nil.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, ErrHostKey) {
		return ErrHostKey
	}
	return ErrUnavailable
}

func (t *Terminal) handleRequests(requests <-chan *ssh.Request) {
	for request := range requests {
		// No terminal title, signal diagnostic or server-controlled request is
		// reflected into application logs/UI. Exit metadata is not interpreted.
		if request.WantReply {
			_ = request.Reply(false, nil)
		}
	}
	_ = t.Close()
}

func (t *Terminal) Read(buffer []byte) (int, error) {
	if t == nil || t.channel == nil {
		return 0, io.EOF
	}
	n, err := t.channel.Read(buffer)
	return n, terminalError(err)
}

func (t *Terminal) ReadStderr(buffer []byte) (int, error) {
	if t == nil || t.channel == nil {
		return 0, io.EOF
	}
	n, err := t.channel.Stderr().Read(buffer)
	return n, terminalError(err)
}

// Write forwards exact input bytes: no local interpretation or appended Enter.
func (t *Terminal) Write(input []byte) (int, error) {
	if len(input) > MaxInputBytes {
		return 0, ErrInvalidInput
	}
	if t == nil || t.channel == nil {
		return 0, ErrSession
	}
	n, err := t.channel.Write(input)
	return n, terminalError(err)
}

// Resize sends only the bounded remote window-change request. SSH does not
// acknowledge window-change, so success is delivery, not proof of applied size.
func (t *Terminal) Resize(columns, rows uint32) error {
	if !validSize(columns, rows) {
		return ErrInvalidInput
	}
	if t == nil || t.channel == nil {
		return ErrSession
	}
	size := struct{ Columns, Rows, Width, Height uint32 }{columns, rows, 0, 0}
	_, err := t.channel.SendRequest("window-change", false, ssh.Marshal(size))
	return terminalError(err)
}

func (t *Terminal) Close() error {
	if t != nil && t.client != nil {
		t.once.Do(func() {
			close(t.closed)
			_ = t.client.Close()
		})
	}
	return nil
}

func validSize(columns, rows uint32) bool {
	return columns > 0 && columns <= MaxColumns && rows > 0 && rows <= MaxRows
}

func terminalError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	return ErrSession
}
