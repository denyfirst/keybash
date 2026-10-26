package sshtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sshkey"
	"golang.org/x/crypto/ssh"
)

func syntheticSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

type signCounter struct {
	ssh.Signer
	calls atomic.Int32
}

func (s *signCounter) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	s.calls.Add(1)
	return s.Signer.Sign(random, data)
}

type requestEvent struct {
	kind      string
	payload   []byte
	wantReply bool
}

type fixtureOptions struct {
	host, user                    ssh.Signer
	noAuth, rejectAuth, rejectPTY bool
	rejectShell                   bool
	legacyKEX                     bool
	openUnsolicited               string
	shellFixture                  func(ssh.Channel)
	resizeFixture                 func([]byte)
	// password enables password authentication, or with prompts set,
	// keyboard-interactive with those prompts (echo per prompt).
	password     string
	prompts      []string
	echos        []bool
	userKeyAlgos []string // the server's accepted public key signature algorithms
}

type sshFixture struct {
	client      net.Conn
	events      chan requestEvent
	session     chan ssh.Channel
	unsolicited chan error
	auth        atomic.Int32
}

// Only the synthetic fixture listens: loopback, an OS-selected ephemeral port,
// fresh in-memory keys, and no external destination or local shell process.
func newFixture(t *testing.T, options fixtureOptions) *sshFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	_ = listener.Close()
	fixture := &sshFixture{client: client, events: make(chan requestEvent, 16), session: make(chan ssh.Channel, 1), unsolicited: make(chan error, 1)}
	var group sync.WaitGroup
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		group.Wait()
	})
	group.Go(func() {
		config := &ssh.ServerConfig{
			NoClientAuth:            options.noAuth,
			MaxAuthTries:            2,
			PublicKeyAuthAlgorithms: options.userKeyAlgos,
			PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				fixture.auth.Add(1)
				if options.rejectAuth || options.user == nil || !bytes.Equal(key.Marshal(), options.user.PublicKey().Marshal()) {
					return nil, errors.New("synthetic private authentication diagnostic")
				}
				return nil, nil
			},
		}
		if options.password != "" && options.prompts == nil {
			config.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				fixture.auth.Add(1)
				if options.rejectAuth || string(password) != options.password {
					return nil, errors.New("synthetic private authentication diagnostic")
				}
				return nil, nil
			}
		}
		if options.password != "" && options.prompts != nil {
			config.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				fixture.auth.Add(1)
				answers, err := client("", "", options.prompts, options.echos)
				if err != nil || len(answers) != 1 || answers[0] != options.password {
					return nil, errors.New("synthetic private authentication diagnostic")
				}
				return nil, nil
			}
		}
		config.AddHostKey(options.host)
		if options.legacyKEX {
			config.KeyExchanges = []string{ssh.InsecureKeyExchangeDH1SHA1}
		}
		conn, channels, requests, err := ssh.NewServerConn(server, config)
		if err != nil {
			return
		}
		defer conn.Close()
		group.Go(func() { ssh.DiscardRequests(requests) })
		if options.openUnsolicited != "" {
			group.Go(func() {
				channel, _, err := conn.OpenChannel(options.openUnsolicited, nil)
				if channel != nil {
					_ = channel.Close()
				}
				fixture.unsolicited <- err
			})
		}
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.Prohibited, "unsupported")
				continue
			}
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			group.Go(func() {
				defer channel.Close()
				for request := range requests {
					fixture.events <- requestEvent{request.Type, append([]byte(nil), request.Payload...), request.WantReply}
					switch request.Type {
					case "pty-req":
						_ = request.Reply(!options.rejectPTY, nil)
					case "shell":
						_ = request.Reply(!options.rejectShell, nil)
						if !options.rejectShell {
							fixture.session <- channel
							group.Go(func() {
								if options.shellFixture != nil {
									options.shellFixture(channel)
								} else {
									_, _ = io.Copy(channel, channel)
								}
							})
						}
					case "window-change":
						if options.resizeFixture != nil {
							options.resizeFixture(request.Payload)
						}
						if request.WantReply {
							_ = request.Reply(false, nil)
						}
					default:
						if request.WantReply {
							_ = request.Reply(false, nil)
						}
					}
				}
			})
		}
	})
	return fixture
}

func labConfig(host, user ssh.Signer) Config {
	return Config{User: "lab-user", HostKey: host.PublicKey().Marshal(), Signer: user, Columns: 100, Rows: 30}
}

func openFixture(t *testing.T, fixture *sshFixture, config Config) *Terminal {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	terminal, err := connect(ctx, "server.example", func(context.Context) (net.Conn, error) { return fixture.client, nil }, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = terminal.Close() })
	return terminal
}

func nextEvent(t *testing.T, fixture *sshFixture, kind string) requestEvent {
	t.Helper()
	select {
	case event := <-fixture.events:
		if event.kind != kind {
			t.Fatalf("expected %s, received %s", kind, event.kind)
		}
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("missing remote request")
		return requestEvent{}
	}
}

func TestSSHVerifiedKeyOpensRemotePTYWithExactUnicodeInputAndResize(t *testing.T) {
	host, user := syntheticSigner(t), &signCounter{Signer: syntheticSigner(t)}
	fixture := newFixture(t, fixtureOptions{host: host, user: user})
	terminal := openFixture(t, fixture, labConfig(host, user))
	if fixture.auth.Load() == 0 || user.calls.Load() == 0 {
		t.Fatal("remote session opened without key authentication")
	}
	pty := nextEvent(t, fixture, "pty-req")
	var dimensions struct {
		Term                         string
		Columns, Rows, Width, Height uint32
		Modes                        string
	}
	if err := ssh.Unmarshal(pty.payload, &dimensions); err != nil || !pty.wantReply || dimensions.Term != "xterm-256color" || dimensions.Columns != 100 || dimensions.Rows != 30 || dimensions.Width != 0 || dimensions.Height != 0 || dimensions.Modes != "\x00" {
		t.Fatal("wrong remote PTY configuration")
	}
	if shell := nextEvent(t, fixture, "shell"); !shell.wantReply || len(shell.payload) != 0 {
		t.Fatal("shell request carried a command or was not acknowledged")
	}
	input := []byte("Salam, Azərbaycan! əıöüçşğ\n\x03\x1b[A\x1b[200~iki\nsətir\x1b[201~")
	if n, err := terminal.Write(input); err != nil || n != len(input) {
		t.Fatal("terminal did not forward exact input")
	}
	output := make([]byte, len(input))
	if _, err := io.ReadFull(terminal, output); err != nil || !bytes.Equal(input, output) {
		t.Fatal("Unicode/control input changed in transit")
	}
	if err := terminal.Resize(140, 45); err != nil {
		t.Fatal(err)
	}
	event := nextEvent(t, fixture, "window-change")
	var size struct{ Columns, Rows, Width, Height uint32 }
	if err := ssh.Unmarshal(event.payload, &size); err != nil || event.wantReply || size.Columns != 140 || size.Rows != 45 || size.Width != 0 || size.Height != 0 {
		t.Fatal("wrong remote resize request")
	}
	channel := <-fixture.session
	if _, err := channel.Stderr().Write([]byte("synthetic stderr")); err != nil {
		t.Fatal(err)
	}
	stderr := make([]byte, len("synthetic stderr"))
	if _, err := io.ReadFull(stderrReader{terminal}, stderr); err != nil || string(stderr) != "synthetic stderr" {
		t.Fatal("extended output was not accessible")
	}
	_ = terminal.Close()
	_ = terminal.Close()
}

type stderrReader struct{ terminal *Terminal }

func (r stderrReader) Read(p []byte) (int, error) { return r.terminal.ReadStderr(p) }

func TestSSHChangedHostKeyStopsBeforeAuthentication(t *testing.T) {
	host, user := syntheticSigner(t), &signCounter{Signer: syntheticSigner(t)}
	fixture := newFixture(t, fixtureOptions{host: host, user: user})
	config := labConfig(syntheticSigner(t), user)
	terminal, err := connect(context.Background(), "server.example", func(context.Context) (net.Conn, error) { return fixture.client, nil }, config)
	if terminal != nil || err != ErrHostKey || fixture.auth.Load() != 0 || user.calls.Load() != 0 {
		t.Fatal("changed host key reached user authentication")
	}
	if len(fixture.events) != 0 {
		t.Fatal("changed host key reached a PTY")
	}
}

const syntheticRemotePassword = "Synthetic remote şifrə 1!"

func passwordConfig(host ssh.Signer, password string) Config {
	return Config{User: "lab-user", HostKey: host.PublicKey().Marshal(), Password: []byte(password), Columns: 100, Rows: 30}
}

func connectOnce(fixture *sshFixture, config Config) (*Terminal, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return connect(ctx, "server.example", func(context.Context) (net.Conn, error) { return fixture.client, nil }, config)
}

// A server that only takes passwords is reached with the stored password,
// after its host key is verified, through either password or a single hidden
// keyboard-interactive prompt. The password never reaches an unverified host.
func TestSSHPasswordAuthenticationAfterHostVerification(t *testing.T) {
	host := syntheticSigner(t)
	for _, mode := range []string{"password", "keyboard-interactive"} {
		options := fixtureOptions{host: host, password: syntheticRemotePassword}
		if mode == "keyboard-interactive" {
			options.prompts, options.echos = []string{"Password: "}, []bool{false}
		}
		fixture := newFixture(t, options)
		terminal := openFixture(t, fixture, passwordConfig(host, syntheticRemotePassword))
		if fixture.auth.Load() != 1 {
			t.Fatalf("%s: authenticated %d times", mode, fixture.auth.Load())
		}
		_ = terminal.Close()
	}
	for name, options := range map[string]fixtureOptions{
		"wrong password":    {host: host, password: "a different synthetic password"},
		"visible prompt":    {host: host, password: syntheticRemotePassword, prompts: []string{"Password: "}, echos: []bool{true}},
		"two prompts":       {host: host, password: syntheticRemotePassword, prompts: []string{"Password: ", "Code: "}, echos: []bool{false, false}},
		"no authentication": {host: host, noAuth: true},
	} {
		fixture := newFixture(t, options)
		if terminal, err := connectOnce(fixture, passwordConfig(host, syntheticRemotePassword)); err == nil || terminal != nil {
			t.Fatalf("%s: session opened", name)
		}
	}
	// A changed host key stops before any credential is offered.
	fixture := newFixture(t, fixtureOptions{host: syntheticSigner(t), password: syntheticRemotePassword})
	if _, err := connectOnce(fixture, passwordConfig(host, syntheticRemotePassword)); err != ErrHostKey || fixture.auth.Load() != 0 {
		t.Fatal("a password was offered to an unverified host")
	}
	// And the answers themselves refuse without verification, whatever order
	// a library calls them in; a prompt is answered only when it is one hidden one.
	var verified, used atomic.Bool
	if answer, err := passwordAnswer(syntheticRemotePassword, &verified, &used)(); answer != "" || err != ErrHostKey || used.Load() {
		t.Fatal("password answered before host verification")
	}
	prompt := promptAnswer(syntheticRemotePassword, &verified, &used)
	if answers, err := prompt("", "", []string{"Password: "}, []bool{false}); answers != nil || err != ErrHostKey || used.Load() {
		t.Fatal("prompt answered before host verification")
	}
	verified.Store(true)
	for name, prompts := range map[string][2][]any{
		"visible":    {{"Password: "}, {true}},
		"two hidden": {{"Password: ", "Code: "}, {false, false}},
	} {
		questions, echos := []string{}, []bool{}
		for i := range prompts[0] {
			questions, echos = append(questions, prompts[0][i].(string)), append(echos, prompts[1][i].(bool))
		}
		if answers, err := prompt("", "", questions, echos); answers != nil || err == nil || used.Load() {
			t.Fatalf("%s prompt was answered with the password", name)
		}
	}
	if answers, err := prompt("", "", []string{"Password: "}, []bool{false}); err != nil || len(answers) != 1 || answers[0] != syntheticRemotePassword || !used.Load() {
		t.Fatal("a single hidden prompt after verification was not answered")
	}
	user := syntheticSigner(t)
	for name, config := range map[string]Config{
		"both credentials": {User: "lab-user", HostKey: host.PublicKey().Marshal(), Signer: user, Password: []byte(syntheticRemotePassword), Columns: 100, Rows: 30},
		"no credential":    {User: "lab-user", HostKey: host.PublicKey().Marshal(), Columns: 100, Rows: 30},
		"NUL password":     passwordConfig(host, "nul\x00inside"),
		"invalid UTF-8":    passwordConfig(host, string([]byte{0xff})),
		"long password":    passwordConfig(host, strings.Repeat("a", sshkey.MaxPasswordLen+1)),
	} {
		if _, err := validateConfig(config); err != ErrInvalidConfig {
			t.Fatalf("%s: configuration accepted", name)
		}
	}
}

// ECDSA and RSA user keys authenticate; RSA signs with SHA-2 only, so a
// server that accepts nothing but SHA-1 "ssh-rsa" is refused.
func TestSSHUserKeyTypesAndNoSHA1(t *testing.T) {
	host := syntheticSigner(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, private := range map[string]any{"ecdsa-p384": p384, "rsa-2048": rsaKey} {
		key, err := sshkey.New(private)
		if err != nil {
			t.Fatal(err)
		}
		fixture := newFixture(t, fixtureOptions{host: host, user: key})
		terminal := openFixture(t, fixture, labConfig(host, key))
		if fixture.auth.Load() != 1 {
			t.Fatalf("%s key did not authenticate exactly once", name)
		}
		_ = terminal.Close()
	}
	key, err := sshkey.New(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, algos := range [][]string{{ssh.KeyAlgoRSASHA512}, {ssh.KeyAlgoRSASHA256}} {
		fixture := newFixture(t, fixtureOptions{host: host, user: key, userKeyAlgos: algos})
		_ = openFixture(t, fixture, labConfig(host, key)).Close()
	}
	sha1Only := newFixture(t, fixtureOptions{host: host, user: key, userKeyAlgos: []string{ssh.KeyAlgoRSA}})
	if terminal, err := connectOnce(sha1Only, labConfig(host, key)); err == nil || terminal != nil {
		t.Fatal("an RSA key authenticated with SHA-1")
	}
	// A plain signer cannot be held to SHA-2, so an RSA one is refused.
	plain, _ := ssh.NewSignerFromKey(rsaKey)
	if _, err := validateConfig(labConfig(host, &signCounter{Signer: plain})); err != ErrInvalidConfig {
		t.Fatal("an RSA signer without algorithm control was accepted")
	}
}

func TestSSHRefusesNoneAuthAndAuthenticationOrPTYFailure(t *testing.T) {
	for _, failure := range []string{"none", "auth", "pty", "shell"} {
		t.Run(failure, func(t *testing.T) {
			host, user := syntheticSigner(t), syntheticSigner(t)
			fixture := newFixture(t, fixtureOptions{host: host, user: user, noAuth: failure == "none", rejectAuth: failure == "auth", rejectPTY: failure == "pty", rejectShell: failure == "shell"})
			terminal, err := connect(context.Background(), "server.example", func(context.Context) (net.Conn, error) { return fixture.client, nil }, labConfig(host, user))
			if terminal != nil || err != ErrUnavailable {
				t.Fatal("refused remote setup was accepted or exposed diagnostics")
			}
			if (failure == "none" || failure == "auth") && len(fixture.events) != 0 {
				t.Fatal("failed authentication opened a session channel")
			}
		})
	}
}

func TestSSHRejectsUnsolicitedForwardingChannels(t *testing.T) {
	for _, kind := range []string{"auth-agent@openssh.com", "x11", "forwarded-tcpip"} {
		host, user := syntheticSigner(t), syntheticSigner(t)
		fixture := newFixture(t, fixtureOptions{host: host, user: user, openUnsolicited: kind})
		_ = openFixture(t, fixture, labConfig(host, user))
		select {
		case err := <-fixture.unsolicited:
			if err == nil {
				t.Fatal("unsolicited forwarding channel was accepted")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("unsolicited channel was not serviced")
		}
	}
}

func TestSSHSessionCancellationUnblocksReadersAndClosesRemote(t *testing.T) {
	host, user := syntheticSigner(t), syntheticSigner(t)
	fixture := newFixture(t, fixtureOptions{host: host, user: user})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	terminal, err := connect(ctx, "server.example", func(context.Context) (net.Conn, error) { return fixture.client, nil }, labConfig(host, user))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = terminal.Close() })
	readDone := make(chan error, 2)
	go func() { _, err := terminal.Read(make([]byte, 1)); readDone <- err }()
	go func() { _, err := terminal.ReadStderr(make([]byte, 1)); readDone <- err }()
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-readDone:
			if err == nil {
				t.Fatal("canceled channel remained readable")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancellation did not unblock terminal readers")
		}
	}
	if _, err := terminal.Write([]byte("after cancellation")); err == nil {
		t.Fatal("canceled session accepted more input")
	}
}

func TestSSHHandshakeDeadlineAndCancellationCloseStalledTransport(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		host, user := syntheticSigner(t), syntheticSigner(t)
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		var ctx context.Context
		var cancel context.CancelFunc
		if timeout {
			ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			go func() {
				_, _ = bufio.NewReader(server).ReadString('\n')
				cancel()
			}()
		}
		defer cancel()
		terminal, err := connect(ctx, "server.example", func(context.Context) (net.Conn, error) { return client, nil }, labConfig(host, user))
		want := context.Canceled
		if timeout {
			want = context.DeadlineExceeded
		}
		if terminal != nil || !errors.Is(err, want) {
			t.Fatalf("stalled handshake was not canceled: %v", err)
		}
		if _, err := server.Write([]byte("synthetic")); err == nil {
			t.Fatal("stalled setup leaked a transport")
		}
	}
}

func TestSSHInvalidConfigurationAndCanceledRequestsNeverDial(t *testing.T) {
	host, user := syntheticSigner(t), syntheticSigner(t)
	base := labConfig(host, user)
	badConfigs := []Config{{}}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.User = "" }, func(c *Config) { c.User = strings.Repeat("a", 129) },
		func(c *Config) { c.User = "lab\nuser" }, func(c *Config) { c.User = "user;cmd" },
		func(c *Config) { c.HostKey = nil }, func(c *Config) { c.HostKey = []byte("malformed") },
		func(c *Config) { c.HostKey = make([]byte, 257) }, func(c *Config) { c.Signer = nil },
		func(c *Config) { c.Columns = 0 }, func(c *Config) { c.Rows = MaxRows + 1 },
		func(c *Config) { c.Columns = MaxColumns + 1 },
	} {
		config := base
		mutate(&config)
		badConfigs = append(badConfigs, config)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := ssh.NewSignerFromKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	// Host keys stay Ed25519; ECDSA is accepted only as a user key.
	config := base
	config.HostKey = ecSigner.PublicKey().Marshal()
	badConfigs = append(badConfigs, config)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakSigner, err := ssh.NewSignerFromKey(weak)
	if err != nil {
		t.Fatal(err)
	}
	config = base
	config.Signer = weakSigner
	badConfigs = append(badConfigs, config)
	dial := func(context.Context) (net.Conn, error) {
		t.Fatal("invalid/canceled configuration reached network")
		return nil, nil
	}
	for _, config := range badConfigs {
		if terminal, err := connect(context.Background(), "server.example", dial, config); terminal != nil || err != ErrInvalidConfig {
			t.Fatal("invalid SSH configuration accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := connect(ctx, "server.example", dial, base); err != context.Canceled {
		t.Fatal("canceled setup reached dial")
	}
	//lint:ignore SA1012 deliberately test malformed caller context.
	if _, err := connect(nil, "server.example", dial, base); err != ErrInvalidConfig {
		t.Fatal("nil context accepted")
	}
	if _, err := connect(context.Background(), "", dial, base); err != ErrInvalidConfig {
		t.Fatal("missing logical server identity accepted")
	}
	if _, err := Connect(context.Background(), nil, base); err != ErrInvalidConfig {
		t.Fatal("missing guarded target accepted")
	}
}

func TestSSHInputAndResizeBoundsDoNotSendRequests(t *testing.T) {
	host, user := syntheticSigner(t), syntheticSigner(t)
	fixture := newFixture(t, fixtureOptions{host: host, user: user})
	terminal := openFixture(t, fixture, labConfig(host, user))
	nextEvent(t, fixture, "pty-req")
	nextEvent(t, fixture, "shell")
	for _, size := range [][2]uint32{{0, 1}, {1, 0}, {MaxColumns + 1, 1}, {1, MaxRows + 1}, {^uint32(0), 1}} {
		if terminal.Resize(size[0], size[1]) != ErrInvalidInput {
			t.Fatal("unbounded resize accepted")
		}
	}
	if n, err := terminal.Write(make([]byte, MaxInputBytes+1)); n != 0 || err != ErrInvalidInput {
		t.Fatal("oversized input accepted")
	}
	if len(fixture.events) != 0 {
		t.Fatal("invalid input sent a remote request")
	}
	_ = terminal.Close()
}

func TestSSHRefusesLegacyAlgorithmBeforeAuthentication(t *testing.T) {
	host, user := syntheticSigner(t), &signCounter{Signer: syntheticSigner(t)}
	fixture := newFixture(t, fixtureOptions{host: host, user: user, legacyKEX: true})
	terminal, err := connect(context.Background(), "server.example", func(context.Context) (net.Conn, error) { return fixture.client, nil }, labConfig(host, user))
	if terminal != nil || err != ErrUnavailable || fixture.auth.Load() != 0 || user.calls.Load() != 0 {
		t.Fatal("legacy negotiation reached authentication")
	}
}

func TestSSHCancellationStopsBackpressuredRemoteOutput(t *testing.T) {
	host, user := syntheticSigner(t), syntheticSigner(t)
	fixture := newFixture(t, fixtureOptions{host: host, user: user})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	terminal, err := connect(ctx, "server.example", func(context.Context) (net.Conn, error) { return fixture.client, nil }, labConfig(host, user))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = terminal.Close() })
	channel := <-fixture.session
	writeDone := make(chan error, 1)
	go func() {
		// Larger than the pinned library's 2 MiB channel window; no reader
		// consumes this output, so successful completion is not possible.
		_, err := channel.Write(make([]byte, 3*1024*1024))
		writeDone <- err
	}()
	select {
	case <-writeDone:
		t.Fatal("unconsumed remote output unexpectedly completed")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("canceled output was reported as successful")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation left remote output blocked")
	}
}

func TestSSHUnconfiguredTerminalAndErrorsAreSafe(t *testing.T) {
	for _, terminal := range []*Terminal{nil, {}} {
		if _, err := terminal.Read(nil); err != io.EOF {
			t.Fatal("empty terminal read did not stop")
		}
		if _, err := terminal.ReadStderr(nil); err != io.EOF {
			t.Fatal("empty terminal stderr did not stop")
		}
		if _, err := terminal.Write(nil); err != ErrSession || terminal.Resize(1, 1) != ErrSession || terminal.Close() != nil {
			t.Fatal("empty terminal did not fail safely")
		}
	}
	if terminalError(errors.New("synthetic sensitive network diagnostic")) != ErrSession {
		t.Fatal("network diagnostic escaped terminal error boundary")
	}
	if terminalError(fmt.Errorf("synthetic private diagnostic: %w", io.EOF)) != io.EOF {
		t.Fatal("wrapped EOF disclosed private diagnostics")
	}
}

type deadlineFailureConn struct {
	net.Conn
	onClear bool
}

func (c deadlineFailureConn) SetDeadline(deadline time.Time) error {
	if !c.onClear || deadline.IsZero() {
		return errors.New("synthetic private deadline diagnostic")
	}
	return c.Conn.SetDeadline(deadline)
}

func TestSSHFailedDialAndDeadlineSetupCloseTransports(t *testing.T) {
	host, user := syntheticSigner(t), syntheticSigner(t)
	config := labConfig(host, user)
	for _, withConn := range []bool{false, true} {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		dial := func(context.Context) (net.Conn, error) {
			if withConn {
				return client, errors.New("synthetic private dial diagnostic")
			}
			return nil, nil
		}
		if terminal, err := connect(context.Background(), "server.example", dial, config); terminal != nil || err != ErrUnavailable {
			t.Fatal("failed dial was accepted or leaked a diagnostic")
		}
		if withConn {
			if _, err := server.Write([]byte("synthetic")); err == nil {
				t.Fatal("failed dial leaked its unexpected connection")
			}
		}
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := connect(context.Background(), "server.example", func(context.Context) (net.Conn, error) { return deadlineFailureConn{Conn: client}, nil }, config); err != ErrUnavailable {
		t.Fatal("deadline setup failure was accepted")
	}
	if _, err := server.Write([]byte("synthetic")); err == nil {
		t.Fatal("deadline setup failure leaked a transport")
	}
	fixture := newFixture(t, fixtureOptions{host: host, user: user})
	if _, err := connect(context.Background(), "server.example", func(context.Context) (net.Conn, error) {
		return deadlineFailureConn{Conn: fixture.client, onClear: true}, nil
	}, config); err != ErrUnavailable {
		t.Fatal("deadline clear failure was accepted")
	}
}

func TestSSHHostPinIsCopiedAndSignerCannotRunBeforeVerification(t *testing.T) {
	host, user := syntheticSigner(t), &signCounter{Signer: syntheticSigner(t)}
	config := labConfig(host, user)
	pin, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	config.HostKey[0] ^= 255
	if !bytes.Equal(pin, host.PublicKey().Marshal()) {
		t.Fatal("caller mutation changed the host pin snapshot")
	}
	var verified, signed atomic.Bool
	signer := &verifiedSigner{Signer: user, verified: &verified, signed: &signed}
	if _, err := signer.Sign(rand.Reader, []byte("synthetic")); err != ErrHostKey || signed.Load() || user.calls.Load() != 0 {
		t.Fatal("signer ran without host verification")
	}
}

type delayedDeadlineContext struct{ context.Context }

func (delayedDeadlineContext) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

func TestSSHTransportDeadlinePrecedesContextTimer(t *testing.T) {
	// Model net.Conn's deadline firing before the context timer is scheduled.
	ctx := delayedDeadlineContext{context.Background()}
	if ctx.Err() != nil || setupError(ctx, errors.New("synthetic transport timeout")) != context.DeadlineExceeded {
		t.Fatal("elapsed deadline was reported as an ordinary connection failure")
	}
}

func FuzzSSHHostKeyConfig(f *testing.F) {
	host, user := syntheticSigner(f), syntheticSigner(f)
	for _, seed := range [][]byte{host.PublicKey().Marshal(), nil, []byte("malformed"), bytes.Repeat([]byte{255}, 257)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		config := labConfig(host, user)
		config.HostKey = raw
		pin, err := validateConfig(config)
		if err != nil {
			if err != ErrInvalidConfig || pin != nil {
				t.Fatal("unsafe parse error or partial pin")
			}
			return
		}
		key, err := ssh.ParsePublicKey(pin)
		if err != nil || key.Type() != ssh.KeyAlgoED25519 || len(pin) > 256 || !bytes.Equal(pin, raw) {
			t.Fatal("accepted pin was not canonical Ed25519 wire data")
		}
	})
}
