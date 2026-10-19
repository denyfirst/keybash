// Keybash's operator laboratory entry point. No production remote-access worker
// or public listener is enabled by this command.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/operatorconfig"
	"github.com/denyfirst/keybash/internal/sshtransport"
)

func main() {
	if run(os.Args[1:], os.Stdin, os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "Keybash refused the operation. Check private Linux paths, exclusive DB ownership, input and TLS configuration.")
		os.Exit(1)
	}
}
func run(args []string, input io.Reader, output io.Writer) error {
	refused := errors.New("operation refused")
	if len(args) == 0 {
		return refused
	}
	command := args[0]
	switch command {
	case "init", "bootstrap-renew", "account-add", "account-recover", "serve-lab", "check-targets", "serve-ssh-lab":
	default:
		return refused
	}
	flags := flag.NewFlagSet("keybash", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	data := flags.String("data", "", "existing owned 0700 data directory")
	key := flags.String("key-file", "", "separate owned 0600 instance key path")
	address := flags.String("listen", "127.0.0.1:8443", "numeric loopback TLS listener")
	cert := flags.String("tls-cert", "", "operator TLS certificate path")
	tlsKey := flags.String("tls-key", "", "operator TLS private key path")
	lost := flags.Bool("lost-mfa", false, "offline recovery also clears a lost factor")
	catalog := flags.String("config", "", "root-owned operator target catalog")
	manager := flags.String("ssh-manager", "", "fixed root SSH manager socket")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *lost && command != "account-recover" {
		return refused
	}
	var targets []identity.RemoteTarget
	if command == "check-targets" {
		validFlags := true
		flags.Visit(func(f *flag.Flag) { validFlags = validFlags && f.Name == "config" })
		if !validFlags || *catalog == "" {
			return refused
		}
		var e error
		targets, e = operatorconfig.Load(*catalog)
		if e != nil {
			return refused
		}
		_, e = fmt.Fprintf(output, "Target configuration valid (%d servers).\n", len(targets))
		return e
	}
	if *data == "" || *key == "" || command != "serve-ssh-lab" && (*catalog != "" || *manager != "") {
		return refused
	}
	if command == "serve-ssh-lab" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() <= 0 || os.Geteuid() == 65534 || os.Getegid() <= 0 ||
			*catalog == "" || !filepath.IsAbs(*manager) || filepath.Clean(*manager) != *manager || len(*manager) > 100 {
			return refused
		}
		var e error
		targets, e = operatorconfig.Load(*catalog)
		if e != nil || !sshOnly(targets) {
			return refused
		}
	}
	if command == "init" {
		store, code, e := identity.InitializeFiles(*data, *key)
		if e != nil {
			return refused
		}
		defer store.Close()
		_, e = fmt.Fprintln(output, code)
		return e
	}
	store, e := identity.OpenFiles(*data, *key)
	if e != nil {
		return refused
	}
	defer store.Close()
	switch command {
	case "bootstrap-renew":
		code, e := store.RenewBootstrap()
		if e != nil {
			return refused
		}
		_, e = fmt.Fprintln(output, code)
		return e
	case "account-add", "account-recover":
		// Fixed two-line stdin protocol: exact username then exact password. No
		// command-line/environment secrets and no duplicate/unknown JSON fields.
		raw, e := io.ReadAll(io.LimitReader(input, 2049))
		if e != nil || len(raw) > 2048 {
			return refused
		}
		defer clear(raw)
		text := strings.TrimSuffix(string(raw), "\n")
		parts := strings.Split(text, "\n")
		if len(parts) != 2 {
			return refused
		}
		if command == "account-add" {
			return store.CreateAccount(parts[0], parts[1])
		}
		return store.RecoverAccount(parts[0], parts[1], *lost)
	case "serve-lab", "serve-ssh-lab":
		host, port, e := net.SplitHostPort(*address)
		ip, pe := netip.ParseAddr(host)
		if e != nil || pe != nil || !ip.Unmap().IsLoopback() || port == "0" || *cert == "" || *tlsKey == "" {
			return refused
		}
		origin := "https://" + *address
		var lab *identity.Lab
		if command == "serve-ssh-lab" {
			lab, e = identity.NewRemoteLab(origin, store, targets, sshtransport.ManagerWorker{SocketPath: *manager}, nil)
		} else {
			lab, e = identity.NewPersistent(origin, store)
		}
		if e != nil {
			return refused
		}
		defer lab.Close()
		pair, e := tls.LoadX509KeyPair(*cert, *tlsKey)
		if e != nil {
			return refused
		}
		listener, e := net.Listen("tcp", *address)
		if e != nil {
			return refused
		}
		server := &http.Server{Handler: lab, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = lab.Close()
				_ = server.Shutdown(shutdown)
			case <-done:
			}
		}()
		e = server.Serve(tls.NewListener(listener, server.TLSConfig))
		close(done)
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return refused
	}
	return refused
}

func sshOnly(targets []identity.RemoteTarget) bool {
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if target.Protocol != "ssh" {
			return false
		}
	}
	return true
}
