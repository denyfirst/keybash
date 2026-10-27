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
	"github.com/denyfirst/keybash/internal/rdplab"
	"github.com/denyfirst/keybash/internal/sessionlimits"
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
	case "init", "bootstrap-renew", "account-add", "account-recover", "serve-lab", "check-targets", "serve-ssh-lab", "serve-remote-lab", "backup", "restore", "key-export", "key-import":
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
	rdpManager := flags.String("rdp-manager", "", "fixed root RDP manager socket")
	manager := flags.String("ssh-manager", "", "fixed root SSH manager socket")
	out := flags.String("out", "", "new backup file, never beside the instance key")
	in := flags.String("in", "", "backup file to restore")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *lost && command != "account-recover" || (*out != "") != (command == "backup") || (*in != "") != (command == "restore") {
		return refused
	}
	var targets []identity.RemoteTarget
	limits := sessionlimits.Default()
	if command == "check-targets" {
		validFlags := true
		flags.Visit(func(f *flag.Flag) { validFlags = validFlags && f.Name == "config" })
		if !validFlags || *catalog == "" {
			return refused
		}
		var e error
		var snapshot operatorconfig.Catalog
		snapshot, e = operatorconfig.LoadCatalog(*catalog)
		targets = snapshot.Targets
		if e != nil {
			return refused
		}
		_, e = fmt.Fprintf(output, "Target configuration valid (%d servers; capacity %d total, %d per owner).\n", len(targets), snapshot.Capacity.Total, snapshot.Capacity.PerOwner)
		return reportUnavailable(output, e, targets, time.Now())
	}
	if *data == "" || *key == "" || command != "serve-ssh-lab" && command != "serve-remote-lab" && (*catalog != "" || *manager != "" || *rdpManager != "") || command != "serve-remote-lab" && *rdpManager != "" {
		return refused
	}
	if command == "serve-ssh-lab" || command == "serve-remote-lab" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() <= 0 || os.Geteuid() == 65534 || os.Getegid() <= 0 ||
			*catalog == "" || !filepath.IsAbs(*manager) || filepath.Clean(*manager) != *manager || len(*manager) > 100 {
			return refused
		}
		var e error
		var snapshot operatorconfig.Catalog
		snapshot, e = operatorconfig.LoadCatalog(*catalog)
		targets, limits = snapshot.Targets, snapshot.Capacity
		if e != nil || command == "serve-ssh-lab" && !sshOnly(targets) || command == "serve-remote-lab" && (!filepath.IsAbs(*rdpManager) || filepath.Clean(*rdpManager) != *rdpManager || len(*rdpManager) > 100 || *rdpManager == *manager) {
			return refused
		}
	}
	switch command {
	case "init":
		store, code, e := identity.InitializeFiles(*data, *key)
		if e != nil {
			return refused
		}
		defer store.Close()
		_, e = fmt.Fprintln(output, code)
		return e
	case "restore":
		codes, summary, e := identity.RestoreFiles(*data, *key, *in, time.Now())
		if e != nil {
			return refused
		}
		// Every factor was reset: hand each user their code, as with account-add.
		_, e = fmt.Fprintf(output, "Restored instance %s from a backup made %s by %s: %d accounts, %d credentials, %d connections.\nMFA was reset for every account. Give each user their one-time setup code:\n",
			summary.Instance, summary.Created.Format(time.RFC3339), summary.Program, summary.Accounts, summary.Credentials, summary.Connections)
		for _, c := range codes {
			if e == nil {
				_, e = fmt.Fprintf(output, "%s\t%s\n", c.Username, c.Code)
			}
		}
		return e
	case "key-export":
		code, e := identity.ExportKeyFiles(*data, *key)
		if e != nil {
			return refused
		}
		_, e = fmt.Fprintln(output, code)
		return e
	case "key-import":
		// The recovery code arrives on stdin, never in arguments or environment.
		raw, e := io.ReadAll(io.LimitReader(input, 257))
		if e != nil || len(raw) > 256 {
			return refused
		}
		defer clear(raw)
		if identity.ImportKeyFiles(*data, *key, string(raw)) != nil {
			return refused
		}
		return nil
	}
	store, e := identity.OpenFiles(*data, *key)
	if e != nil {
		return refused
	}
	defer store.Close()
	switch command {
	case "backup":
		summary, e := identity.WriteBackup(store, *out, *key, time.Now())
		if e != nil {
			return refused
		}
		_, e = fmt.Fprintf(output, "Backup of instance %s written %s: %d accounts, %d credentials, %d connections. It opens only with the instance key; keep the key's recovery code apart from it.\n",
			summary.Instance, summary.Created.Format(time.RFC3339), summary.Accounts, summary.Credentials, summary.Connections)
		return e
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
		// The one-time setup code goes to the operator's terminal like the
		// bootstrap code: hand it over separately from the password. Recovery
		// that keeps an enrolled factor prints nothing.
		var setup string
		if command == "account-add" {
			setup, e = store.CreateAccount(parts[0], parts[1])
		} else {
			setup, e = store.RecoverAccount(parts[0], parts[1], *lost)
		}
		if e != nil {
			return refused
		}
		if setup != "" {
			_, e = fmt.Fprintln(output, setup)
		}
		return e
	case "serve-lab", "serve-ssh-lab", "serve-remote-lab":
		host, port, e := net.SplitHostPort(*address)
		ip, pe := netip.ParseAddr(host)
		if e != nil || pe != nil || !ip.Unmap().IsLoopback() || port == "0" || *cert == "" || *tlsKey == "" {
			return refused
		}
		origin := "https://" + *address
		var lab *identity.Lab
		if command == "serve-ssh-lab" || command == "serve-remote-lab" {
			var worker identity.RDPWorker
			if command == "serve-remote-lab" {
				worker = rdplab.ManagerWorker{SocketPath: *rdpManager}
			}
			lab, e = identity.NewRemoteLabWithLimits(origin, store, targets, sshtransport.ManagerWorker{SocketPath: *manager}, worker, limits)
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

// reportUnavailable names each valid target that cannot be used now, which
// for RDP means Windows has usually renewed the certificate approved for it.
func reportUnavailable(output io.Writer, e error, targets []identity.RemoteTarget, now time.Time) error {
	for _, target := range targets {
		if e == nil && !target.UsableAt(now) {
			_, e = fmt.Fprintf(output, "Unavailable until its approved certificate is replaced: %q (%s).\n", target.Name, target.ID)
		}
	}
	return e
}
