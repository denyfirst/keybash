//go:build browserlab

package identity

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

type demoWorker struct{}

// This worker has no dial or process execution path. Catalog addresses are
// inert metadata. It does not implement or claim SSH authentication. The
// desktop page runs IronRDP, which needs a real RDP server, so the demo has
// no desktop.
func (*demoWorker) OpenSSH(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, user string, _ sshkey.Credential) (terminalweb.Stream, error) {
	if user != "synthetic-user" || ctx.Err() != nil {
		return nil, errRefused
	}
	a, b := net.Pipe()
	stop := context.AfterFunc(ctx, func() { _ = a.Close(); _ = b.Close() })
	go func() { defer stop(); defer b.Close(); demoTerminal(b) }()
	return fixtureRemoteStream{a}, nil
}

func demoCommand(line string) string {
	switch line {
	case "help":
		return "SIMULATION ONLY. No local or remote shell.\r\nCommands: help, whoami, hostname, pwd, ls, uname, date, echo TEXT, clear, exit\r\n"
	case "whoami":
		return "synthetic-user\r\n"
	case "hostname":
		return "keybash-demo.invalid\r\n"
	case "pwd":
		return "/home/synthetic-user (simulated)\r\n"
	case "ls":
		return "README-demo.txt  no-real-files/\r\n"
	case "uname", "uname -a":
		return "Simulated Linux terminal UI; no operating system attached\r\n"
	case "date":
		return time.Now().UTC().Format(time.RFC3339) + "\r\n"
	case "clear":
		return "\x1b[2J\x1b[H"
	case "":
		return ""
	}
	if strings.HasPrefix(line, "echo ") {
		return strings.TrimPrefix(line, "echo ") + "\r\n"
	}
	return "Demo: command unavailable. Type help. Nothing was executed.\r\n"
}

func demoTerminal(conn net.Conn) {
	if _, err := io.WriteString(conn, "\x1b[36mKEYBASH INTERACTIVE UI DEMO\x1b[0m\r\nSimulation only: no Linux shell, host files or network access.\r\nType help. Try Unicode, selection/copy, paste preview and Ctrl+C.\r\n\r\ndemo@keybash:~$ "); err != nil {
		return
	}
	r := bufio.NewReader(conn)
	line := []rune{}
	for {
		ch, _, err := r.ReadRune()
		if err != nil {
			return
		}
		out := ""
		switch ch {
		case '\r', '\n':
			if string(line) == "exit" {
				_, _ = io.WriteString(conn, "\r\nDemo session closed.\r\n")
				return
			}
			out = "\r\n" + demoCommand(string(line)) + "demo@keybash:~$ "
			line = line[:0]
		case 3:
			line = line[:0]
			out = "^C\r\ndemo@keybash:~$ "
		case 4:
			return
		case 12:
			out = "\x1b[2J\x1b[Hdemo@keybash:~$ " + string(line)
		case 8, 127:
			if len(line) > 0 {
				line = line[:len(line)-1]
				out = "\b \b"
			}
		case 27:
			// Consume a bounded CSI arrow/bracketed-paste marker, never execute
			// or reflect escape sequences from user input.
			if next, err := r.ReadByte(); err != nil || next != '[' {
				return
			}
			for i := 0; i < 16; i++ {
				b, err := r.ReadByte()
				if err != nil {
					return
				}
				if b >= 0x40 && b <= 0x7e {
					break
				}
				if i == 15 {
					return
				}
			}
		default:
			if ch >= 32 && ch != utf8.RuneError && len(line) < 1024 {
				line = append(line, ch)
				out = string(ch)
			}
		}
		if _, err := io.WriteString(conn, out); err != nil {
			return
		}
	}
}

// The simulated terminal runs nothing: it answers a few fixed commands and
// says so for any other.
func TestDemoInputBoundary(t *testing.T) {
	if !strings.Contains(demoCommand("help"), "SIMULATION ONLY") || !strings.Contains(demoCommand("echo hello"), "hello") {
		t.Fatal("valid simulated command refused")
	}
	for _, raw := range []string{"powershell", "bash -c id", "cat /etc/passwd", "echo; whoami", "curl https://example.invalid"} {
		if !strings.Contains(demoCommand(raw), "Nothing was executed") {
			t.Fatal("arbitrary demo command accepted")
		}
	}
}

func TestDemoWorkerCancellation(t *testing.T) {
	worker := &demoWorker{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := worker.OpenSSH(ctx, nil, nil, "wrong-user", nil); err == nil {
		t.Fatal("wrong demo user accepted")
	}
	stream, err := worker.OpenSSH(ctx, nil, nil, "synthetic-user", nil)
	if err != nil {
		t.Fatal("valid demo user refused")
	}
	defer stream.Close()
	buffer := make([]byte, 2048)
	if n, err := stream.Read(buffer); err != nil || !bytes.Contains(buffer[:n], []byte("Simulation only")) {
		t.Fatal("demo disclosure missing")
	}
	cancel()
	done := make(chan error, 1)
	go func() { _, err := stream.Read(buffer); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled demo stream stayed readable")
		}
	case <-time.After(time.Second):
		t.Fatal("demo cancellation did not release read")
	}
	if _, err := worker.OpenSSH(ctx, nil, nil, "synthetic-user", nil); err == nil {
		t.Fatal("canceled demo worker started")
	}
}
