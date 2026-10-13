package sshtransport

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// Test-only Linux server fixture. No shipped code executes a local shell.
func linuxShellOptions(t *testing.T, host, user ssh.Signer) fixtureOptions {
	t.Helper()
	var mu sync.Mutex
	var master *os.File
	workingDirectory := t.TempDir()
	options := fixtureOptions{host: host, user: user}
	options.shellFixture = func(channel ssh.Channel) {
		command := exec.Command("/bin/bash", "--noprofile", "--norc", "-i")
		command.Env = []string{"PATH=/usr/bin:/bin", "TERM=xterm-256color", "LC_ALL=C.UTF-8", "PS1=keybash-lab> ", "HISTFILE=/dev/null"}
		command.Dir = workingDirectory
		file, err := pty.StartWithSize(command, &pty.Winsize{Cols: 100, Rows: 30})
		if err != nil {
			t.Error("Linux PTY fixture could not start")
			_ = channel.Close()
			return
		}
		mu.Lock()
		master = file
		mu.Unlock()
		closePTY := func() { mu.Lock(); master = nil; _ = file.Close(); mu.Unlock() }
		defer func() {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			closePTY()
			_ = command.Wait()
			_ = channel.Close()
		}()
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(file, channel)
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			closePTY()
			close(done)
		}()
		_, _ = io.Copy(channel, file)
		_ = channel.Close()
		closePTY()
		<-done
	}
	options.resizeFixture = func(data []byte) {
		var size struct{ Columns, Rows, Width, Height uint32 }
		if ssh.Unmarshal(data, &size) != nil || !validSize(size.Columns, size.Rows) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if master != nil {
			_ = pty.Setsize(master, &pty.Winsize{Cols: uint16(size.Columns), Rows: uint16(size.Rows)})
		}
	}
	return options
}

func TestSSHLinuxBashPTYUnicodeInterruptAndKernelResize(t *testing.T) {
	host, user := syntheticSigner(t), syntheticSigner(t)
	fixture := newFixture(t, linuxShellOptions(t, host, user))
	terminal := openFixture(t, fixture, labConfig(host, user))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output := make(chan []byte, 32)
	go func() {
		buffer := make([]byte, 8192)
		for {
			n, err := terminal.Read(buffer)
			if n > 0 {
				select {
				case output <- append([]byte(nil), buffer[:n]...):
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	var collected []byte
	wait := func(marker string) {
		t.Helper()
		for {
			index := bytes.Index(collected, []byte(marker))
			if index >= 0 {
				collected = collected[index+len(marker):]
				return
			}
			select {
			case chunk := <-output:
				collected = append(collected, chunk...)
			case <-ctx.Done():
				t.Fatalf("Linux PTY marker missing: %s", marker)
			}
		}
	}
	wait("keybash-lab> ")
	if err := terminal.Resize(140, 45); err != nil {
		t.Fatal(err)
	}
	_, _ = terminal.Write([]byte("printf '\\u0259\\u0131\\u00f6\\u00fc\\u00e7\\u015f\\u011f'; printf '\\n'; stty size\r"))
	wait("əıöüçşğ")
	wait("45 140")
	// Readiness is emitted by the foreground child, after Bash has assigned
	// its process group to the PTY. A marker from the parent shell is too early.
	_, _ = terminal.Write([]byte("stty -echo; bash --noprofile --norc -c 'printf \"KI_%s\\n\" READY; exec sleep 30'\r"))
	wait("KI_READY")
	_, _ = terminal.Write([]byte{3})
	wait("keybash-lab> ")
	_ = terminal.Close()
}
