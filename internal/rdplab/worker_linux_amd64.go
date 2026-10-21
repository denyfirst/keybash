//go:build linux && amd64

package rdplab

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const rdpWorkerHello = "keybash-rdp-worker/v1\n"
const rdpWorkerReady = "keybash-rdp-ready/v1\n"

type rdpConnection struct {
	ctx     context.Context
	cancel  context.CancelFunc
	in, out *os.File
	done    <-chan struct{}
	once    sync.Once
}

func newRDPConnection(ctx context.Context, cancel context.CancelFunc, in, out *os.File, done <-chan struct{}) *rdpConnection {
	c := &rdpConnection{ctx: ctx, cancel: cancel, in: in, out: out, done: done}
	context.AfterFunc(ctx, func() { _ = in.Close(); _ = out.Close() })
	return c
}
func (c *rdpConnection) Read(p []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, errNative
	}
	n, e := c.out.Read(p)
	if c.ctx.Err() != nil {
		clear(p[:n])
		return 0, errNative
	}
	return n, e
}
func (c *rdpConnection) Write(p []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, errNative
	}
	return c.in.Write(p)
}
func (c *rdpConnection) Close() error {
	c.once.Do(func() { c.cancel(); _ = c.in.Close(); _ = c.out.Close() })
	select {
	case <-c.done:
		return nil
	case <-time.After(3 * time.Second):
		return errNative
	}
}
func (c *rdpConnection) LocalAddr() net.Addr  { return &net.UnixAddr{Net: "unix", Name: "private-rdp"} }
func (c *rdpConnection) RemoteAddr() net.Addr { return c.LocalAddr() }
func (c *rdpConnection) SetDeadline(t time.Time) error {
	if c.SetReadDeadline(t) != nil || c.SetWriteDeadline(t) != nil {
		return errNative
	}
	return nil
}
func (c *rdpConnection) SetReadDeadline(t time.Time) error  { return c.out.SetReadDeadline(t) }
func (c *rdpConnection) SetWriteDeadline(t time.Time) error { return c.in.SetWriteDeadline(t) }

func readRDPMarker(r io.Reader, marker string) error {
	p := make([]byte, len(marker))
	_, err := io.ReadFull(r, p)
	if err != nil || string(p) != marker {
		return errNative
	}
	return nil
}
func finishRDPSetup(c *rdpConnection, setup context.Context) error {
	stop := context.AfterFunc(setup, c.cancel)
	defer stop()
	deadline, _ := setup.Deadline()
	if c.SetDeadline(deadline) != nil || readRDPMarker(c, rdpWorkerHello) != nil || readRDPMarker(c, rdpWorkerReady) != nil || setup.Err() != nil || c.ctx.Err() != nil || !stop() || c.SetDeadline(time.Time{}) != nil {
		return errNative
	}
	return nil
}

// RunNativeWorker never accepts a command, path, destination or environment
// from its input. Read-only sealed mounts supply only pinned public trust.
// Credentials pass verbatim through private pipes to the native library.
func RunNativeWorker(parentNS string, uid, gid uint32) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if uid < 1 || gid < 1 || uid > 2147483647 || gid > 2147483647 || uid == 65534 || gid == 65534 || os.Getuid() != int(uid) || os.Geteuid() != int(uid) || os.Getgid() != int(gid) || os.Getegid() != int(gid) {
		return errNative
	}
	groups, e := os.Getgroups()
	if e != nil || len(groups) != 0 {
		return errNative
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return errNative
	}
	for _, f := range []string{"CapEff", "CapPrm", "CapBnd", "CapAmb"} {
		if !strings.Contains(string(status), f+":\t0000000000000000") {
			return errNative
		}
	}
	if !strings.Contains(string(status), "NoNewPrivs:\t1") || !strings.Contains(string(status), "Seccomp:\t2") {
		return errNative
	}
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil || ns == parentNS || !strings.HasPrefix(parentNS, "net:[") {
		return errNative
	}
	if unix.Unshare(0) != unix.EPERM {
		return errNative
	}
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return errNative
	}
	for _, limit := range []struct {
		kind  int
		value uint64
	}{{unix.RLIMIT_CORE, 0}, {unix.RLIMIT_NOFILE, 128}, {unix.RLIMIT_NPROC, 128}, {unix.RLIMIT_AS, 2 << 30}} {
		if unix.Setrlimit(limit.kind, &unix.Rlimit{Cur: limit.value, Max: limit.value}) != nil {
			return errNative
		}
	}
	// Only descriptor 3 is an external capability. It must not leak through
	// exec to guacd or any of its native children.
	unix.CloseOnExec(3)
	for fd := 4; fd <= 7; fd++ {
		// bwrap may already have consumed its filter FD; Go can reuse that
		// number for its poller. Never close a descriptor by number here.
		// Remaining bootstrap capabilities contain only read-only public data.
		unix.CloseOnExec(fd)
	}
	targetFile := os.NewFile(3, "guarded-rdp-target")
	target, e := net.FileConn(targetFile)
	_ = targetFile.Close()
	if e != nil {
		return errNative
	}
	defer target.Close()
	if _, ok := target.(*net.TCPConn); !ok {
		return errNative
	}
	if _, e = io.WriteString(os.Stdout, rdpWorkerHello); e != nil {
		return errNative
	}
	if info, e := os.Stat("/run/keybash"); e != nil || info.Mode().Perm()&0022 != 0 {
		return errNative
	}
	for _, name := range []string{"/run/keybash/approved.pem", "/run/keybash/name"} {
		if f, e := os.OpenFile(name, os.O_WRONLY, 0); e == nil { // #nosec G304 -- two fixed read-only public trust mounts; a successful write-open is a security refusal.
			_ = f.Close()
			return errNative
		}
	}
	bridge, e := net.Listen("tcp4", "127.0.0.1:3390")
	if e != nil {
		return errNative
	}
	defer bridge.Close()
	guacd := exec.Command("/opt/keybash-rdp/sbin/guacd", "-f", "-b", "127.0.0.1", "-p", "4822", "-L", "error")
	guacd.Env = []string{"LD_LIBRARY_PATH=/opt/keybash-rdp/lib", "HOME=/tmp", "LANG=C.UTF-8", "WLOG_LEVEL=OFF"}
	guacd.Stdout, guacd.Stderr = io.Discard, io.Discard
	guacd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if guacd.Start() != nil {
		return errNative
	}
	done := make(chan struct{})
	go func() { _ = guacd.Wait(); close(done) }()
	defer func() { _ = guacd.Process.Kill(); <-done }()
	go func() {
		local, e := bridge.Accept()
		_ = bridge.Close()
		if e == nil {
			relayRDP(local, target)
		}
	}()
	var guac net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		guac, e = net.DialTimeout("tcp4", "127.0.0.1:4822", 50*time.Millisecond)
		if e == nil {
			break
		}
		select {
		case <-done:
			return errNative
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if guac == nil {
		return errNative
	}
	defer guac.Close()
	if _, e = io.WriteString(os.Stdout, rdpWorkerReady); e != nil {
		return errNative
	}
	finished := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(guac, os.Stdin); _ = guac.Close(); finished <- struct{}{} }()
	go func() { _, _ = io.Copy(os.Stdout, guac); _ = guac.Close(); finished <- struct{}{} }()
	select {
	case <-finished:
	case <-done:
	}
	return nil // private PID namespace/manager kill owns all remaining descendants
}

func relayRDP(a, b net.Conn) {
	copyOne := func(dst, src net.Conn) {
		_, _ = io.CopyBuffer(dst, io.LimitReader(src, 16*1024*1024), make([]byte, 32*1024))
		_ = dst.Close()
		_ = src.Close()
	}
	go copyOne(a, b)
	copyOne(b, a)
}
