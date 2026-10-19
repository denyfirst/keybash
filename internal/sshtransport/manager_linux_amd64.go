//go:build linux && amd64

package sshtransport

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	managerHello  = "keybash-ssh-manager/v1"
	managerStart  = "start/v1"
	managerActive = "active/v1"
	managerCancel = "cancel/v1"
	managerDone   = "done/v1"
	managerSlots  = 8
)

func peerCredentials(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, ErrProcess
	}
	var cred *unix.Ucred
	var check error
	err = raw.Control(func(fd uintptr) { cred, check = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || check != nil || cred == nil {
		return nil, ErrProcess
	}
	return cred, nil
}

// recvManagerPacket atomically receives one bounded seqpacket and rights buffer
// (alignment can fit four FDs; launch admits exactly three). CLOEXEC is set by
// recvmsg itself, including during exec
// in other goroutines. Every received FD is owned and closed even on refusal.
func recvManagerPacket(c *net.UnixConn) (string, []*os.File, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", nil, ErrProcess
	}
	var data [64]byte
	oob := make([]byte, unix.CmsgSpace(3*4))
	var n, oobn, flags int
	var readErr error
	err = raw.Read(func(fd uintptr) bool {
		for {
			n, oobn, flags, _, readErr = unix.Recvmsg(int(fd), data[:], oob, unix.MSG_CMSG_CLOEXEC)
			if readErr != unix.EINTR {
				return readErr != unix.EAGAIN && readErr != unix.EWOULDBLOCK
			}
		}
	})
	files := make([]*os.File, 0, 3)
	messages, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
	for _, message := range messages {
		rights, e := unix.ParseUnixRights(&message)
		if e != nil {
			parseErr = ErrProcess
			continue
		}
		for _, fd := range rights {
			files = append(files, os.NewFile(uintptr(fd), "session-capability"))
		}
	}
	if err != nil || readErr != nil || parseErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == 0 {
		closeManagerFiles(files)
		return "", nil, ErrProcess
	}
	return string(data[:n]), files, nil
}

func closeManagerFiles(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}

func writeManagerPacket(c *net.UnixConn, packet string, files ...*os.File) error {
	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}
	var rights []byte
	if len(fds) != 0 {
		rights = unix.UnixRights(fds...)
	}
	n, oobn, err := c.WriteMsgUnix([]byte(packet), rights, nil)
	if err != nil || n != len(packet) || oobn != len(rights) {
		return ErrProcess
	}
	return nil
}

func expectManagerPacket(c *net.UnixConn, expected string) error {
	packet, files, err := recvManagerPacket(c)
	defer closeManagerFiles(files)
	if err != nil || packet != expected || len(files) != 0 {
		return ErrProcess
	}
	return nil
}

func managerDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || filepath.Base(path) == "." {
		return ErrProcess
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return ErrProcess
	}
	// Unlike the executable checker, this leaf must be a root-owned directory.
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrProcess
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 && !(current != dir && info.Mode()&os.ModeSticky != 0) {
			return ErrProcess
		}
		if current == "/" {
			return nil
		}
	}
}

// ServeSSHManager has no TCP listener, browser API, vault access, dial, key
// parser, command selection or caller-selected image. The exact authorized
// gateway UID/GID may request eight fixed sandbox launches using passed FDs.
func ServeSSHManager(ctx context.Context, config ManagerConfig) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || config.GatewayUID == 0 || config.GatewayGID == 0 || config.GatewayUID == 65534 || managerDirectory(config.SocketPath) != nil {
		return ErrProcess
	}
	binary, err := openWorkerBinary(config.Worker)
	if err != nil {
		return ErrProcess
	}
	_ = binary.Close()
	// Do not unlink an existing path, including a stale socket. A second
	// manager or restart must never replace a live listener silently.
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: config.SocketPath, Net: "unixpacket"})
	if err != nil {
		return ErrProcess
	}
	defer listener.Close()
	if os.Chown(config.SocketPath, 0, int(config.GatewayGID)) != nil || os.Chmod(config.SocketPath, 0660) != nil { // #nosec G302 -- dedicated gateway primary group needs connect; root owns the non-writable parent, kernel UID/GID admission remains mandatory.
		return ErrProcess
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel() // cancel active leases before waiting, including accept errors.
	slots := make(chan struct{}, managerSlots)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrProcess
		}
		cred, err := peerCredentials(conn)
		if err != nil || cred.Uid != config.GatewayUID || cred.Gid != config.GatewayGID {
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			workers.Go(func() { defer func() { <-slots }(); serveManagerLease(ctx, conn, config.Worker) })
		default:
			_ = conn.Close()
		}
	}
}

func validManagerFiles(files []*os.File) bool {
	if len(files) != 3 {
		return false
	}
	tcp := int(files[0].Fd())
	domain, e1 := unix.GetsockoptInt(tcp, unix.SOL_SOCKET, unix.SO_DOMAIN)
	kind, e2 := unix.GetsockoptInt(tcp, unix.SOL_SOCKET, unix.SO_TYPE)
	protocol, e3 := unix.GetsockoptInt(tcp, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	_, e4 := unix.Getpeername(tcp)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || domain != unix.AF_INET && domain != unix.AF_INET6 || kind != unix.SOCK_STREAM || protocol != unix.IPPROTO_TCP {
		return false
	}
	var pipes [2]unix.Stat_t
	for i, f := range files[1:] {
		fd := int(f.Fd())
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		mode := unix.O_RDONLY
		if i == 1 {
			mode = unix.O_WRONLY
		}
		if err != nil || flags&unix.O_ACCMODE != mode || unix.Fstat(fd, &pipes[i]) != nil || pipes[i].Mode&unix.S_IFMT != unix.S_IFIFO {
			return false
		}
	}
	return pipes[0].Dev != pipes[1].Dev || pipes[0].Ino != pipes[1].Ino
}

func serveManagerLease(life context.Context, conn *net.UnixConn, w ProcessWorker) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(life)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if conn.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		return
	}
	binary, err := openWorkerBinary(w)
	if err != nil {
		return
	}
	defer binary.Close()
	if writeManagerPacket(conn, managerHello) != nil {
		return
	}
	packet, files, err := recvManagerPacket(conn)
	defer closeManagerFiles(files)
	if err != nil || packet != managerStart || !validManagerFiles(files) {
		return
	}
	parentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return
	}
	filter, writer, err := os.Pipe()
	if err != nil {
		return
	}
	defer filter.Close()
	_, err = writer.Write(sshSeccomp())
	_ = writer.Close()
	if err != nil {
		return
	}
	_, kill, done, err := startSSHProcess(ctx, parentNS, files[0], binary, filter, files[1], files[2])
	if err != nil {
		return
	}
	defer kill()
	// No inherited session descriptor remains in the root manager.
	closeManagerFiles(files)
	if writeManagerPacket(conn, managerActive) != nil || conn.SetDeadline(time.Time{}) != nil {
		kill()
		<-done
		return
	}
	monitor := make(chan struct{})
	go func() {
		defer close(monitor)
		// Any extra packet (including repeated start), rights, EOF or malformed
		// cancellation terminates this lease; none can launch a second child.
		_ = expectManagerPacket(conn, managerCancel)
		kill()
	}()
	<-done
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = writeManagerPacket(conn, managerDone)
	_ = conn.Close()
	<-monitor
}

func connectSSHManager(life, setup context.Context, path, host string, dial func(context.Context) (net.Conn, error), pin []byte, user string, seed []byte) (*processStream, error) {
	// The public gateway must never run as root or the sandbox's worker UID.
	if os.Geteuid() == 0 || os.Geteuid() == 65534 || managerDirectory(path) != nil {
		return nil, ErrProcess
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		return nil, ErrProcess
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, ErrProcess
	}
	connection, err := (&net.Dialer{}).DialContext(setup, "unixpacket", path)
	if err != nil {
		return nil, ErrProcess
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, ErrProcess
	}
	owned := true
	defer func() {
		if owned {
			_ = conn.Close()
		}
	}()
	cred, err := peerCredentials(conn)
	deadline, _ := setup.Deadline()
	if err != nil || cred.Uid != 0 || conn.SetDeadline(deadline) != nil || expectManagerPacket(conn, managerHello) != nil {
		return nil, ErrProcess
	}
	stop := context.AfterFunc(setup, func() { _ = conn.Close() })
	defer stop()
	raw, err := dial(setup)
	if raw != nil {
		defer raw.Close()
	}
	tcp, ok := raw.(*net.TCPConn)
	if err != nil || !ok || tcp == nil || setup.Err() != nil {
		return nil, ErrProcess
	}
	transport, err := tcp.File()
	if err != nil {
		return nil, ErrProcess
	}
	defer transport.Close()
	childInput, in, err := os.Pipe()
	if err != nil {
		return nil, ErrProcess
	}
	defer childInput.Close()
	out, childOutput, err := os.Pipe()
	if err != nil {
		_ = in.Close()
		return nil, ErrProcess
	}
	defer childOutput.Close()
	if writeManagerPacket(conn, managerStart, transport, childInput, childOutput) != nil || expectManagerPacket(conn, managerActive) != nil || !stop() || conn.SetDeadline(time.Time{}) != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, ErrProcess
	}
	_ = childInput.Close()
	_ = childOutput.Close()
	ctx, cancel := context.WithCancel(life)
	done := make(chan struct{})
	s := newProcessStream(ctx, cancel, in, out, done)
	stopLife := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = writeManagerPacket(conn, managerCancel)
	})
	go func() {
		defer close(done)
		defer conn.Close()
		defer stopLife()
		if expectManagerPacket(conn, managerDone) != nil {
			cancel() // manager crash/disappearance revokes buffered output too.
		}
	}()
	owned = false
	if finishProcessSetup(s, setup, host, pin, user, seed) != nil {
		_ = s.Close()
		return nil, ErrProcess
	}
	return s, nil
}
