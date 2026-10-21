//go:build linux && amd64

package rdplab

import (
	"context"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	managerHello  = "keybash-rdp-manager/v1"
	managerStart  = "start/v1"
	managerActive = "active/v1"
	managerCancel = "cancel/v1"
	managerDone   = "done/v1"
)

func rdpPeerCredentials(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, errNative
	}
	var cred *unix.Ucred
	var check error
	err = raw.Control(func(fd uintptr) { cred, check = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || check != nil || cred == nil {
		return nil, errNative
	}
	return cred, nil
}

// recvRDPPacket atomically receives one bounded seqpacket and rights buffer
// (alignment can fit six FDs; launch admits exactly five). CLOEXEC is set by
// recvmsg itself, including during exec in other goroutines. Every received FD is owned and closed even on refusal.
func recvRDPPacket(c *net.UnixConn) (string, []*os.File, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", nil, errNative
	}
	var data [64]byte
	oob := make([]byte, unix.CmsgSpace(5*4))
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
	files := make([]*os.File, 0, 5)
	messages, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
	for _, message := range messages {
		rights, e := unix.ParseUnixRights(&message)
		if e != nil {
			parseErr = errNative
			continue
		}
		for _, fd := range rights {
			files = append(files, os.NewFile(uintptr(fd), "session-capability"))
		}
	}
	if err != nil || readErr != nil || parseErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == 0 {
		closeRDPFiles(files)
		return "", nil, errNative
	}
	return string(data[:n]), files, nil
}

func closeRDPFiles(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}

func writeRDPPacket(c *net.UnixConn, packet string, files ...*os.File) error {
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
		return errNative
	}
	return nil
}

func expectRDPPacket(c *net.UnixConn, expected string) error {
	packet, files, err := recvRDPPacket(c)
	defer closeRDPFiles(files)
	if err != nil || packet != expected || len(files) != 0 {
		return errNative
	}
	return nil
}

func rdpManagerDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 || filepath.Base(path) == "." {
		return errNative
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errNative
	}
	// Unlike the executable checker, this leaf must be a root-owned directory.
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errNative
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 && !(current != dir && info.Mode()&os.ModeSticky != 0) {
			return errNative
		}
		if current == "/" {
			return nil
		}
	}
}

// ServeRDPManager has no TCP listener, browser API, vault access, dial, credential
// parser, command selection or caller-selected image. The exact authorized
// gateway UID/GID may request a bounded number of fixed sandbox launches.
func ServeRDPManager(ctx context.Context, config ManagerConfig) error {
	capacity := config.MaxSessions
	if !config.valid() || ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || rdpManagerDirectory(config.SocketPath) != nil {
		return errNative
	}
	binary, err := openRDPImage(config)
	if err != nil {
		return errNative
	}
	_ = binary.Close()
	// Do not unlink an existing path, including a stale socket. A second
	// manager or restart must never replace a live listener silently.
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: config.SocketPath, Net: "unixpacket"})
	if err != nil {
		return errNative
	}
	defer listener.Close()
	if os.Chown(config.SocketPath, 0, int(config.GatewayGID)) != nil || os.Chmod(config.SocketPath, 0660) != nil { // #nosec G302 -- dedicated gateway primary group needs connect; root owns the non-writable parent, kernel UID/GID admission remains mandatory.
		return errNative
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel() // cancel active leases before waiting, including accept errors.
	slots := make(chan struct{}, capacity)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errNative
		}
		cred, err := rdpPeerCredentials(conn)
		if err != nil || cred.Uid != config.GatewayUID || cred.Gid != config.GatewayGID {
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			workers.Go(func() { defer func() { <-slots }(); serveRDPLease(ctx, conn, config) })
		default:
			_ = conn.Close()
		}
	}
}

func validManagerFiles(files []*os.File) bool {
	if len(files) != 5 {
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
	for i, f := range files[1:3] {
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
	for i, limit := range []int64{65536, 253} {
		fd := files[i+3]
		var st unix.Stat_t
		seals, e := unix.FcntlInt(fd.Fd(), unix.F_GET_SEALS, 0)
		required := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
		if e != nil || seals&required != required || unix.Fstat(int(fd.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 1 || st.Size > limit {
			return false
		}
	}
	return pipes[0].Dev != pipes[1].Dev || pipes[0].Ino != pipes[1].Ino
}

func serveRDPLease(life context.Context, conn *net.UnixConn, w ManagerConfig) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(life)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if conn.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		return
	}
	binary, err := openRDPImage(w)
	if err != nil {
		return
	}
	defer binary.Close()
	if writeRDPPacket(conn, managerHello) != nil {
		return
	}
	packet, files, err := recvRDPPacket(conn)
	defer closeRDPFiles(files)
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
	_, err = writer.Write(rdpSeccomp())
	_ = writer.Close()
	if err != nil {
		return
	}
	_, kill, done, err := startRDPProcess(ctx, parentNS, w, files[0], binary, filter, files[1], files[2], files[3], files[4])
	if err != nil {
		return
	}
	defer kill()
	// No inherited session descriptor remains in the root manager.
	closeRDPFiles(files)
	if writeRDPPacket(conn, managerActive) != nil || conn.SetDeadline(time.Time{}) != nil {
		kill()
		<-done
		return
	}
	monitor := make(chan struct{})
	go func() {
		defer close(monitor)
		// Any extra packet (including repeated start), rights, EOF or malformed
		// cancellation terminates this lease; none can launch a second child.
		_ = expectRDPPacket(conn, managerCancel)
		kill()
	}()
	<-done
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = writeRDPPacket(conn, managerDone)
	_ = conn.Close()
	<-monitor
}

func connectRDPManager(life, setup context.Context, path string, dial func(context.Context) (net.Conn, error), pin *Identity) (net.Conn, error) {
	// The public gateway must never run as root or the sandbox's worker UID.
	if os.Geteuid() == 0 || os.Geteuid() == 65534 || rdpManagerDirectory(path) != nil {
		return nil, errNative
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		return nil, errNative
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errNative
	}
	connection, err := (&net.Dialer{}).DialContext(setup, "unixpacket", path)
	if err != nil {
		return nil, errNative
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errNative
	}
	owned := true
	defer func() {
		if owned {
			_ = conn.Close()
		}
	}()
	cred, err := rdpPeerCredentials(conn)
	deadline, _ := setup.Deadline()
	if err != nil || cred.Uid != 0 || conn.SetDeadline(deadline) != nil || expectRDPPacket(conn, managerHello) != nil {
		return nil, errNative
	}
	stop := context.AfterFunc(setup, func() { _ = conn.Close() })
	defer stop()
	raw, err := dial(setup)
	if raw != nil {
		defer raw.Close()
	}
	tcp, ok := raw.(*net.TCPConn)
	if err != nil || !ok || tcp == nil || setup.Err() != nil {
		return nil, errNative
	}
	transport, err := tcp.File()
	if err != nil {
		return nil, errNative
	}
	defer transport.Close()
	childInput, in, err := os.Pipe()
	if err != nil {
		return nil, errNative
	}
	defer childInput.Close()
	out, childOutput, err := os.Pipe()
	if err != nil {
		_ = in.Close()
		return nil, errNative
	}
	defer childOutput.Close()
	certFile, err := sealedRDPFile(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pin.der}))
	if err != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, errNative
	}
	defer certFile.Close()
	nameFile, err := sealedRDPFile([]byte(pin.name))
	if err != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, errNative
	}
	defer nameFile.Close()
	if writeRDPPacket(conn, managerStart, transport, childInput, childOutput, certFile, nameFile) != nil || expectRDPPacket(conn, managerActive) != nil || !stop() || conn.SetDeadline(time.Time{}) != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, errNative
	}
	_ = childInput.Close()
	_ = childOutput.Close()
	ctx, cancel := context.WithCancel(life)
	done := make(chan struct{})
	s := newRDPConnection(ctx, cancel, in, out, done)
	stopLife := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = writeRDPPacket(conn, managerCancel)
	})
	go func() {
		defer close(done)
		defer conn.Close()
		defer stopLife()
		if expectRDPPacket(conn, managerDone) != nil {
			cancel() // manager crash/disappearance revokes buffered output too.
		}
	}()
	owned = false
	if finishRDPSetup(s, setup) != nil {
		_ = s.Close()
		return nil, errNative
	}
	return s, nil
}

func sealedRDPFile(data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("keybash-public-trust", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errNative
	}
	f := os.NewFile(uintptr(fd), "public-trust")
	if n, e := f.Write(data); e != nil || n != len(data) {
		_ = f.Close()
		return nil, errNative
	}
	if _, e := f.Seek(0, 0); e != nil {
		_ = f.Close()
		return nil, errNative
	}
	if _, e := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); e != nil {
		_ = f.Close()
		return nil, errNative
	}
	return f, nil
}
