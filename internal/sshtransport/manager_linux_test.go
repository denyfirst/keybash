//go:build linux && amd64

package sshtransport

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func managerSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("socket pair failed")
	}
	connections := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "test-control")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal("socket import failed")
		}
		connections[i] = conn.(*net.UnixConn)
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	}
	return connections[0], connections[1]
}

func testManagerPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

func TestSSHManagerPacketsBoundRightsAndPeer(t *testing.T) {
	a, b := managerSocketPair(t)
	cred, err := peerCredentials(a)
	if err != nil || cred.Uid != uint32(os.Getuid()) || cred.Gid != uint32(os.Getgid()) {
		t.Fatal("kernel peer identity changed")
	}
	r, _ := testManagerPipe(t)
	if writeManagerPacket(a, managerStart, r, r, r) != nil {
		t.Fatal("valid manager packet refused")
	}
	packet, files, err := recvManagerPacket(b)
	defer closeManagerFiles(files)
	if err != nil || packet != managerStart || len(files) != 3 {
		t.Fatal("valid manager packet changed")
	}
	for _, f := range files {
		flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		if e != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("received capability can leak across exec")
		}
	}
	for _, bad := range []struct {
		data string
		fds  []*os.File
	}{{string(bytes.Repeat([]byte("x"), 65)), nil}, {managerStart, []*os.File{r, r, r, r, r}}, {"", nil}} {
		if writeManagerPacket(a, bad.data, bad.fds...) != nil {
			t.Fatal("malformed fixture send failed")
		}
		if _, leaked, err := recvManagerPacket(b); err == nil || len(leaked) != 0 {
			closeManagerFiles(leaked)
			t.Fatal("truncated or empty manager packet accepted")
		}
	}
	if writeManagerPacket(a, managerHello, r) != nil || expectManagerPacket(b, managerHello) == nil {
		t.Fatal("unexpected manager reply capabilities accepted")
	}
	if writeManagerPacket(a, managerStart) != nil || expectManagerPacket(b, managerHello) == nil {
		t.Fatal("unexpected manager reply schema accepted")
	}
}

func TestSSHManagerDescriptorKinds(t *testing.T) {
	host, user := syntheticSigner(t), syntheticSigner(t)
	f := newFixture(t, fixtureOptions{host: host, user: user})
	tcp, err := f.client.(*net.TCPConn).File()
	if err != nil {
		t.Fatal("TCP export failed")
	}
	defer tcp.Close()
	in, inWrite := testManagerPipe(t)
	outRead, out := testManagerPipe(t)
	valid := []*os.File{tcp, in, out}
	if !validManagerFiles(valid) {
		t.Fatal("valid manager descriptors refused")
	}
	regular, err := os.CreateTemp(t.TempDir(), "not-a-pipe")
	if err != nil {
		t.Fatal("file fixture failed")
	}
	defer regular.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listener fixture failed")
	}
	defer listener.Close()
	listening, err := listener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal("listener export failed")
	}
	defer listening.Close()
	for _, bad := range [][]*os.File{nil, {tcp, in}, {tcp, in, out, out}, {regular, in, out}, {listening, in, out}, {tcp, regular, out}, {tcp, inWrite, out}, {tcp, in, outRead}, {tcp, in, inWrite}} {
		if validManagerFiles(bad) {
			t.Fatal("unsafe manager descriptors accepted")
		}
	}
}
