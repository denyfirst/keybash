//go:build linux && amd64

package rdplab

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func rdpPacketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
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

func rdpTestPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("pipe failed")
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

func TestRDPManagerPacketsBoundRightsAndPeer(t *testing.T) {
	a, b := rdpPacketPair(t)
	cred, err := rdpPeerCredentials(a)
	if err != nil || cred.Uid != uint32(os.Getuid()) || cred.Gid != uint32(os.Getgid()) {
		t.Fatal("kernel peer identity changed")
	}
	r, _ := rdpTestPipe(t)
	if writeRDPPacket(a, managerStart, r, r, r, r, r) != nil {
		t.Fatal("valid manager packet refused")
	}
	packet, files, err := recvRDPPacket(b)
	defer closeRDPFiles(files)
	if err != nil || packet != managerStart || len(files) != 5 {
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
	}{{string(bytes.Repeat([]byte("x"), 65)), nil}, {managerStart, []*os.File{r, r, r, r, r, r, r}}, {"", nil}} {
		if writeRDPPacket(a, bad.data, bad.fds...) != nil {
			t.Fatal("malformed fixture send failed")
		}
		if _, leaked, err := recvRDPPacket(b); err == nil || len(leaked) != 0 {
			closeRDPFiles(leaked)
			t.Fatal("truncated or empty manager packet accepted")
		}
	}
	if writeRDPPacket(a, managerHello, r) != nil || expectRDPPacket(b, managerHello) == nil {
		t.Fatal("unexpected manager reply capabilities accepted")
	}
	if writeRDPPacket(a, managerStart) != nil || expectRDPPacket(b, managerHello) == nil {
		t.Fatal("unexpected manager reply schema accepted")
	}
}

func TestRDPManagerDescriptorKindsAndSealedTrust(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	c, e := net.Dial("tcp4", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	peer, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	tcp, e := c.(*net.TCPConn).File()
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	in, inWrite := rdpTestPipe(t)
	outRead, out := rdpTestPipe(t)
	cert, e := sealedRDPFile([]byte("public fixture certificate"))
	if e != nil {
		t.Fatal(e)
	}
	defer cert.Close()
	name, e := sealedRDPFile([]byte("synthetic.invalid"))
	if e != nil {
		t.Fatal(e)
	}
	defer name.Close()
	good := []*os.File{tcp, in, out, cert, name}
	if !validManagerFiles(good) {
		t.Fatal("valid sealed RDP capabilities refused")
	}
	regular, e := os.CreateTemp(t.TempDir(), "unsealed")
	if e != nil {
		t.Fatal(e)
	}
	defer regular.Close()
	for _, bad := range [][]*os.File{nil, {tcp, in, out, cert}, {tcp, in, out, cert, name, name}, {regular, in, out, cert, name}, {tcp, inWrite, out, cert, name}, {tcp, in, outRead, cert, name}, {tcp, in, inWrite, cert, name}, {tcp, in, out, regular, name}, {tcp, in, out, cert, regular}} {
		if validManagerFiles(bad) {
			t.Fatal("unsafe RDP descriptor or unsealed trust accepted")
		}
	}
}
