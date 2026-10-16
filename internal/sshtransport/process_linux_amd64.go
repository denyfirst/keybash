//go:build linux && amd64

package sshtransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// Root performs namespace setup only. The statically linked child drops to
// real host UID/GID 65534 BEFORE reading any key/remote protocol. A separate
// authenticated privileged manager for an unprivileged gateway is still a gate.
func sandboxSSHArgs(parentNS string) []string {
	return []string{"--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
		"--hostname", "keybash-ssh-worker", "--cap-drop", "ALL", "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP",
		"--clearenv", "--setenv", "GOMAXPROCS", "2", "--setenv", "GOMEMLIMIT", "64MiB", "--setenv", "GOTRACEBACK", "none",
		"--ro-bind", "/usr/bin/setpriv", "/setpriv",
		"--ro-bind", "/usr/lib/x86_64-linux-gnu/libcap-ng.so.0", "/lib/x86_64-linux-gnu/libcap-ng.so.0",
		"--ro-bind", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6",
		"--ro-bind", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2",
		"--ro-bind", "/proc/self/fd/4", "/worker", "--proc", "/proc", "--dev", "/dev", "--remount-ro", "/", "--chdir", "/",
		"--seccomp", "5", "--", "/setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", "/worker", parentNS}
}

// cBPF is applied by bwrap before exec and inherited by every Go thread. It
// denies new sockets, process clones and namespace/introspection APIs. exec
// remains available for the initial static binary; the only executable visible
// in the read-only root is /worker. This is not a syscall allowlist or cgroup.
func sshSeccomp() []byte {
	f := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.AUDIT_ARCH_X86_64},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 0x40000000},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
	}
	for _, call := range []uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4,
		unix.SYS_FORK, unix.SYS_VFORK, unix.SYS_CLONE3, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_IO_URING_SETUP, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_OPEN_BY_HANDLE_AT} {
		f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: call}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	f = append(f,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 3, K: unix.SYS_CLONE},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 1, K: unix.CLONE_THREAD},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.LittleEndian, f)
	return raw.Bytes()
}

func trustedRootPath(path string, executable bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrProcess
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return ErrProcess
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 {
			return ErrProcess
		}
		if info.Mode().Perm()&0022 != 0 && !(current != path && info.IsDir() && info.Mode()&os.ModeSticky != 0) {
			return ErrProcess
		}
		if current == path && (!info.Mode().IsRegular() || executable && info.Mode().Perm()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0) {
			return ErrProcess
		}
		if current == "/" {
			return nil
		}
	}
}

func openWorkerBinary(w ProcessWorker) (*os.File, error) {
	if w.Digest == [32]byte{} || trustedRootPath(w.Path, true) != nil || trustedRootPath("/usr/bin/bwrap", true) != nil || trustedRootPath("/usr/bin/setpriv", true) != nil {
		return nil, ErrProcess
	}
	for _, path := range []string{"/usr/lib/x86_64-linux-gnu/libcap-ng.so.0", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || trustedRootPath(resolved, false) != nil {
			return nil, ErrProcess
		}
	}
	fd, err := unix.Open(w.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrProcess
	}
	f := os.NewFile(uintptr(fd), "approved-worker")
	good := false
	defer func() {
		if !good {
			_ = f.Close()
		}
	}()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 32*1024*1024+1))
	if err != nil || n > 32*1024*1024 || !bytes.Equal(h.Sum(nil), w.Digest[:]) {
		return nil, ErrProcess
	}
	binary, err := elf.NewFile(f)
	if err != nil || binary.Machine != elf.EM_X86_64 || binary.Class != elf.ELFCLASS64 {
		return nil, ErrProcess
	}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return nil, ErrProcess
		}
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, ErrProcess
	}
	good = true
	return f, nil
}

func launchSSHProcess(life, setup context.Context, w ProcessWorker, host string, dial func(context.Context) (net.Conn, error), pin []byte, user string, seed []byte) (*processStream, error) {
	if os.Geteuid() != 0 {
		return nil, ErrProcess
	}
	binary, err := openWorkerBinary(w)
	if err != nil {
		return nil, ErrProcess
	}
	defer binary.Close()
	parentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, ErrProcess
	}
	raw, err := dial(setup)
	if raw != nil {
		defer raw.Close()
	}
	if err != nil || raw == nil || setup.Err() != nil {
		return nil, ErrProcess
	}
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		return nil, ErrProcess
	}
	transport, err := tcp.File()
	if err != nil {
		return nil, ErrProcess
	}
	defer transport.Close()
	filter, filterWriter, err := os.Pipe()
	if err != nil {
		return nil, ErrProcess
	}
	defer filter.Close()
	policy := sshSeccomp()
	_, err = filterWriter.Write(policy)
	_ = filterWriter.Close()
	if err != nil {
		return nil, ErrProcess
	}
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
	ctx, cancel := context.WithCancel(life)
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", sandboxSSHArgs(parentNS)...) // #nosec G204 -- fixed root-owned tool, fixed sandbox flags and inherited descriptors; no secret/browser command arguments.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.ExtraFiles = []*os.File{transport, binary, filter}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = childInput, childOutput, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	if cmd.Start() != nil {
		cancel()
		_ = in.Close()
		_ = out.Close()
		return nil, ErrProcess
	}
	// Parent must not keep child pipe endpoints alive after exec.
	_ = childInput.Close()
	_ = childOutput.Close()
	done := make(chan struct{})
	s := &processStream{ctx: ctx, cancel: cancel, in: in, out: out, done: done}
	s.stdout = processOutput{ctx: ctx, queue: make(chan []byte, 2)}
	s.stderr = processOutput{ctx: ctx, queue: make(chan []byte, 2)}
	context.AfterFunc(ctx, func() { _ = in.Close(); _ = out.Close() })
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	ready := false
	defer func() {
		if !ready {
			_ = s.Close()
		}
	}()
	stopSetup := context.AfterFunc(setup, cancel)
	defer stopSetup()
	deadline, _ := setup.Deadline()
	if out.SetReadDeadline(deadline) != nil || in.SetWriteDeadline(deadline) != nil {
		return nil, ErrProcess
	}
	kind, hello, err := readWorkerFrame(out)
	if err != nil || kind != frameHello || string(hello) != workerHello {
		return nil, ErrProcess
	}
	start := ssh.Marshal(&workerStart{Version: 1, Host: host, User: user, Pin: pin, Seed: seed})
	err = writeWorkerFrame(in, frameStart, start)
	clear(start)
	if err != nil {
		return nil, ErrProcess
	}
	kind, data, err := readWorkerFrame(out)
	if err != nil || kind != frameReady || len(data) != 0 || setup.Err() != nil || ctx.Err() != nil {
		return nil, ErrProcess
	}
	if !stopSetup() || out.SetReadDeadline(time.Time{}) != nil || in.SetWriteDeadline(time.Time{}) != nil {
		return nil, ErrProcess
	}
	go s.demux()
	ready = true
	return s, nil
}

func prepareSSHWorker(parentNS string) error {
	if !strings.HasPrefix(parentNS, "net:[") || len(parentNS) > 64 {
		return ErrProcess
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns == parentNS {
		return ErrProcess
	}
	host, err := os.ReadFile("/proc/sys/kernel/hostname")
	if err != nil || string(host) != "keybash-ssh-worker\n" || os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 || os.Getegid() != 65534 {
		return ErrProcess
	}
	for _, path := range []string{"/etc", "/home", "/usr", "/run"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return ErrProcess
		}
	}
	mode, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	if err != nil || mode != 2 {
		return ErrProcess
	}
	// Behavioral filter check, not just a configured flag. No packet can leave.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	if err != unix.EPERM {
		return ErrProcess
	}
	for _, limit := range []struct {
		resource int
		value    uint64
	}{{unix.RLIMIT_CORE, 0}, {unix.RLIMIT_FSIZE, 0}, {unix.RLIMIT_NOFILE, 64}, {unix.RLIMIT_CPU, 60}, {unix.RLIMIT_NPROC, 128}} {
		if unix.Setrlimit(limit.resource, &unix.Rlimit{Cur: limit.value, Max: limit.value}) != nil {
			return ErrProcess
		}
	}
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return ErrProcess
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ErrProcess
	}
	if !bytes.Contains(status, []byte("NoNewPrivs:\t1")) {
		return ErrProcess
	}
	for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapAmb"} {
		if !bytes.Contains(status, []byte(field+":\t0000000000000000")) {
			return ErrProcess
		}
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 || os.Getuid() != 65534 || os.Getgid() != 65534 {
		return ErrProcess
	}
	return nil
}

// RunProcessWorker refuses outside the exact sandbox before reading credentials.
func RunProcessWorker(parentNS string, input io.ReadCloser, output io.WriteCloser) error {
	if prepareSSHWorker(parentNS) != nil {
		return ErrProcess
	}
	binary := os.NewFile(4, "worker-image")
	image, err := binary.Stat()
	approved, check := os.Stat("/worker")
	if err != nil || check != nil || !os.SameFile(image, approved) {
		return ErrProcess
	}
	_ = binary.Close()
	f := os.NewFile(3, "authorized-tcp")
	if f == nil {
		return ErrProcess
	}
	raw, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return ErrProcess
	}
	if _, ok := raw.(*net.TCPConn); !ok {
		_ = raw.Close()
		return ErrProcess
	}
	if writeWorkerFrame(output, frameHello, []byte(workerHello)) != nil {
		_ = raw.Close()
		return ErrProcess
	}
	return serveSSHWorker(context.Background(), input, output, raw)
}
