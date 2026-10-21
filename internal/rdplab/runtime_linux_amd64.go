//go:build linux && amd64

package rdplab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func rdpRootPath(path string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errNative
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return errNative
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0022 != 0 && !(current != path && info.Mode()&os.ModeSticky != 0) {
			return errNative
		}
		if current == path && !directory {
			if !info.Mode().IsRegular() || st.Nlink != 1 || info.Mode().Perm()&0111 == 0 || info.Size() < 1 || info.Size() > 32*1024*1024 {
				return errNative
			}
		} else if !info.IsDir() {
			return errNative
		}
		if current == "/" {
			return nil
		}
	}
}

// RuntimeInventory never follows symlinks. Its canonical ordered inventory binds
// the entire loader/plugin/library closure, including permissions. Root may
// replace an approved deployment; a hostile host administrator is not excluded.
func RuntimeInventory(path string) ([32]byte, error) {
	var zero [32]byte
	if rdpRootPath(path, true) != nil {
		return zero, errNative
	}
	h := sha256.New()
	count, total := 0, int64(0)
	required := map[string]bool{"opt/keybash-rdp/sbin/guacd": false, "opt/keybash-rdp/lib/libguac-client-rdp.so": false, "lib64/ld-linux-x86-64.so.2": false, "setpriv": false, "worker": false, "run/keybash/approved.pem": false, "run/keybash/name": false}
	directories := map[string]bool{"proc": false, "dev": false, "tmp": false, "run/keybash": false}
	err := filepath.WalkDir(path, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errNative
		}
		rel, err := filepath.Rel(path, name)
		if err != nil {
			return errNative
		}
		for _, r := range rel {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._+-", r)) {
				return errNative
			}
		}
		info, err := entry.Info()
		if err != nil {
			return errNative
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errNative
		}
		count++
		if count > 1024 {
			return errNative
		}
		if info.IsDir() {
			_, _ = io.WriteString(h, rel+" "+strconv.FormatUint(uint64(info.Mode().Perm()), 8)+" directory\n")
			if _, ok := directories[rel]; ok {
				directories[rel] = true
			}
			return nil
		}
		if !info.Mode().IsRegular() || st.Nlink != 1 || info.Size() < 1 || info.Size() > 64*1024*1024 {
			return errNative
		}
		total += info.Size()
		if total > 512*1024*1024 {
			return errNative
		}
		fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return errNative
		}
		file := os.NewFile(uintptr(fd), "runtime-inventory")
		fileHash := sha256.New()
		n, copyErr := io.Copy(fileHash, io.LimitReader(file, info.Size()+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || n != info.Size() {
			return errNative
		}
		_, _ = io.WriteString(h, rel+" "+strconv.FormatUint(uint64(info.Mode().Perm()), 8)+" "+hex.EncodeToString(fileHash.Sum(nil))+"\n")
		if _, ok := required[rel]; ok {
			required[rel] = true
		}
		return nil
	})
	for _, present := range required {
		if !present {
			return zero, errNative
		}
	}
	for _, present := range directories {
		if !present {
			return zero, errNative
		}
	}
	if err != nil {
		return zero, errNative
	}
	copy(zero[:], h.Sum(nil))
	return zero, nil
}

func openRDPImage(c ManagerConfig) (*os.File, error) {
	if !c.valid() || rdpRootPath(c.WorkerPath, false) != nil {
		return nil, errNative
	}
	digest, err := RuntimeInventory(c.Runtime)
	if err != nil || digest != c.RuntimeDigest {
		return nil, errNative
	}
	fd, err := unix.Open(c.WorkerPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errNative
	}
	f := os.NewFile(uintptr(fd), "approved-rdp-worker")
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 32*1024*1024+1))
	if err != nil || n > 32*1024*1024 || !bytes.Equal(h.Sum(nil), c.WorkerDigest[:]) {
		return nil, errNative
	}
	image, err := elf.NewFile(f)
	if err != nil || image.Machine != elf.EM_X86_64 || image.Class != elf.ELFCLASS64 {
		return nil, errNative
	}
	for _, p := range image.Progs {
		if p.Type == elf.PT_INTERP {
			return nil, errNative
		}
	}
	if _, err = f.Seek(0, 0); err != nil {
		return nil, errNative
	}
	ok = true
	return f, nil
}

func rdpSandboxArgs(parent string, c ManagerConfig) []string {
	u, g := strconv.FormatUint(uint64(c.WorkerUID), 10), strconv.FormatUint(uint64(c.WorkerGID), 10)
	return []string{"--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
		"--hostname", "keybash-rdp-worker", "--cap-drop", "ALL", "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP",
		"--clearenv", "--setenv", "GOMAXPROCS", "2", "--setenv", "GOMEMLIMIT", "64MiB", "--setenv", "GOTRACEBACK", "none",
		"--ro-bind", c.Runtime, "/",
		"--ro-bind", "/proc/self/fd/4", "/worker",
		// memfds have no realpath. Let bwrap consume the sealed public bytes
		// directly into private read-only mounts, never host trust files.
		"--dir", "/run/keybash", "--perms", "0444", "--ro-bind-data", "6", "/run/keybash/approved.pem", "--perms", "0444", "--ro-bind-data", "7", "/run/keybash/name",
		"--proc", "/proc", "--dev", "/dev", "--perms", "1777", "--tmpfs", "/tmp", "--remount-ro", "/", "--chdir", "/",
		"--seccomp", "5", "--", "/setpriv", "--reuid=" + u, "--regid=" + g, "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", "/worker", parent, u, g}
}

// This is a denylist, not a syscall allowlist. The private network deliberately
// permits native loopback sockets. The only external transport is inherited FD3.
func rdpSeccomp() []byte {
	f := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.AUDIT_ARCH_X86_64},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 0x40000000},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
	}
	for _, call := range []uint32{unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_IO_URING_SETUP, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_OPEN_BY_HANDLE_AT} {
		f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: call}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	// libc can fall back to clone when clone3 is explicitly unavailable.
	f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_CLONE3}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)})
	// Native fork/thread creation is needed; namespace creation never is.
	f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 3, K: unix.SYS_CLONE}, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16}, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jf: 1, K: unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.LittleEndian, f)
	return raw.Bytes()
}

func startRDPProcess(life context.Context, parent string, c ManagerConfig, transport, image, filter, input, output, cert, name *os.File) (context.Context, context.CancelFunc, <-chan struct{}, error) {
	ctx, cancel := context.WithCancel(life)
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", rdpSandboxArgs(parent, c)...) // #nosec G204 -- fixed root tool and validated operator configuration; no IPC commands or credentials.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.ExtraFiles = []*os.File{transport, image, filter, cert, name}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	cmd.WaitDelay = time.Second
	done, started := make(chan struct{}), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		err := cmd.Start()
		started <- err
		if err == nil {
			_ = cmd.Wait()
		}
	}()
	if <-started != nil {
		cancel()
		return nil, nil, nil, errNative
	}
	_ = input.Close()
	_ = output.Close()
	return ctx, cancel, done, nil
}
