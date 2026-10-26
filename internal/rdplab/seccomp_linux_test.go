//go:build linux && amd64

package rdplab

import (
	"testing"

	"github.com/denyfirst/keybash/internal/sandboxfilter"
	"golang.org/x/sys/unix"
)

// The native RDP filter is evaluated instruction by instruction. guacd and
// FreeRDP keep loopback sockets, forks and threads; namespace creation and
// the shared kernel surface stay denied; foreign architectures die.
func TestRDPSeccompDecisions(t *testing.T) {
	filter := rdpSeccomp()
	const kill, allow = uint32(unix.SECCOMP_RET_KILL_PROCESS), uint32(unix.SECCOMP_RET_ALLOW)
	eperm := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	enosys := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.ENOSYS)
	check := func(what string, data sandboxfilter.Data, want uint32) {
		t.Helper()
		if got, err := sandboxfilter.Evaluate(filter, data); err != nil || got != want {
			t.Fatalf("%s: got %#x (%v), want %#x", what, got, err, want)
		}
	}
	call := func(nr uint32, args ...uint64) sandboxfilter.Data {
		d := sandboxfilter.Data{Nr: nr, Arch: unix.AUDIT_ARCH_X86_64}
		copy(d.Args[:], args)
		return d
	}
	check("foreign architecture", sandboxfilter.Data{Nr: unix.SYS_READ, Arch: unix.AUDIT_ARCH_I386}, kill)
	check("x32 numbering", call(0x40000000|unix.SYS_READ), kill)
	for _, nr := range kernelSurface {
		check("kernel surface", call(nr), eperm)
	}
	// Named explicitly so shrinking the shared list cannot pass by iteration.
	for _, nr := range []uint32{unix.SYS_USERFAULTFD, unix.SYS_PIDFD_GETFD, unix.SYS_PROCESS_MADVISE, unix.SYS_KCMP, unix.SYS_FSOPEN,
		unix.SYS_FSMOUNT, unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_MOUNT_SETATTR, unix.SYS_NAME_TO_HANDLE_AT,
		unix.SYS_KEXEC_LOAD, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_IO_URING_ENTER, unix.SYS_CHROOT} {
		check("critical kernel surface", call(nr), eperm)
	}
	for _, nr := range []uint32{unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_MOUNT,
		unix.SYS_PIVOT_ROOT, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_IO_URING_SETUP, unix.SYS_KEYCTL, unix.SYS_OPEN_BY_HANDLE_AT} {
		check("existing denial", call(nr), eperm)
	}
	check("clone3 falls back", call(unix.SYS_CLONE3), enosys)
	for _, flag := range []uint64{unix.CLONE_NEWNS, unix.CLONE_NEWUTS, unix.CLONE_NEWIPC, unix.CLONE_NEWUSER, unix.CLONE_NEWPID, unix.CLONE_NEWNET, unix.CLONE_NEWCGROUP} {
		check("namespace clone", call(unix.SYS_CLONE, uint64(unix.SIGCHLD)|flag), eperm)
	}
	check("process clone", call(unix.SYS_CLONE, uint64(unix.SIGCHLD)), allow)
	check("thread clone", call(unix.SYS_CLONE, unix.CLONE_VM|unix.CLONE_THREAD|unix.CLONE_SIGHAND), allow)
	for _, nr := range []uint32{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_SOCKET, unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN,
		unix.SYS_ACCEPT4, unix.SYS_POLL, unix.SYS_SELECT, unix.SYS_MMAP, unix.SYS_FUTEX, unix.SYS_EXECVE, unix.SYS_WAIT4,
		unix.SYS_EXIT_GROUP, unix.SYS_OPENAT, unix.SYS_GETRANDOM, unix.SYS_PRCTL} {
		check("required call", call(nr), allow)
	}
}
