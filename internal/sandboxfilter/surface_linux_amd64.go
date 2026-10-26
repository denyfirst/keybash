//go:build linux && amd64

package sandboxfilter

import "golang.org/x/sys/unix"

// KernelSurface lists syscalls neither protocol worker needs whose kernel
// paths are common exploitation primitives (userfaultfd, pidfd and process
// memory access, the new mount API, handle-based opens) or administrative
// operations. Most already need capabilities the workers drop; denying them
// in the filter removes the kernel code path itself from reach. Both filters
// return EPERM for these, like their existing denylist entries.
var KernelSurface = []uint32{
	unix.SYS_USERFAULTFD, unix.SYS_PIDFD_GETFD, unix.SYS_PROCESS_MADVISE, unix.SYS_PROCESS_MRELEASE, unix.SYS_KCMP,
	unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_OPEN_TREE, unix.SYS_OPEN_TREE_ATTR,
	unix.SYS_MOVE_MOUNT, unix.SYS_MOUNT_SETATTR, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_CHROOT,
	unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_FANOTIFY_INIT,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_REBOOT, unix.SYS_ACCT, unix.SYS_QUOTACTL, unix.SYS_QUOTACTL_FD,
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_SYSLOG, unix.SYS_VHANGUP,
	unix.SYS_LOOKUP_DCOOKIE, unix.SYS_USELIB,
}
