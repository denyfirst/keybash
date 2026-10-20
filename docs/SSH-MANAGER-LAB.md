# Separate SSH launch manager

20 October update: finite slot capacity is now selected through the same
root-owned `--config` catalog as the SSH gateway; omission keeps eight slots.
See `SESSION-CAPACITY.md` for ranges, accounting, tests and remaining kernel
resource/service gates. Session private keys still bypass manager parsing.

19 October 2026. Source-only Linux/amd64 laboratory boundary. The custody CLI
now has a separate operator-catalog SSH integration flag (`OPERATOR-CATALOG-LAB.md`). No installer,
production service, real credential, image or release is introduced.

## Authority and data flow

`ManagerWorker` implements the existing owned-session SSH interface in an
unprivileged gateway. `cmd/keybash-ssh-manager` is a separate root process with
administrator-fixed socket path, gateway UID/primary GID, worker path and SHA256.
It has no TCP listener, target resolver, vault input or caller-selected command,
image, mount, digest, UID or sandbox flags. Runtime assets remain local.

The listener uses Unix SOCK_SEQPACKET. Its parent and ancestors must be root
owned, non-symlink and non-writable by the gateway. Root-owned sticky ancestors
are allowed only above the immediate parent, for the disposable CI directory.
The socket is root-owned mode 0660 with the dedicated gateway group. Only the
exact nonzero configured UID **and primary GID** pass kernel SO_PEERCRED checks;
membership in the group alone is insufficient. Root is not a gateway identity.
The gateway verifies the root-owned socket and the manager's kernel UID before
dialing the target or handing off descriptors. UID 65534 is reserved for the
existing sandbox worker and cannot run the gateway.

The authenticated manager hello reserves a configured pending/active slot (default eight).
The gateway uses `NamedTarget.DialContext` and transfers exactly three FDs in
one fixed `start/v1` packet: the already connected internet TCP stream, the
worker input pipe's read end, and its distinct output pipe's write end. Kernel
recvmsg sets CLOEXEC atomically, including while another goroutine launches a
child. Message/control truncation, extra FDs, listening/non-TCP sockets, regular
files, wrong pipe direction and shared pipe endpoints refuse. Every received
capability is closed on every refusal path.

The root manager revalidates its fixed image/hash before each admission hello,
before the gateway's target dial. After descriptor validation it starts the unchanged
namespace/seccomp/setpriv boundary described in `SSH-PROCESS-LAB.md`, then
closes its copies of the session descriptors. It never reads SSH startup,
keys, remote protocol or terminal bytes. The gateway waits for the isolated
worker hello through the private pipe and sends only that session's host pin,
username and Ed25519 seed directly to the worker. SSH verifies the pin on the
same connected FD before key authentication. The manager's `active/v1` means
process launch only; application readiness still requires successful SSH
authentication, PTY and shell admission.

The gateway UID is trusted to enforce target/owner/custody policy. A compromise
of that UID can request the configured number of launches using its own connected TCP FDs;
the manager does not independently reconstruct DNS/catalog authorization.
It never grants the UID a root network dial or arbitrary exec. FD possession
is a capability, not proof of application ownership. Root/host administration
remains trusted and can inspect memory/descriptors; direct pipes do not provide
cryptographic secrecy against a malicious root manager.

## Lifecycle and resource bounds

Only one start is permitted per control connection. Extra packets, replay,
capabilities, malformed cancellation or disconnect kill its managed sandbox.
Setup admission expires after five seconds and gateway setup after ten. Slot
exhaustion refuses before the gateway target dial. Normal child completion
allows already received terminal output to drain. Explicit cancellation or
unexpected manager loss drops queued output, closes the pipes and revokes SSH.
The manager sends done only after its managed process is reaped; cancellation
waits at most two seconds for that acknowledgement. Manager shutdown cancels
all leases and joins them. A second manager cannot unlink/replace a live socket;
an unclean restart can leave a stale socket for local administrator inspection.
Cancellation signals only Go's owned process handle, using pidfd on supported
Linux, rather than issuing a raw process-group signal against a reusable PID.
The fixed bwrap parent-death/PID boundary closes the inner worker.

There is no hard aggregate memory guarantee or kernel-uninterruptible-task kill
guarantee. Configured finite slots bound accepted goroutines/children; the OS's socket
backlog and host resource policy remain outside this bound. Dedicated installed
worker identity (the laboratory still uses shared UID/GID 65534), aggregate
cgroups, restrictive service units, package/runtime dependency delivery,
manager restart/upgrade operations and deployment egress policy remain gates.

## Evidence

Ordinary Linux tests cover kernel peer identity, exact packet schema, bounded
ancillary data/truncation, atomic CLOEXEC, connected-TCP and pipe validation.
The existing `scripts/ssh-process-lab.sh` additionally runs the root manager
with separate UID/GID 65533 gateway test processes. Synthetic SSH keys and
ephemeral loopback fixtures stay in `_test.go`; the runtime adapter has no
loopback or dial-override configuration.

The required gate measures actual unprivileged SSH authentication, Unicode
input/output, resize, pin refusal before authentication, cancellation/reaping,
wrong UID/GID/root refusal, malformed rights, pending/active quotas, replay,
setup expiry, capacity return and manager shutdown revocation. It compiles
and runs the standalone manager binary and kills it after actual SSH readiness
to measure abrupt-loss cleanup. It compiles
both permissive and restrictive peer-admission and descriptor-validation
mutations, checks their intended assertions, restores byte-for-byte and reruns
the originals. All previous SSH child, owned-browser, native RDP and fuzz gates
remain required. Windows/macOS builds refuse this Linux-only boundary.

These gates and adversarial maintainer self-review are not independent audit.
Operator target/host-key approval UI, production RDP manager/clipboard, service
integration, recovery/backup and independent review of an exact release
candidate remain required before production credential custody/remote access.
