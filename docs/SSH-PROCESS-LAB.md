# SSH worker process boundary

16 October 2026. This slice moves the SSH protocol engine into a static Linux/
amd64 worker. It is a privileged **laboratory manager**, not a root web gateway,
installer, production service or authorization for real credentials. The
custody-only CLI stays unchanged. An authenticated manager for an unprivileged
gateway, operator target/trust configuration and UI, packaging and independent
candidate audit remain required. Porch and Rootwell are untouched.

## Admission and custody

`identity.NewRemoteLab` retains MFA, fresh proof, ownership, approval binding,
one-use capabilities, quotas and active revocation. After bounded OpenSSH import
validation it builds one `sshkey.Key` from the authorized Ed25519 key. This
redacted, copied material implements the existing signer interface and is closed
after setup. The existing library worker still works. `ProcessWorker` refuses
arbitrary signers: there is no SSH agent or reusable signing RPC/oracle.

The process worker receives a single 32-byte Ed25519 seed through a bounded
private startup pipe, after its sandbox hello. It receives no DB path, instance
key, login password, MFA seed, passphrase or other vault records. The gateway
has already parsed/decrypted an encrypted imported key within its two-slot
budget. Neither startup bytes nor native diagnostics are logged, written to a
key file, placed in URLs/arguments/environment, or sent to browser storage.
Best-effort clearing reduces lifetime; guaranteed RAM erasure is not claimed.
A compromised active worker can use its own session key/output; this is not
zero knowledge or protection from a fully compromised host administrator.

## Exact transport and server identity

The manager checks the approved worker's SHA256, ELF architecture/static linking,
root ownership, non-writable file/ancestor permissions and no symlink path.
Root-owned sticky temporary parents are accepted for the CI fixture. The opened
image descriptor is mounted, reducing path replacement exposure. System bwrap,
setpriv and the fixed runtime library paths must also be root controlled.
The image digest is trusted operator configuration, never browser approval.

Only then does `NamedTarget.DialContext` resolve once, validate the entire DNS
answer against its target pins and installation policy, and dial one literal
approved endpoint. The manager hands that already-connected TCP descriptor to
the child. The child cannot select a new host, IP, URL, port or broker address.
It performs the existing SSH exchange on **that same connection**, using its
copied Ed25519 host pin, supported algorithms and signing-after-verification
gate. There is no TLS/SSH preflight-then-redial authority or TOFU fallback.
Ready means host verification, configured key authentication and remote PTY/
shell admission succeeded; a successful sandbox hello alone is not readiness.

## Linux boundary

The fixed bwrap invocation creates private mount/network/PID/IPC/UTS namespaces,
an empty network namespace and a read-only root. It mounts only the approved
worker, setpriv, three required runtime libraries, proc and minimal dev. No home,
DB/control path, Docker socket, general /usr tree or host shell is mounted.
Trusted setpriv drops to real host UID/GID 65534, clears supplementary groups,
every capability set and enables no-new-privileges **before Go worker startup**.
This avoids doing per-thread privilege changes in a running Go process.

A small amd64 cBPF filter is loaded by bwrap before exec and inherited by every
worker thread. It checks the syscall architecture, refuses x32, new sockets/
connect/listen/accept, process forks and non-thread clones, namespace/mount,
ptrace/process-memory, keyring, BPF/perf, io_uring setup and handle-based opens.
Go runtime thread creation remains available. Initial setpriv/worker exec must
remain available; this is a deny policy, not a complete syscall allowlist.
The worker checks a different network namespace, fixed hostname, reduced UID/
groups/capabilities, no-new-privileges, absent host paths and a behavioral EPERM
socket probe before reading credentials. Unsupported sandbox conditions refuse.

Core/file output is limited to zero; descriptors to 64, CPU to 60 seconds and
process/thread RLIMIT_NPROC to 128 for that real UID. Runtime GOMAXPROCS=2 and
GOMEMLIMIT=64MiB are hints, not a hard process-memory ceiling. Aggregate cgroup
quotas and a dedicated per-installation service identity remain gates; shared
UID 65534 and a privileged manager are for this isolated laboratory only.

## IPC and lifetime

Binary frames carry a one-byte type and a four-byte length checked before
allocation. Startup is at most 1024 bytes, terminal input 32 KiB, resize eight
bytes, and output chunks 8192 bytes. Only one startup is accepted; input and
resize cannot change connection parameters. Two output queues per stream are
bounded to two chunks each. The child and manager independently cap total
output to 16 MiB; the browser relay's existing 8 MiB ceiling remains stricter.
There is no listener, arbitrary IPC peer or child-selected second connection.

Setup is bounded to ten seconds; the child bounds initial startup to five.
Close/owner cancellation closes private pipes, kills the managed process group
and waits at most two seconds for reaping. bwrap's parent-death/PID boundary
also owns descendants. Normal worker EOF drains already received output;
explicit cancellation refuses even buffered output. Remote background processes
are not guaranteed killed by closing SSH. Kernel uninterruptible tasks are not
given an absolute kill-time guarantee.

## Evidence and next work

Portable tests cover frame success/refusal/malformed/oversize, actual SSH pin/
key/PTY/input/resize/cancellation, repeated startup rejection, buffered output
revocation and clean EOF drain. `sshkey` tests cover key copying, inconsistent
public halves, redaction and closed-key refusal. `FuzzSSHWorkerFrames` is a
required two-million-execution target.

`scripts/ssh-process-lab.sh` builds a static child and separate race-enabled
test manager in disposable paths, then runs actual sandbox authentication,
changed-pin-before-auth refusal, none-auth refusal, image/digest refusal,
revocation and the owned MFA/vault/browser/logout flow. Synthetic loopback dial
substitution stays in `_test.go`; the runtime adapter has no loopback flag.
CI must pass this gate as well as all prior native RDP/browser/fuzz gates.

Source references reviewed for the launcher: [Bubblewrap options](https://github.com/containers/bubblewrap/blob/main/bwrap.xml)
and [descriptor/exec lifecycle](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c).
Host packages are trusted operator dependencies, not bundled signed release
artifacts. These tests and maintainer self-review are not independent audit.
