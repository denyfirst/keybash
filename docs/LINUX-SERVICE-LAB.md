# Source systemd SSH service integration

20 October 2026. This is an offline source plan and a disposable Linux/amd64
systemd/cgroup-v2 acceptance gate. It is not a signed package, production
deployment, public ingress or RDP service. Nothing is installed on the
maintainer's Windows computer. Use synthetic credentials until release gates pass.

## Plan and identities

Build `cmd/keybash`, `cmd/keybash-ssh-manager`, `cmd/keybash-ssh-worker`,
`cmd/keybash-service-check`, and the offline `cmd/keybash-service-plan` from the
same reviewed commit with the pinned toolchain. The worker must be static
(`CGO_ENABLED=0`). Hash that exact worker image, not a path or a later rebuild.
The plan command writes four public files to a NEW administrator-selected
staging directory; it never installs files, creates accounts or starts services.
Existing output refuses. Staging uses rooted, exclusive file creation.

Example with illustrative **unused** numeric identities (verify that both names
and all UID/GID numbers are unoccupied; never reuse a login/service account):

```text
keybash-service-plan --output=/private/review/keybash-plan \
  --gateway-uid=64080 --gateway-gid=64080 \
  --worker-uid=64081 --worker-gid=64081 \
  --worker-digest=<64 lowercase hex SHA256 of the approved static worker> \
  --cpu-percent=200 --memory-mib=1024 --tasks=512
```

Zero, root, reserved lab UID/GID 65534, shared gateway/worker UID or GID,
out-of-range IDs, malformed/all-zero digest and invalid/unlimited budgets refuse.
Only numeric values and the digest enter fixed templates: no caller-selected
command, path, environment, unit name or directive. The sysusers file describes
separate `keybash-gateway` and `keybash-worker` users/groups with no login shell.
The service preflight checks names AND numeric identities, primary groups and
absence of foreign supplementary groups. Numeric collisions are not adopted.

The manager receives worker UID/GID only from root startup flags. They are
absent from gateway IPC/browser requests. Bubblewrap/setpriv drops to that
identity before reading key/protocol input; the worker verifies actual real and
effective UID/GID, empty groups, capabilities, no-new-privileges, namespace,
filesystem and behavioral seccomp checks. Legacy callers omitting BOTH worker
IDs keep the old 65534 lab identity; generated service plans always use an
explicit dedicated identity. A partial/invalid pair or gateway collision refuses.

## Fixed layout and administrator steps

The generated units expect the following operator-provisioned layout. This
document is a source integration guide; an automatic installer, upgrade and
rollback mechanism remains a separate gate.

| Path | Authority and contents |
|---|---|
| `/usr/local/libexec/keybash/` | Root-owned, non-writable by services; the four runtime executables, worker digest matching the generated manager unit |
| `/etc/keybash/targets.json` | Root-owned public offline SSH-only catalog, non-writable by services; same snapshot loaded by gateway/manager |
| `/var/lib/keybash/` | Gateway-owned mode 0700 durable custody data |
| `/etc/keybash/keys/` | Separate gateway-owned mode 0700 directory, mode 0600 `instance.key` |
| `/etc/keybash/tls/` | Gateway-owned mode 0700 directory, operator-trusted `cert.pem` and mode 0600 `key.pem` |
| `/run/keybash-manager/` | Created by systemd, root-owned 0755; root-owned 0660 `control.sock` with gateway group |

Ancestor ownership/modes and no-follow catalog/worker provenance rules remain.
Root controls `/etc/keybash`; the gateway cannot replace its parent or catalog.
Root must review the generated plan and supply platform dependencies (Bubblewrap,
setpriv and the already checked x86_64 Linux runtime library paths), create the
dedicated identities from the reviewed sysusers file, provision private paths,
initialize custody as the gateway UID through the existing CLI and keep the
one-use bootstrap code private. Initialization/recovery never belongs in
ExecStart, environment, shell history or journal output.

After placing the reviewed unit/slice files under `/etc/systemd/system/`, run
`systemd-analyze verify`, reload the daemon and explicitly start
`keybash-gateway.service` on the isolated synthetic lab host. `Requires`-style
binding starts its manager first. No unit is automatically enabled by the plan
tool. Stop gateway/manager before offline account recovery or policy/image
updates. Replace the whole reviewed plan and restart BOTH services after any
catalog/capacity/profile/image change. The manager socket directory is removed
by systemd on stop, allowing a clean restart without unlinking a live socket.

The gateway is nonroot with no capabilities, read-only system/home protection,
no namespace creation and only private data writable. The root manager has
only a Unix listener, private network, restricted capabilities and no mounted
custody key/data/TLS paths. Its namespace setup still requires CAP_SYS_ADMIN;
Bubblewrap also needs NETLINK/NET_ADMIN to initialize loopback inside the new
private network and MKNOD for its private `/dev`. Fresh internet socket families
remain denied to the manager; the final worker still drops every capability
and denies new sockets through its own seccomp policy before secret input.
The manager and host/root administrator remain trusted. The child keeps its separate
empty network/filesystem/PID namespace and inherited authorized TCP stream.
This does not turn a compromised root manager into an untrusted principal.

Manager stop/loss stops the bound gateway. Control-group shutdown includes all
descendants; existing manager parent-death and owned-process cancellation remain.
There is no automatic restart loop. Recovery/restart is an explicit operator
operation. The listener stays trusted TLS 1.3 on **127.0.0.1:8443** with existing
Host/Origin/MFA/owner/trust checks: reverse-proxy/public-origin support is not
introduced, and exposing this port through an arbitrary proxy is not supported.

## Aggregate kernel policy

Both services and all inherited SSH descendants are in `keybash.slice`.
Default combined budget: CPUQuota 200% (two cores' time), MemoryMax 1024 MiB,
MemorySwapMax 0 and TasksMax 512 (threads count too). Plan ranges are CPU 10–6400%,
memory 256–1048576 MiB and tasks 128–32768. They are finite engineering ranges,
not measured hardware recommendations or a promise of 128 active SSH sessions.
Configure admission capacity separately through the shared catalog.

Every service ExecStartPre checks actual cgroup-v2 membership and kernel
`cpu.max`, `memory.max`, `memory.swap.max`, and `pids.max` at the common parent,
including exact intended values. Missing controllers/files, unlimited/mismatched
values or wrong ancestry refuse before the application/socket starts. It is a
startup check, not a monitor against later trusted-root changes. Read-only
cgroups prevent the gateway/worker from moving themselves. Root is trusted.

CPU exhaustion throttles. Tasks exhaustion refuses process/thread creation.
Memory exhaustion can invoke the kernel OOM killer and end active work; a hard
memory ceiling is NOT an application busy queue or availability guarantee.
OOMPolicy=kill and control-group cleanup apply per service; aggregate pressure
can affect either service. No remote-process-kill or kernel-uninterruptible-task
guarantee exists. Go's worker GOMEMLIMIT remains a soft hint, not this hard cap.
The older worker RLIMIT_NPROC=128 remains an additional shared-per-UID backstop;
capacity/profile sizing requires measurement, especially at higher admission.

## Required evidence

`scripts/service-lab.sh` compiles the source plan/preflight/gateway/manager/worker
and tagged tests on an ephemeral systemd Linux CI runner. It refuses existing
Keybash paths, unit files, account names and occupied test IDs; no production
credential enters it. It creates synthetic custody/TLS/catalog fixtures and
temporarily installs the exact generated units, then removes units, state and
accounts. Do not run this destructive synthetic acceptance script on a customer
or maintainer host; it is a disposable-runner test, not an installer.

The gate verifies actual nonroot trusted-TLS readiness, separate root manager,
real synthetic SSH over that manager's inherited descriptor despite its private
network, exact dedicated worker UID and inherited cgroup, hidden custody key,
stop/revocation, empty descendants and a restored restart. Changing each of the
four parent limits must refuse startup before a manager socket appears. After
restoration another actual SSH session succeeds. Fixed unprivileged CPU, fork
and memory probes then run under the same parent slice: CPU throttling counters,
pids rejection counters and an actual OOM-kill counter must increase. Ordinary
probe failure/timeouts cannot stand in for those kernel events.

Portable tests cover finite/invalid plans, injected digests, mandatory service
boundaries, malformed/overflow/unlimited kernel snapshots, membership, swap,
outside-service refusal and legacy/dedicated worker identity. Both permissive
and restrictive mutations must fail intended assertions, then sources restore
and affected gates rerun. The other actual SSH/native RDP/browser/race/fuzz and
signing/analysis gates stay required. See `VERIFICATION.md` for executed evidence.

Production RDP service/clipboard, public TLS ingress, tested runtime packaging,
fresh-host installer/upgrade/restore, load/VM/browser sizing and independent
review of an exact candidate remain gates. This is maintainer-tested integration,
not an independent audit or authorization to deploy real credentials.

Primary references: [systemd resource controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html),
[service execution](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
and [service lifecycle](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).
Bubblewrap setup references: [private network setup](https://github.com/containers/bubblewrap/blob/v0.9.0/network.c)
and [namespace/filesystem launcher](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c).
