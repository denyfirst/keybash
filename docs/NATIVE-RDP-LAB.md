# Native RDP laboratory

Synthetic lab with a required Linux CI gate (`scripts/native-rdp-lab.sh`); not
a release or production entry point. No real remote account or credential is
used.

> **20 November 2026, step 3e3 of [the IronRDP desktop page](BROWSER-RDP-PAGE.md).**
> Until this date the lab built Guacamole server 1.6.0 and FreeRDP 3.33.1, with
> Keybash's patches and its OpenSSL identity callback, and every desktop ran
> guacd. Every desktop now runs Keybash's RDP proxy (`BROWSER-RDP-PROXY.md`),
> and guacd, FreeRDP, their patches and their freshness watches have left the
> repository. ADR 0003 and ADR 0008 keep the reasons; the git history keeps the
> old lab.

## What the lab builds

- **Keybash's RDP proxy** (`rdp-proxy/`, `scripts/build-rdp-proxy.sh`), the
  one program a desktop's worker starts.
- **The test peer** (`rdp-testpeer/`, `scripts/build-rdp-testpeer.sh`):
  IronRDP's own server at the commit the proxy and the browser module pin,
  with TLS and NLA for one synthetic account. It is never shipped.
- **The runtime** (`scripts/build-rdp-runtime.py`): the proxy, `setpriv`, and
  the operating-system libraries `ldd` finds for them, with the mountpoints the
  sandbox binds. Nothing else is in it; its full ordered inventory binds every
  file and permission (`RuntimeInventory`), and the proxy is required.
- The Keybash programs the service lab installs.

Both Rust programs come from their committed `Cargo.lock`, with a fresh cargo
home and the toolchain IronRDP pins. OS libraries come from Ubuntu 24.04's
package repositories; they are not claimed immutable or universally CVE-free.
The lab prints the runtime's file hashes and the proxy's linkage as dated CI
evidence, not a reproducible release or a complete SBOM.

## Identity and protocol boundary

The proxy enforces its own pin on its own TLS before CredSSP
(`rdp-proxy/src/pin.rs`): rustls, TLS 1.2 or 1.3, a verifier that takes only
the pinned certificate's exact bytes within its dates, and the leaf compared
again before any credential leaves the process. A protocol other than NLA
refuses. A server reached by DNS name was approved with a certificate for that
name; a server at a literal address with its exact certificate, which may be
Windows' own (ADR 0003). The rules come from the target (`identityFor`), and the
sealed name file holds a DNS name or exactly `@exact-leaf`.

`TestNativeRDPManagerProxyMeetsNLAInTheSandbox` runs every desktop the way the
service does, through the manager, the worker's sandbox and the guarded broker:

- the right password gets IronRDP's RDCleanPath answer with the pinned
  certificate, by name and by Windows' own certificate pinned exactly, and
  revocation ends it with nothing more crossing;
- a wrong password ends as "credentials";
- a gateway that is not the configured one gets nothing, and nothing is dialled;
- a server showing another certificate, the pinned one past or before its
  dates, TLS 1.1, TLS without NLA, or plain RDP ends as "refused". A Go TLS
  peer observes each of these, and closure must come before any CredSSP data.

CI then mutates the proxy's pin in both directions, from a disposable copy of
`rdp-proxy/`: a proxy that takes any certificate must fail the refusals with
credentials seen leaving it, and a proxy that takes none must fail the right
password. The normal lab then runs again in full. A refusal timeout alone fails.

These are synthetic peer tests, not Windows interoperability: the proxy's live
tests against Windows and the maintainer's tests on the test VM cover that.

## Worker and broker

The manager starts each desktop's worker in Bubblewrap: private network, PID,
IPC, UTS and mount namespaces, the worker's own UID and GID, no groups or
capabilities, no new privileges, a syscall denylist, and the runtime as a
read-only root. The worker checks all of this itself, then starts only the
proxy, with no argument and an empty environment; it reaches the server
through a private loopback bridge over the one guarded stream it inherits.
`TestNativeRDPSandboxPreparation` checks the sandbox's shape, and the sandbox
mutations (allow-all and deny-all syscall filters) must fail its public
preflight.

A one-use raw-stream broker binds the guarded NamedTarget to the approved
identity and uses its dial result without another DNS lookup. The worker never
chooses another host or port, and TLS is preserved end to end. Credentials
travel once, in the proxy's setup frame on private pipes, never in command
arguments, URLs or the environment. The manager checks its peer's Unix
credentials before it starts anything.

`TestNativeRDPSystemdServiceBoundary` installs the real units on the CI runner,
opens a desktop through the installed manager, checks the worker's identity
and cgroup and the slice's limits, and stops the manager: the desktop's input
and output end with it.

Primary references: [IronRDP](https://github.com/Devolutions/IronRDP),
[rustls](https://github.com/rustls/rustls), and
[Bubblewrap](https://github.com/containers/bubblewrap).
