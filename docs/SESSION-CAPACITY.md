# Operator-controlled connection capacity

20 October 2026. Remote connections now use finite, immutable operator-selected
admission bounds. These are resource controls, not licensing tiers. Existing
catalogs keep eight total/two per owner; those values are now defaults rather
than constants at the gateway and manager gates.

Add the optional member to the existing root-owned version 1 catalog:

```json
"capacity": {"total": 16, "per_owner": 4}
```

Both integers are required when present: total 1–128, per-owner 1–total.
Explicit null, zero, negative, fractional/string/overflow values, duplicate or
unknown fields and unlimited/disabled modes refuse the whole file. Omission
uses defaults; invalid settings never fall back. 128 is an implementation
admission ceiling, not a certification of 128 real sessions on a host. Tested
hardware/workload profiles and measured deployment sizing remain gates.

`check-targets --config /operator/targets.json` prints configured capacity and
target count without opening custody or networking. Runtime APIs return targets
and capacity together in one Catalog; target-only adapters exist in test files.
Root ownership, pinned no-follow opens and identity/network validation remain.
Old binaries reject the unknown new member rather than ignoring its policy.

Supply the same file to both processes, with their existing required flags:

```text
keybash serve-ssh-lab ... --config /operator/targets.json --ssh-manager /run/keybash/ssh-manager.sock
keybash-ssh-manager ... --config /operator/targets.json
```

See the operator/manager guides for private custody/TLS paths and fixed image,
hash, socket and gateway UID/GID arguments. The manager's config flag is optional
for legacy lab callers, which keep eight slots. Both processes must use the same
file and restart together after policy changes. Each loads once; there is no
hot reload or cross-process capacity negotiation. A smaller manager still
restricts SSH launches independently of the gateway.

Pending and active leases share the configured gateway total/per-owner budget.
Checks and insertions use the session mutex, so concurrent requests cannot
overbook it. Expiry, logout, deletion and cleanup return capacity through the
existing revocation lifecycle. Live connections are not evicted for new ones.
Pre-proof WebSockets use a separate budget with the same numbers, reserving
before proof and releasing on handler exit. These lanes are independently
bounded; early lease revocation can precede asynchronous socket cleanup.

The SSH manager counts pending/active launches until setup ends or the worker
is reaped. Exact kernel UID/GID, three-FD validation, fixed image/hash,
namespaces, syscall policy and host-key-before-authentication remain. It parses
trusted root-owned public catalog metadata at startup; session private keys and
terminal bytes still pass directly to the worker rather than its parser.

Capacity refusal is authenticated HTTP 503 with fixed `X-Keybash-Capacity: full`
and a five-second retry hint. Terminal/desktop entry displays a fixed Azerbaijani
busy message, preserves existing sessions and performs no automatic retry.
Authentication/mutation attempt budgets remain separate. Ready MFA accounts
may GET `/api/remote/capacity` for configured numbers only, without other owners'
usage. There is no browser setter or caller-selected worker/endpoint override.
The HTTP grant does not reserve every downstream resource atomically. A race
at socket admission or a separately full/misconfigured manager can still refuse
setup with the existing generic connection failure. No cross-process capacity
guarantee or automatic waiting/retry queue is claimed.

Portable tests cover legacy/custom/boundary settings, malformed input, invalid
constructors, copied policy, more than two owner/more than eight total leases,
global/owner refusal, concurrent admission, pending expiry, logout, pre-proof
socket capacity/return and preservation of an active lease. The Edge/Chromium
owned workflow observes a refused second connection and continued input/output
on the first, without starting another worker.

The required Linux gate exercises limits one and ten with one real authenticated
SSH worker plus pending reservations, overflow refusal and cancellation. It
also starts the compiled manager CLI at ten slots from a root-owned catalog.
This is admission correctness evidence, not a ten-active-worker benchmark.
All prior SSH/native RDP/browser/race/fuzz and provenance gates remain required.

Finite admission does not enforce an aggregate RAM/CPU/pids budget. Kernel
cgroups/service policy, dedicated installed identities/units, measured host
profiles, production RDP/clipboard, real VM/browser matrix, backup/restore,
packaging and independent exact-candidate audit remain product gates. No service
is installed, no real credential is used and no production release is made.
