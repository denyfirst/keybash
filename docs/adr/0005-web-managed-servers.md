# 0005 — Servers managed from the web, with per-user access

Date: 2026-11-02. Status: accepted direction; built in phases, each its own
pull request.

## Context

Today an operator adds servers on the Keybash host as root, with
`keybash server-add` or by editing `/etc/keybash/targets.json`. The gateway
reads that catalog once at start. Every user can see every server in it and
connect to any of them with their own key or password. Adding a server needs a
restart, which closes open sessions.

The maintainer decided:
- Everything is done from the website.
- Only administrators add servers.
- A new server is visible to nobody until an administrator assigns it.
- This work comes next, before the release process.

The gateway itself dials targets. `targetguard` dials only pinned addresses
outside protected networks, and the connected socket is then handed to the
worker. The SSH manager reads only capacity from the catalog. The gateway's
systemd unit has no IP address restriction. So the root-owned catalog is a
policy the gateway applies to itself: a compromised gateway can reach any
address its host can reach, including cloud metadata services and the
internet.

A user who could add servers would turn Keybash into a bridge into the
internal network. Through the gateway's position they could reach hosts they
cannot reach themselves. An administrator who adds servers from the web has
the same power, so their reach needs a limit the gateway cannot lift.

## Decision

### A. A kernel network boundary, set by root

- Root names the networks servers may be in with `--target-networks` at
  install or upgrade. They are an argument of the root-owned gateway unit,
  rendered by `keybash-service-plan` and read back by `upgrade.sh` like
  `--allow-from`. So one root-owned source sets both the gateway's own check
  and the kernel's.
- `keybash-service-plan` renders, on the gateway unit:
  - `IPAddressDeny=0.0.0.0/0 ::/0`, every address;
  - `IPAddressAllow=` for loopback (`127.0.0.0/8 ::1/128`: clients through a
    tunnel, and the local DNS stub), the `--allow-from` networks when exposed,
    and the target networks.
  - The prefixes are written out rather than as systemd's `any` and
    `localhost`, which `systemd-run` does not read, so a test probe runs with
    the unit's very lines.
- systemd enforces this in the kernel (cgroup BPF), for incoming and outgoing
  traffic alike. Even a compromised gateway cannot reach outside those
  networks.
- An allowed network cannot have a hole in it, so a target network may touch
  no protected network, loopback, link-local, multicast, translation range or
  metadata endpoint.
- `install.sh`, `upgrade.sh` and the gateway itself refuse target networks
  that leave a catalog server out.
- An install that names none gets one host network per catalog address. It
  reaches what it reached before and nothing new, until the operator names
  networks with `upgrade.sh --target-networks=…`.
- Name resolution goes to the system resolver. On Ubuntu that is the loopback
  stub, so it stays allowed. A resolver elsewhere must be inside an allowed
  network; the install check says so.

### B. Servers in the encrypted store, managed by administrators

- Server records are kept beside accounts, sealed like other records: ID,
  name, protocol, address, port, the pinned identity (SSH Ed25519 host key or
  RDP certificate), who added it and when, and a revision.
- On the Servers page, administrators can:
  - **Scan** an address and port. The gateway reads the server's identity: SSH
    stops at the host key, offers only Ed25519 and never authenticates; RDP
    fetches the certificate. It shows the fingerprint and the command that
    prints the same fingerprint on the server's own console. Scans are
    admin-only, limited to the target networks and rate-limited, so they
    cannot map the network.
  - **Add** a server with the fingerprint they compared. This needs a fresh
    phone code, and the server takes effect with no restart.
  - **Rename** a server.
  - **Remove** a server. This ends its sessions at once and marks connections
    to it unavailable.
  - **Accept a changed identity.** This needs a fresh phone code, and owners
    then re-approve their connections, as today.
- Catalog servers from `targets.json` are listed as "from the server file":
  their access can be assigned on the page, but they are changed only on the
  host.
- The gateway's target set becomes a guarded map rebuilt on each change.
  Starting with no server at all becomes valid.

### C. Access per user

- Each server has an access list of accounts, empty when the server is added.
- The same rule applies to administrators: they manage every server but
  connect only where they are on the list.
- `/api/targets`, the connection form, the lease grant, the lease redeem and
  the socket all check the list. Removing a person ends their sessions on that
  server at once, as a role change does.
- Auditors see servers and access lists read-only, and hold no key.
- On the first start after the upgrade, each catalog server is granted to the
  accounts that already have a connection to it, so nobody loses access they
  use today.

### D. Shared keys, later

- An administrator can attach one credential to a server for its users.
- They connect with it without ever seeing it: no reveal, no export.
- It needs its own design: rotation, who can replace it, and how a removed
  person loses it.

## Consequences

- Kernel enforcement adds a boundary that does not exist today. A
  compromised gateway can no longer reach metadata services, other subnets
  or the internet.
- A compromised administrator account can add servers inside the target
  networks and connect to them with credentials it holds. The fresh phone
  code, the kernel boundary and the audit record (planned) limit and record
  that. It still cannot read other people's secrets.
- The access lists and server changes are written to the audit record once
  that exists; until then they are visible on the Servers page only.
- Each phase is merged only with success, refusal, malformed-input and abuse
  tests, and with sabotage in both directions:
  - A: unit rendering and a real systemd install that cannot reach an
    address outside the target networks;
  - B and C: the store and HTTP tests, and the browser tests.
