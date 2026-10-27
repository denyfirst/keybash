# Offline operator target catalog

19 October 2026. The operator can now supply the immutable target catalog as
bounded JSON. `keybash check-targets --config /absolute/path/targets.json`
performs offline validation and prints only a count. It opens no database,
listener, DNS lookup, target TCP stream or worker. No dependency changes.

## Schema and authority

Version 1 requires `version`, `protected_networks`, and `targets`. The optional
strict `capacity` member selects finite total/per-owner admission; omission
keeps defaults. See `SESSION-CAPACITY.md` for schema, gates and limits.
The complete file is at most 256 KiB. There are 1–64 canonical protected CIDRs,
1–256 targets and 1–16 canonical IP pins per target. Duplicate IDs, CIDRs and
IPs refuse. A bad entry refuses the whole snapshot, with a fixed error and
no partial catalog. JSON duplicates (including escaped keys), case variants,
unknown fields, trailing values, null/coerced values, invalid UTF-8 and lone
surrogates refuse. Control/format characters cannot enter names.

Each target requires these six shared fields and exactly one public identity:

| Field | Meaning |
|---|---|
| `id` | Stable independently generated random 128-bit lowercase hex ID |
| `name` | Nonempty UTF-8 label, up to 160 bytes |
| `protocol` | Exactly `ssh` or `rdp` |
| `hostname` | Existing guard's ASCII DNS name, or for SSH only a canonical IPv4/IPv6 address; no URL or host:port |
| `port` | Integer 1–65535; no numeric string or fractional value |
| `addresses` | Explicit canonical IPv4/IPv6 pins; no zones/mapped aliases. Absent when `hostname` is an address |
| `ssh_host_key` | One canonical OpenSSH Ed25519 public key, without options/comment/newline |
| `rdp_certificate` | Canonical padded base64 of the full approved leaf DER, up to 32 KiB |

The two identity fields are mutually exclusive. No password, private key,
username, environment substitution, include, file reference, plugin, worker
command or browser-selected endpoint belongs in this file. SSH public key
and RDP certificate acquisition/verification happens independently, outside
Keybash; validation does not establish who supplied a file or a live peer's
identity. There is no discovery, TOFU or network-based approval.

Illustrative SSH shape (replace the ID/public-key placeholders and example
networks using independently verified installation values before validation):

```json
{
  "version": 1,
  "protected_networks": ["10.99.0.0/16"],
  "targets": [{
    "id": "<stable random 32 lowercase hex characters>",
    "name": "Linux server",
    "protocol": "ssh",
    "hostname": "linux.example.invalid",
    "port": 22,
    "addresses": ["10.44.0.8"],
    "ssh_host_key": "ssh-ed25519 <independently approved public key base64>"
  }]
}
```

A server with no DNS name, common on an office network, is approved by its
address alone: `"hostname": "192.168.10.20"` with no `addresses` field. Nothing
is resolved for it, so there is no name to rebind or poison, and the dial still
passes the target's own policy and the protected networks. A second list beside
the address is refused rather than reconciled. The SSH host key remains the
server's identity; the address is only where to reach it. RDP keeps a name,
because both the import and the native worker check its certificate against one.

`protected_networks` is mandatory and nonempty to require an explicit deployment
decision. The operator must actually list database/control/host infrastructure
and custom translation ranges: the program cannot infer or prove completeness.
Protected ranges override every target approval. Existing loopback, link-local,
metadata, non-unicast and unsupported translation/tunnel exclusions stay in
force. Each target receives a separate immutable policy containing only its
own IP/port pairs; neither another target nor DNS can expand that authority.
RDP imports reuse the existing certificate name/purpose/key-strength and
critical-extension checks. The validity period is not an import check: Windows
renews its own certificate, and the approved one then expires. Such a target
still loads and only it is unavailable (no approval, no launch) while every
other target keeps working; `check-targets` names it until its certificate is
replaced. Imports do not replace the native worker's own TLS check, which
requires the period at every connection.

## Linux file provenance

Runtime loading supports Linux only. The path must be absolute and clean.
Every parent is walked through pinned directory descriptors using no-follow
opens. Direct parent and file are root-owned and never group/world-writable.
Earlier root-owned sticky ancestors may be shared-writable (the CI temporary
root is an example); the direct parent cannot. Root/host/filesystem remain
trusted. No symlink, nonregular file, shared hardlink, set-ID/sticky file,
empty/oversized file or changed size/mtime/ctime snapshot is accepted.
Nonblocking open prevents a FIFO from hanging the loader. The unprivileged
gateway can read public metadata but cannot change the root-owned catalog.

`ParseCatalog` is a portable internal validator, not a file-authority API. Runtime
commands use the checked `LoadCatalog` path. Neither the browser nor a stored
connection can call it or replace a running catalog. Restart is required;
existing in-memory sessions/leases die and stored owner decisions are checked
against the new host/port/IP/key snapshot before reuse.

## Explicit SSH-only integration command

The existing `serve-lab` remains custody-only. The separate command is:

```text
keybash serve-ssh-lab --data /private/data --key-file /separate/instance.key \
  --listen 127.0.0.1:8443 --tls-cert /operator/tls.pem --tls-key /operator/tls-key.pem \
  --config /operator/targets.json --ssh-manager /run/keybash/ssh-manager.sock
```

This is an integration entry point, not an installer or production release.
It requires Linux/amd64, a nonroot gateway UID other than reserved worker UID
65534, a nonroot primary GID, private existing custody paths, numeric loopback
TLS and an entirely SSH catalog. A missing/invalid catalog or any RDP entry
refuses the whole command before custody open. There is no in-process SSH
fallback and no native RDP launcher. The configured root manager still checks
the exact gateway UID/primary GID; the gateway checks the socket/root peer,
and the fixed worker verifies the actual SSH host key before user authentication.
The manager socket is validated on launch; HTTPS readiness alone does not
prove a worker or remote server is available. Existing manager image/hash,
namespace, descriptor and cancellation checks remain mandatory.

Login/MFA/owner checks, fresh proof for trust decisions, explicit full fingerprint, one-use lease, guarded
DNS/TCP and logout/revocation remain unchanged. SIGINT/SIGTERM close the lab
and shut down HTTPS; credentials/configuration contents are never logged.
Use synthetic credentials until installation, recovery and independent review
gates pass. This change installs or runs no service on the maintainer machine.

## Evidence and remaining gates

Portable tests cover valid SSH/RDP, identity format, expiry/name/purpose,
canonical network binding, forbidden/protected targets, duplicate and malformed
JSON, immutable copied inputs, whole-snapshot refusal and boundary counts.
`FuzzOperatorCatalog` is a required two-million-execution CI gate.
`scripts/operator-config-lab.sh` runs actual root file checks and a UID/GID
65533 reader, plus the compiled CLI as that separate user: initialization,
trusted TLS, pre-MFA refusal, bootstrap/MFA, approved target detail and clean
SIGTERM. Its target is synthetic and never dialed. Actual SSH/manager/native
RDP/browser tests remain separate required gates; the CLI test does not claim
an actual end-to-end remote connection through this new entry point.

Installed service units/dedicated identities, aggregate cgroups, production
RDP launcher and clipboard, non-loopback trusted TLS ingress, backup/restore,
real VM/browser matrix, packaging/upgrades and independent review of an exact
release candidate remain gates. Passing CI and maintainer self-review are not
an independent audit or permission to deploy/use production credentials.
