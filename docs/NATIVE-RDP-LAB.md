# Native RDP laboratory candidate

14 October 2026. Candidate under required Linux CI verification; not a release
or production entry point. No real remote account or credential is used.

The lab builds Guacamole server 1.6.0 and FreeRDP 3.32.2 from upstream release
archives, verified before extraction:

| Source | SHA-256 |
|---|---|
| FreeRDP 3.32.2 tar.gz | `e95a505c0057e4d06a3b120477c421028769deba4db9c639ef3465d050f0955c` |
| Guacamole server 1.6.0 tar.gz | `8bc45675da96d7b6f39728160181e3d4ff3c08f460f6d26de5805b642bf13f2b` |

Both upstream projects use Apache-2.0. The builder preserves upstream license/
NOTICE material and records installed package versions, native file hashes and
dynamic linkage. This is dated CI evidence, not a reproducible release or a
complete production license/SBOM bundle. OS libraries come from Ubuntu 24.04's
package repositories; they are not claimed immutable or universally CVE-free.
No container image, Java web application or Guacamole JS client is adopted here.

Upstream FreeRDP advisories and latest releases were checked on 14 October 2026.
3.32.2 is the current upstream security/bugfix release. Published advisories
include legacy ranges and items without machine-readable patched versions;
the release choice is not a blanket absence-of-vulnerabilities claim. Guacamole
security reports list 1.6.0 as the current fixed release. Review/update ownership
remains with the maintainer; review changed native APIs, archives, advisories and
OS dependency inventory before changing pins. Production packaging needs its
own complete native vulnerability/license review and independent candidate audit.

## Native identity and protocol boundary

Guacamole's supplied fingerprint fast path can accept before ordinary X509
validation. The lab instead registers FreeRDP's application-managed X509 hook,
removes that fast path and forbids ignore/automatic certificate trust. The hook
uses OpenSSL to compare the actual leaf's SHA-256 DER digest with the imported
approved leaf and validate its DNS SAN, validity, server-auth/digital-signature
usage, critical extensions and key strength. It refuses gateway/redirect flags.
TLS has a 1.2 floor and ECDHE/AEAD TLS 1.2 suites. The check occurs on the native
worker's actual TLS connection, before CredSSP, not on a separate probe.
CN-only default certificates are deliberately unsupported; an approved
certificate with a matching DNS SAN is required for this lab.

`native/prepare.py` applies narrow checked patches to the pinned sources. The
FreeRDP sample is a synthetic fixture only: NLA enabled, legacy/TLS-only mode
disabled, loopback-only listener and a fresh test SAM account. Its fixed marker
is emitted in PostConnect, after protocol authentication. Guacamole `ready`
alone is not evidence of successful RDP authentication. Required cases include
correct/incorrect password, actual image output, revocation, changed/expired/
name-mismatched certificates, old TLS and missing NLA. TLS refusal fixtures
observe closure before any CredSSP application data. These are Linux synthetic
peer tests, not Windows interoperability or full desktop/clipboard evidence.

The private Go adapter accepts the exact reviewed Guacamole argument schema;
unknown, duplicate, missing or changed-version fields refuse before credentials
are sent. Browser-selected params, target/gateway selection, drive, file transfer,
SFTP, arbitrary channels, programs, audio, printing and recording are unavailable.
Credentials travel on private Unix control IPC, never command arguments, URLs or
environment. Formatting the plan redacts credentials. Streams have instruction,
frame/byte limits and reject unsolicited files/pipes/argv/prompts. There is no
browser RDP route or product login/ownership/vault in this candidate.

## Worker and broker

The launcher lives only in Linux test files. Bubblewrap supplies private network,
PID, IPC, UTS and mount namespaces, UID/GID 65534, no groups/capabilities and
no-new-privileges. Approved trust files and individual per-test socket inodes
are bound read-only; no host home, database, vault, Docker socket or fixture
private key/SAM is mounted into the worker. Read-only OS libraries under /usr
and /lib and the reviewed CI prefix remain visible; this is not a minimal
production root filesystem. guacd receives address-space, CPU, descriptor and
process limits. Aggregate cgroup/session quotas remain a production gate.

A one-use raw-stream broker binds the guarded NamedTarget to the approved logical
identity and uses its dial result without another DNS lookup. The worker never
chooses another host/port: its private loopback bridge consumes one Unix stream
capability, with TLS preserved end-to-end. Broker cancellation/quotas close both
directions. Synthetic native fixtures inject loopback dials only in test files;
the production guard's exclusions are unchanged. Private IPC checks the peer UID
and host parent directories remain mode 0700. This is lab capability isolation,
not application user ownership or authorization.

Before installing a product worker: complete usable production launch/IPC
authorization, small runtime filesystem, aggregate resource/egress abuse tests,
real Windows/browser clipboard/keyboard and reconnect matrix, credential custody,
packaging and independent security review. No production service is deployed.

Primary references: [FreeRDP release](https://github.com/FreeRDP/FreeRDP/releases/tag/3.32.2),
[FreeRDP advisories](https://github.com/FreeRDP/FreeRDP/security/advisories),
[Guacamole source/checksums](https://guacamole.apache.org/releases/1.6.0/),
[Guacamole security](https://guacamole.apache.org/security/),
[OpenSSL verification](https://docs.openssl.org/3.0/man3/X509_verify_cert/),
[Bubblewrap](https://github.com/containers/bubblewrap).
