# Keybash

A Denyfirst self-hosted SSH and RDP workspace, in development.

Keybash will let individuals and small teams keep their own credentials and
work on servers from a browser. Deployment is exclusively self-hosted, with
bundled local assets and no required vendor relay, cloud account, or telemetry.
Security comes before convenience; comfortable clipboard and keyboard behavior
are designed and tested alongside the security boundaries.

**Current status:** in development and not released; keep only test data on
it. [What exists and what remains before a release](docs/STATUS.md). In short:

- A source installer, upgrader and uninstaller for one Linux x86-64 host with
  systemd. HTTPS on loopback or on named LAN/VPN networks only, and the kernel
  lets the gateway reach only the networks its servers are in
  ([installing](docs/INSTALL.md), [LAN ingress](docs/LAN-INGRESS.md)).
- Accounts with Argon2id passwords, mandatory TOTP and recovery codes, roles
  and invitations, all managed on the web pages.
- Stored SSH keys and passwords, each sealed under its own data key. Servers
  are added on the Servers page; their host key or certificate is checked on
  the server's console and pinned ([server trust](docs/SERVER-TRUST-LAB.md)).
- SSH terminals through a sandboxed worker per session
  ([SSH worker](docs/SSH-PROCESS-LAB.md), [manager](docs/SSH-MANAGER-LAB.md)).
- Windows desktops run IronRDP in the browser (WebAssembly, drawn on the GPU,
  H.264 through WebCodecs) behind Keybash's own RDP proxy, written in Rust. The
  proxy pins the server's certificate on its own TLS before any credential
  leaves it, and the browser never sees the password
  ([ADR 0008](docs/adr/0008-video-path.md), [the desktop page](docs/BROWSER-RDP-PAGE.md),
  [the proxy](docs/BROWSER-RDP-PROXY.md)).
- Offline encrypted backups and restore ([backup](docs/BACKUP-RESTORE.md)).
- Signed commits, CodeQL, static and vulnerability analysis, Linux CI that
  installs and upgrades on systemd, browser tests, native tests that open a
  desktop from the page to a synthetic RDP server, and sabotage of security
  checks in both directions.

[The local demo](docs/INTERACTIVE-DEMO.md) shows the pages with a sample
terminal and no servers, and [the test setup guide](docs/TEST-SETUP.md) prepares a separate
test VM.

## Start here

- [Product plan](docs/PRODUCT-PLAN.md)
- [Current status and what remains before a release](docs/STATUS.md)
- [Installing, upgrading and adding people](docs/INSTALL.md)
- [Backup, key recovery and restore](docs/BACKUP-RESTORE.md)
- [Roadmap](docs/ROADMAP.md)
- [Engineering and signing workflow](docs/ENGINEERING.md)
- [Implemented security invariants](docs/SECURITY-INVARIANTS.md)
- [Protocol lab scope and next gates](docs/PROTOCOL-LAB.md)
- [RDP boundaries and remaining native gates](docs/adr/0003-rdp-precredential-boundaries.md)
- [Superseded by ADR 0008: H.264 to the browser from our own encoder](docs/adr/0007-h264-to-the-browser.md)
- [Accepted: desktops run IronRDP in the browser behind Keybash's RDP proxy](docs/adr/0008-video-path.md)
- [The desktop page on IronRDP](docs/BROWSER-RDP-PAGE.md)
- [Keybash's RDP proxy](docs/BROWSER-RDP-PROXY.md)
- [Native RDP lab evidence and limits](docs/NATIVE-RDP-LAB.md)
- [Record of the earlier guacd desktop page](docs/BROWSER-RDP-LAB.md)
- [Password identity lab and remaining MFA gates](docs/IDENTITY-LAB.md)
- [Durable MFA/custody lab and operator usage](docs/CUSTODY-LAB.md)
- [Account-owned SSH/RDP session integration](docs/OWNED-REMOTE-LAB.md)
- [Try the local interactive UI demo](docs/INTERACTIVE-DEMO.md)
- [Separate test VM setup](docs/TEST-SETUP.md)
- [Dependencies and their reviews](docs/DEPENDENCIES.md)
- [Staying current: scheduled version and vulnerability checks](docs/STAYING-CURRENT.md)

## Development checks

Go selects the toolchain pinned in `go.mod`. The target guard uses the standard
library; SSH uses the reviewed dependency pinned in `go.mod`. PowerShell:

```powershell
./scripts/check.ps1
```

CI also runs Linux race tests, bounded hostname fuzzing, compilation checks, pinned static
analysis, vulnerability checking and commit signature verification. Analysis
tools and source dependencies are not part of the product runtime.

Browser lab verification requires locked test dependencies in `web/` and
Playwright's test browser. Run `go test -tags=browserlab -run
TestBrowserTerminalLab ./internal/sshtransport`. On Windows, set
`KEYBASH_BROWSER_CHANNEL=msedge` for the installed Edge binary. This creates
and tears down an isolated test session; it is not an install/serve command.

## Independence and trust

Porch and Rootwell remain separate, read-only references. Keybash changes are
made only in this repository. It uses the existing Denyfirst public commit/tag
and separate release signer identities; private keys are never copied here.

The maintainer authorized public repository development. Keybash is licensed
under the AGPL-3.0 (see Licence below); no production release has been made
yet. No independent audit is claimed. The self-hosted gateway will need
access to active credentials; the vault is not a zero-knowledge guarantee
against host compromise.

## Licence

AGPL-3.0. See [`LICENSE`](LICENSE). Third-party licences are listed in
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) (Licence section).
