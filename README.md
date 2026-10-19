# Keybash

A Denyfirst self-hosted SSH and RDP workspace, in development.

Keybash will let individuals and small teams keep their own credentials and
work on servers from a browser. Deployment is exclusively self-hosted, with
bundled local assets and no required vendor relay, cloud account, or telemetry.
Security comes before convenience; comfortable clipboard and keyboard behavior
are designed and tested alongside the security boundaries.

**Current status:** repository foundation, tested outbound IP target guard,
and hostname-scoped DNS pins with literal-IP dialing.
An SSH library lab now verifies an approved Ed25519 host key before key
authentication and opens a bounded remote PTY with cancellation and resize.
A loopback-only HTTPS browser lab adds local xterm rendering, bounded WebSocket
transport and paste review. It uses a synthetic SSH fixture; Linux CI exercises
a real Bash PTY inside the test fixture. A credential-free RDP lab now tests
HYBRID negotiation, pinned TLS and bounded Unicode text streams; Linux CI tests
an empty worker network namespace. A separate native Linux lab builds pinned
Guacamole/FreeRDP, verifies identity on its own TLS before CredSSP, authenticates
a synthetic NLA account and decodes desktop images through an isolated worker.
Its one-use broker and actual native identity mutations are required CI gates.
A loopback browser RDP viewer adds bounded PNG/canvas rendering, focused mouse/
keyboard, local fullscreen and native revocation checks. RDP clipboard and
remote resize remain disabled.
A separate memory-only identity lab adds named password login, Argon2id,
bounded attempts, password change, secure cookies/CSRF and session revocation.
A separate Linux loopback custody lab now adds durable encrypted accounts,
one-use operator bootstrap, mandatory MFA/recovery, and owner-scoped encrypted
Ed25519 key/password custody with fresh authentication for sensitive actions.
Its browser interface and offline operator entry point use synthetic data.
An owned-session lab now links MFA/custody and encrypted connection records to
the existing SSH and isolated native RDP browser fixtures, with one-use socket
admission, approval binding and account-wide logout revocation.
A disposable interactive UI preview now opens sample terminal/desktop views
through the normal MFA/owned-connection flow. These are simulations, not real
Linux/Windows sessions; see the [local demo guide](docs/INTERACTIVE-DEMO-AZ.md).
Installed isolated workers/operator configuration, RDP clipboard, deployment and an
independently audited production release remain gates.
A separate Linux/amd64 SSH process laboratory now uses a hash-bound static
child, private namespaces, restricted syscalls and one inherited guarded TCP
connection. Its privileged test manager is not a root web service or installer.
See [the SSH process boundary](docs/SSH-PROCESS-LAB.md) for limits and remaining gates.
A separate authenticated Unix manager now launches that worker for an
unprivileged gateway, without reading its session key or terminal stream.
See [the manager boundary](docs/SSH-MANAGER-LAB.md); installation remains a gate.

## Start here

- [Product plan (Azerbaijani)](docs/PRODUCT-PLAN-AZ.md)
- [Current status (Azerbaijani)](docs/STATUS-AZ.md)
- [Roadmap](docs/ROADMAP.md)
- [Engineering and signing workflow](docs/ENGINEERING.md)
- [Implemented security invariants](docs/SECURITY-INVARIANTS.md)
- [Protocol lab scope and next gates](docs/PROTOCOL-LAB.md)
- [RDP boundaries and remaining native gates](docs/adr/0003-rdp-precredential-boundaries.md)
- [Native RDP lab evidence and limits](docs/NATIVE-RDP-LAB.md)
- [Browser RDP lab evidence and limits](docs/BROWSER-RDP-LAB.md)
- [Password identity lab and remaining MFA gates](docs/IDENTITY-LAB.md)
- [Durable MFA/custody lab and operator usage](docs/CUSTODY-LAB.md)
- [Account-owned SSH/RDP session integration](docs/OWNED-REMOTE-LAB.md)
- [Try the local interactive UI demo (Azerbaijani)](docs/INTERACTIVE-DEMO-AZ.md)
- [Remaining product steps (Azerbaijani)](docs/READY-CHECKLIST-AZ.md)
- [Pinned SSH dependency review](docs/DEPENDENCIES.md)

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

The maintainer authorized public repository development. A source license and
production release have not yet been selected. No independent audit is
claimed. The self-hosted gateway will need access to active credentials; the
vault is not a zero-knowledge guarantee against host compromise.
