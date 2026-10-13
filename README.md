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
There is no login, vault, browser terminal, RDP gateway, deployment, or production
release yet. SSH tests use a synthetic server, not a real Linux shell/browser.

## Start here

- [Product plan (Azerbaijani)](docs/PRODUCT-PLAN-AZ.md)
- [Current status (Azerbaijani)](docs/STATUS-AZ.md)
- [Roadmap](docs/ROADMAP.md)
- [Engineering and signing workflow](docs/ENGINEERING.md)
- [Implemented security invariants](docs/SECURITY-INVARIANTS.md)
- [Protocol lab scope and next gates](docs/PROTOCOL-LAB.md)
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

## Independence and trust

Porch and Rootwell remain separate, read-only references. Keybash changes are
made only in this repository. It uses the existing Denyfirst public commit/tag
and separate release signer identities; private keys are never copied here.

The maintainer authorized public repository development. A source license and
production release have not yet been selected. No independent audit is
claimed. The self-hosted gateway will need access to active credentials; the
planned vault is not a zero-knowledge guarantee against host compromise.
