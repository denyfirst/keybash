# Protocol dependency review

Reviewed on 2026-10-13 for the SSH library lab, not an entire product release.
Maintainer/update owner: Denyfirst. Keep exact module versions and checksums;
review each upgrade and rerun dependency, vulnerability and protocol gates.

## Adopted SSH dependency

`golang.org/x/crypto v0.58.0` (tag commit
`8fdf07b3114278fb3b78c1cf1814e08bd851eb4c`, published 2026-10-09) is the Go
extended crypto module, maintained through the Go project. It requires Go
1.26.0; Keybash remains pinned to Go 1.26.9. The direct runtime import is
`golang.org/x/crypto/ssh`. Use `go mod verify` and the checksum database; no
vendored protocol fork, custom crypto or external SSH executable is introduced.

License: BSD-3-Clause. Original license texts for crypto, sys and term are in
`third-party/`; ship applicable notices with future artifacts. Keybash's own
source license remains a separate decision. A library license does not assign
a license to Keybash.

The graph also selects `x/sys v0.49.0`, `x/term v0.47.0`, `x/net v0.60.0` and
`x/text v0.43.0`. `x/sys` supplies architecture-dependent CPU support. `x/term`
is reached by upstream SSH tests, not our terminal implementation. net/text
are upstream module requirements, not current Keybash runtime imports.
`go.mod`, `go.sum`, `go mod graph`, `go mod why -m`, and per-platform package
inventories are the source of truth; the graph is not a runtime SBOM.

## Vulnerability result and excluded code

`govulncheck -show verbose ./...` found zero affected imported packages and
zero reachable vulnerable symbols on the reviewed source. It also reported
module-level [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932): the module's
unmaintained OpenPGP packages, with no fixed version. Keybash does not import
them. This is not a claim that the whole crypto module is vulnerability-free.
Local and CI gates reject OpenPGP imports, including test/transitive imports.
Do not waive a future reachable SSH vulnerability based on this scoped result.

## Parser, protocol and resource review

Inspected the pinned module source: `client.go`, `client_auth.go`,
`handshake.go`, `common.go`, `cipher.go` and `channel.go`. Host-key signature
verification and our pin callback precede client authentication. The library
tries `none` before supplied auth methods; Keybash refuses setup unless its
verified signer actually signed. No password, keyboard-interactive or agent
fallback is configured. Host and user keys are Ed25519-only for this lab;
certificate and RSA/ECDSA support require separate review and tests.

Key exchange and ciphers use `SupportedAlgorithms()`, rather than legacy
defaults; MACs are explicitly SHA-256/SHA-512 (including EtM). Legacy key
exchange is refused. The pinned transport caps SSH packets at 256 KiB,
channel payloads at 32 KiB, and channel windows at 2 MiB. Its pending-packet
queue is bounded to 64 packets. These are source limits, not an installation
capacity guarantee. Use isolated workers and aggregate session quotas before
deployment; a malicious authenticated server can still consume resources.

Our public host pin input is at most 256 bytes; username is bounded ASCII;
setup has a ten-second total budget, cancellation closes transport, and PTY
dimensions/input frames are bounded. No private key parser, persistent trust
store, banner renderer or terminal escape parser is introduced in this slice.
Runtime connections use the guard's already-open stream, not `ssh.Dial`.
No forwarding handlers, local process or raw SSH client is exposed to callers.

## Remaining adoptions

xterm.js, browser transport, Guacamole/FreeRDP, database and vault dependencies
remain unapproved. Review their exact versions, full graph, license, advisories,
resource limits and update process before adding them.

Primary references: [SSH API at the pinned version](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/ssh),
[upstream source](https://github.com/golang/crypto/tree/v0.58.0/ssh), and
[Go vulnerability management](https://go.dev/doc/security/vuln/).
