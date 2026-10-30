# Protocol dependency review

## Interface typeface (2026-10-26)

The pages adopt the Denyfirst design Porch established, including its typeface:
Schibsted Grotesk, the variable Latin subset from
`@fontsource-variable/schibsted-grotesk` 5.3.0, under the SIL Open Font License
1.1 (`third-party/schibsted-grotesk-LICENSE.txt`). The file is byte-identical
to the one Porch pinned (SHA-256 `4c8b93f4…a75e05`), copied rather than
fetched; `web/assets_test.go` pins the hash, so a different file is a reviewed
change. A font is a program the browser parses, so it is served only from this
server with an exact `font/woff2` type and `nosniff`, every page policy limits
fonts to `font-src 'self'`, and no stylesheet loads any other URL or import.
It adds no Go or JavaScript dependency and nothing at runtime outside the page.

## Toolchain security update (2026-10-21)

The current pin is Go 1.26.10. The live vulnerability gate reported
GO-2026-6809 in crypto/x509 on 1.26.9; 1.26.10 contains the upstream certificate
verification correction. See the [Go release history](https://go.dev/doc/devel/release#go1.26.10).
Historical adoption notes below describe the toolchain at adoption time.
All native/browser/service and analysis gates must pass with the updated pin.

## RDP source runtime integration (2026-10-21)

Versions and source archive digests remain the pinned Guacamole 1.6.0/FreeRDP
3.32.2 reviewed below. `build-native-runtime.sh` shares the checked build between
the synthetic sample-enabled prefix and the empty-prefix server/sample-disabled
test-VM path. The installed manager runtime is staged from the latter. It
contains only guacd, its selected libraries and transitive loader/library closure,
the trusted builder's setpriv closure and fixed empty mountpoints. No browser,
sample server, source build tool, host /usr mount or vault file enters it.
The source-test package is not a signed/offline distributable or final SBOM.
Host library licensing/inventory, reproducibility and independent audit remain
release gates. User-space native loopback sockets are private to each worker.
The runtime inventory explicitly includes OpenSSL's distribution-supplied
`legacy.so` provider, which WinPR loads dynamically for NTLM's protocol MD4
operation and which `ldd` cannot discover. The module and its dependencies are
hash-bound; its fixed module directory is supplied only to guacd. This does not
enable weak TLS ciphers/certificates or change the Argon2id login password store.

The 21 October recheck includes the new [FreeRDP advisories](https://github.com/FreeRDP/FreeRDP/security/advisories),
including [DRDYNVC allocation bounds](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-rrp5-666j-g6gp)
(affected through 3.32.1, fixed in the existing 3.32.2 pin), and the current
[Apache security reports](https://guacamole.apache.org/security/). This is a
dated advisory review, not a vulnerability-free or independent-audit claim.
Distribution loader/library updates still belong to the supported-host/release
inventory and update policy.

Guacamole 1.6's common UTF-16 reader/writer treats individual 16-bit units as
characters. The RDP clipboard integration therefore adds a narrow adapter using
the already pinned WinPR conversion API, queried capacities, explicit UTF-16
surrogate/terminator checks and exact UTF-8 roundtrip validation. The adapter
copies a bounded snapshot under the native clipboard lock before querying or
converting, so concurrent clipboard updates cannot change its input. Only
CF_UNICODETEXT is advertised/requested; no lossy codepage fallback is enabled.
The codec tests compare golden wire bytes, empty/exact-limit text, malformed
UTF-8/UTF-16 and buffer bounds under ASan/UBSan. Both accept-all/refuse-all
mutations must fail the intended assertions before the normal test reruns.
Go/browser boundaries still validate complete UTF-8 independently. This changes
the RDP adapter, not the upstream common converter or other protocol support.

## Durable custody adoption (2026-10-15)

Pinned `go.etcd.io/bbolt v1.5.0` (MIT, tag
`e7a8b2dd498494a3766ba24dd94d3509e5588485`, released 2026-06-21), module sum
`h1:S7GAl7Fxv12yohbwFfIbQCGDWbQbtDGPET4P/bD4lxU=`. Reviewed pinned open,
exclusive locking, rooted OpenFile callback, fsync defaults, MaxSize allocation,
transaction rollback and bounded lookup/write behavior. It needs Go 1.25;
the existing Go 1.26.9 pin is unchanged. It uses the already pinned x/sys;
its dependency build/benchmark/test graph is not the runtime inventory.
No bbolt CLI, network service, dynamic module/plugin or migration auto-run.

Pinned `github.com/pquerna/otp v1.5.0` (Apache-2.0, tag
`5971b1ef1d6652fec2caed37f11e5cacd9249f78`, released 2025-05-16), sum
`h1:NMMR+WrmaqXU4EzdGJEE1aUUI0AMRzsp96fFFWNPwxs=`. Reviewed HOTP/TOTP
validation, digit/algorithm selection, seed decoding and skew adapter. Keybash
calls the six-digit SHA1 HMAC OTP API and owns transactional replay/budget
enforcement, not the cryptographic algorithm. The root library imports
`github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc` (MIT), sum
`h1:biVzkmvwrH8WK8raXaxBx6fRVTlJILwEwQGL1I/ByEI=`. This older transitive
dependency is retained explicitly in the inventory. Maintenance age limits this
adoption; monitor the OTP/module advisories, and review removal/update before
release. Do not silently update either dependency or widen the parser/import
surface.

## QR enrollment (2026-10-29)

The same pinned barcode module now becomes a direct dependency for one call:
`qr.Encode(uri, qr.M, qr.Auto)` in `identity.seedQR`, the encoder pquerna/otp's
own `Key.Image` uses. Reviewed at the pin: a pure-Go encoder with no I/O,
`unsafe` or reflection imports. Its module iteration runs two internal
goroutines that the same call drains to completion. No decoder and no image
codec is reached. The input is
only `otpauth://totp/Keybash:` with a validated account name, a server-made
base32 seed and a fixed issuer (at most 142 bytes), so no untrusted or
unbounded data is ever encoded. The output is checked to be a square of 21 to
57 modules before use. No barcode parsing, other symbology or `barcode.Scale`
is used. `TestSeedQRCarriesExactlyTheSeed` checks the drawing against an
independent reading of the QR format information (level M, both copies,
reading order), so a transposed or mirrored code fails. A full content decoder
is not part of the test; the factor confirmation with a current code remains
the end-to-end proof. The module and sum are unchanged.

Licenses are in `docs/third-party/`. `go list -deps`/`govulncheck` inventory
includes the existing crypto/sys packages, bbolt, OTP and barcode. Sum-file
entries additionally include upstream test/tool dependencies; they are not
all linked runtime packages. No newly adopted reachable symbol/package advisory
was reported by the scan; the excluded OpenPGP module advisory below remains.
This is neither independent audit nor a blanket vulnerability-free claim.

The embedded common-password dataset is SecLists
`Passwords/Common-Credentials/10k-most-common.txt`, Git blob
`a93ea7f91f095b38728795ecd6ec731e59b8c112`, SHA256
`68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce`.
Its MIT license is preserved as `docs/third-party/seclists-LICENSE.txt`
(source license blob `fbd3be5da1b5c7363ab6d581e4cc6a22a8893683`). It is
bundled data, not an online password lookup; no user password leaves self-host.
It needs deliberate corpus refresh/review and does not cover all breached
passwords. The test pins its exact bytes.

Primary references: [bbolt API](https://pkg.go.dev/go.etcd.io/bbolt@v1.5.0),
[pinned bbolt source](https://github.com/etcd-io/bbolt/tree/v1.5.0),
[OTP API](https://pkg.go.dev/github.com/pquerna/otp@v1.5.0/hotp),
[pinned OTP source](https://github.com/pquerna/otp/tree/v1.5.0),
[Go random-nonce GCM](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce),
[SecLists source](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials).

## Password identity adoption (2026-10-15)

The identity lab adds `golang.org/x/crypto/argon2` from the already pinned
v0.58.0 module, plus its `blake2b` implementation and architecture helpers.
No module/version or external identity service is added. Existing BSD notices
apply. Reviewed the pinned `IDKey` implementation/API, fixed-cost validation,
memory/work allocation, salt generation and constant-time digest comparison.
The library owns Argon2; Keybash does not implement or fork a password KDF.

The opaque lab hash fixes 64 MiB, three passes, four lanes, 16 random salt
bytes and 32 output bytes. There is no untrusted serialized cost field/parser.
Two concurrent derivations are allowed, with bounded attempts and no request
queue. The KDF itself is not interruptible; canceled/stale work must finish
within that fixed cost and cannot issue a session. These controls are not a
process-RAM limit or calibrated production throughput claim. Hash storage,
migration, password blocklist, MFA and durable encrypted seed custody are
separate gates in `IDENTITY-LAB.md`.

Local module verification and reachable-symbol/package vulnerability checks
passed; the existing excluded OpenPGP module advisory below remains relevant.
No claim that the entire crypto module is vulnerability-free. CI repeats these
checks, JSON fuzzing, race tests and the Chromium identity browser fixture.

Primary sources: [pinned Argon2 API](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/argon2),
[Go source](https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.58.0:argon2/argon2.go),
[OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## Original protocol review

Reviewed on 2026-10-13 for the SSH library lab, not an entire product release.
Maintainer/update owner: Denyfirst. Keep exact module versions and checksums;
review each upgrade and rerun dependency, vulnerability and protocol gates.

## Adopted SSH dependency

`golang.org/x/crypto v0.58.0` (tag commit
`8fdf07b3114278fb3b78c1cf1814e08bd851eb4c`, published 2026-10-09) is the Go
extended crypto module, maintained through the Go project. It requires Go
1.26.0; Keybash remains pinned to Go 1.26.9. The initial direct runtime import was
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

## Browser lab adoption (2026-10-13)

- `github.com/coder/websocket v1.8.15`: Coder-maintained Go WebSocket library,
  ISC license, no additional module requirements. Reviewed accept/origin rules,
  context closure, message limits and disabled compression. Our exact Origin,
  owner, TLS 1.3 and loopback checks precede upgrade; library defaults alone are
  insufficient because missing Origin is accepted by default. License retained.
- `github.com/creack/pty v1.1.24`: MIT, no additional module requirements;
  Linux test fixture only. Reviewed PTY creation, controlling session, resize and
  close/process cleanup. It is not imported by shipped runtime packages. Fixed
  Bash executable/arguments, a temporary directory and a minimal environment
  are confined to `_linux_test.go`; never expose this as a product worker.
- `@xterm/xterm 6.0.0`: MIT, no runtime dependencies. Exact registry integrity
  is locked in `web/pnpm-lock.yaml`; JS/CSS/license are served locally and their
  SHA-256 inventory is in `web/vendor/manifest.json`. `vendor.mjs` reconstructs
  them from the locked package; CI refuses differences. No CDN or attach addon.
- Playwright/core `1.64.0`: Apache-2.0, browser-test tooling only. Node `24.19.0`
  and pnpm `11.25.0` are CI tools; Node's official Linux archive SHA-256 is pinned
  before extraction. Install scripts are disabled; browser installation is an
  explicit test setup step. These are not runtime product requirements.

Go call/package scanning found no affected imported packages/reachable symbols;
the excluded OpenPGP module advisory above still applies. The locked JS graph
audit reported no known advisories. These dated scans do not replace review.

The lab caps WebSocket input at 32 KiB, control JSON at 1 KiB, and outgoing
frames at 8 KiB plus sequence. At most 32 outgoing frames await in-order
render credit; the original lab socket keeps an 8 MiB total output ceiling,
owned sessions have none. Two queued chunks and bounded stream reader buffers
bound memory. Duplicate/wrong/unsent credit
and unknown/duplicate control fields close the stream. Rate caps and absolute
expiry are lab controls, not an installation capacity or production login claim.

The browser certificate exception exists only in an isolated automated context
against a synthetic loopback TLS server; no system trust is modified. Windows
clipboard APIs are mocked so tests do not read/overwrite the user's clipboard.
Linux headless CI exercises native Clipboard API separately. Neither is a
full browser/OS permission matrix. Application code has no TLS-ignore option.

Sources: [xterm security](https://xtermjs.org/docs/guides/security/),
[Coder WebSocket](https://github.com/coder/websocket/tree/v1.8.15),
[PTY fixture library](https://github.com/creack/pty/tree/v1.1.24),
[Node checksums](https://nodejs.org/dist/v24.19.0/SHASUMS256.txt).

## Remaining adoptions

The native RDP lab uses test-only source builds of Guacamole 1.6.0 and
FreeRDP 3.32.2. Exact archives, integration changes, upstream/OS review, license
inventory and limits are recorded in `NATIVE-RDP-LAB.md`; required Linux CI
checks native success, refusal, decoded images, cancellation and actual C
callback sabotage in both directions, followed by restored-source verification. They are not adopted
as a production runtime or packaged/deployed service. The Go module graph adds
no version; x/sys becomes a direct test dependency for Unix peer credentials.
NTLM's MD4 SAM hash is confined to a synthetic `_linux_test.go` peer, not a vault
password hashing choice. Native vulnerability evidence is separate from Go's
govulncheck and the browser graph audit.

The credential-free RDP probe/private text codec introduces no module, native
binary or browser dependency. TLS uses the pinned Go standard library. Its
imported leaf is the only trust anchor; standard TLS/name checks remain enabled,
along with the mandatory exact DER pin and validity/usage/key constraints.
No credentials or live stream are
returned. It is not Guacamole's native certificate implementation. The tagged
Linux isolation fixture uses runner-provided util-linux unshare/setpriv and
sudo, and only a temporary fixed test child. This does not package a sandbox.
See ADR 0003 for limits and the native adoption gate.

Production Guacamole/FreeRDP, database and vault dependencies remain unapproved. Review
their exact versions, full graph, license, advisories,
resource limits and update process before adding them.

Primary references: [SSH API at the pinned version](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/ssh),
[upstream source](https://github.com/golang/crypto/tree/v0.58.0/ssh), and
[Go vulnerability management](https://go.dev/doc/security/vuln/).


## Browser RDP lab: Apache guacamole-common-js 1.6.0

The official client source archive is pinned to SHA-256
`81f9fd5a7b4377fb0ee295d0d4fec92e9667f2aafaa3d0ed8937f535deabdee4`.
Its release signature verified with Apache's published public signing key
`F467E54ACC52F1D2778826865B2977AEE5E4518F` in a separate temporary public keyring.
The source/security reports and JS display/parser/input code were reviewed on
14 October 2026. No blanket vulnerability-free or independent-audit claim.

`scripts/vendor-guacamole.py` verifies the archive before reading named members,
concatenates 35 unmodified modules deterministically and preserves LICENSE/NOTICE.
The manifest contains each module/file hash; required CI regenerates exact bytes.
No npm wrapper, new runtime package, Maven/Java application or CDN is adopted.
The existing xterm/pnpm assets remain unchanged. Node is copied into the disposable
native test prefix solely to run the verified headless browser harness.

The app uses a restricted custom tunnel and only the allowed drawing/input
subset. Auxiliary tunnel/audio/video helpers defined by the package are not
constructed or enabled. Only bounded, completely decoded and statically re-encoded PNGs can reach the
Blob-image renderer. Unsupported source URLs, SVG, arbitrary streams and
transforms are refused by the server adapter. The legacy lab also refuses
clipboard; the manager workspace admits only bounded completed plain text.
CSP stays self-only for scripts
with the existing reviewed inline-style allowance; the desktop profile adds
`img-src blob:`. It does not loosen the terminal profile. Source requests,
clipboard/storage absence and revocation are measured in the browser gates.

The manager workspace's native/browser text and display-update evidence is
tracked in `RDP-WORKSPACE-INTEGRATION.md`. Keyboard layouts/reconnect, real
Windows, production packaging and independent audit remain gates. Limits and API/source
references are in [the browser RDP lab](BROWSER-RDP-LAB.md).

## Operating-system marks (2026-10-30)

Connection cards can show the mark of the server's operating system, picked by
the connection's owner. The marks for Ubuntu, Debian, Fedora, Red Hat, Rocky
Linux, AlmaLinux, CentOS, Arch Linux, Alpine Linux, openSUSE, Linux Mint, Kali
Linux, Gentoo, NixOS, Raspberry Pi, FreeBSD, macOS (Apple) and Linux (Tux)
come from Simple Icons `simple-icons@16.35.0` (npm, released 2026-10-11),
licensed CC0-1.0. The licence is in `docs/third-party/simple-icons-LICENSE.md`
(SHA-256 `9046848b63a5c92bff14e4accca80bd987e0623b74adf9226ce5198d312b79d5`). Windows and the generic server are our own line drawings.

This follows the same rule as the bundled typeface. The data was copied once
from `cdn.jsdelivr.net/npm/simple-icons@16.35.0/icons/<slug>.svg`, fetched
twice by different clients with identical digests. Only each file's single
`path` data is kept, checked against `[MmLlHhVvCcSsQqTtAaZz0-9., -]`, in
`web/systems.mjs`, and drawn by DOM calls. No SVG file, script or URL is
shipped, nothing is fetched at runtime, and the CSP is unchanged. The server
accepts only these names (`TestSystemNamesMatchTheMarks`). Each mark is its
owner's trademark, shown only to say which system a server runs. Updating
means repeating this with a new pinned version and new digests.

| Mark | SHA-256 of the source SVG |
|---|---|
| almalinux | `d31e95e025c2299efb0fcbf64965081c5815ae32a54ad39db20b0c16327a6ef6` |
| alpinelinux | `d37d0a7873c65174308d63929f09ab93c3aaa7f5c5df79cdec4be532e015fc98` |
| apple | `2a1509dccd25e6d2bc7a11a8e52941077e1a48555e192ce638699b9f083c2a7c` |
| archlinux | `2b1d26b4a1194c40dc068b2aba4b3a5f9ea83b6a8f1da04c229d03fe80308bfa` |
| centos | `94a3ca4414ed77c8bdf1ff0bd6d40d64ac4e27bd863889af50044ab6167ce1fa` |
| debian | `8835536d63c80990f9c90c935982ba329d163e707c894278ca6bd73258d1962b` |
| fedora | `c234757373cab5ed80d7b2df8ff26ea039bcec16a9e9a47adbd29f5d0e94489a` |
| freebsd | `57c61b8658266e79ae3d753d367ebb56d5157e929fc72b2bc6ba7fe7a1059584` |
| gentoo | `894c74754481396130effc60dc3f3a4022bfa863c1ec78344f3c77bb9b73851f` |
| kalilinux | `0ceffe5e8ce02aae42f7f5f6cada390f79e5ab6450a4e460b03127a370c33a1a` |
| linux | `7e55f2779ae11a83c9dad2d0414a65d8ca7867d0716ce58bfe41ed299ae1447f` |
| linuxmint | `ab7e227a8e7b7d167d8bc4617c6323c205b4565ce1c206e6d1fd677669cd27d4` |
| nixos | `08e3442ba2b81fd8bb50c745ab354b96128a80e8884969f7dace33fe7d15a921` |
| opensuse | `22f842b1d6b2cf32b7b1a569708c2ca73bd5cae627def4e45e15d07915f0d6bf` |
| raspberrypi | `ab35cdb6cfd69779dfa54c8f15f0ed3c514ff6c07f1c941dd47a61115a208c59` |
| redhat | `3d0e1854a9dad1a8ad11132843f522f948197ec0e0ee49b7a51d5fdf44230568` |
| rockylinux | `a65476b168c4ef14c6b743e7eb3875e56c9d60ca15bbaef57a72a6cdeab242d0` |
| ubuntu | `b0aca674c881a07bb60b26afbcee07093ae419e29ee38e376f938817fa66ae03` |
