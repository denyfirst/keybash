# Foundation verification

Scope: outbound IP target guard and repository workflow, not login, vault,
SSH/RDP sessions, clipboard or a deployable service. All test endpoints and
messages are synthetic. Dial tests use injected package-private test functions
and `net.Pipe`; no external network destination is contacted by the tests.

## Local evidence

PowerShell `./scripts/check.ps1 -Analysis` exercises formatting, module
verification, vet, shuffled tests, build, staticcheck, gosec, govulncheck and
actionlint. Analysis module versions were inspected and match CI pins.
Linux/macOS/Windows vet and build are also run. Linux race evidence comes from
CI because the local Windows environment is not the release environment.

The pinned toolchain is Go 1.26.9. The runtime module has no third-party
requirements. This does not pre-approve future SSH/RDP or crypto dependencies.

## Deliberate behavioral mutations

1. In `Policy.permitted`, changed the unapproved-target refusal condition to
   `!approved && false`. The source compiled, and
   `TestDialRejectsUnregisteredTargetWithoutNetwork` failed because an
   unregistered target was no longer denied. Restored the original bytes.
2. Changed the final successful `return canonical, true` in `Policy.permitted`
   to `return canonical, false`. The source compiled, and
   `TestDialApprovedPrivateTargetUsesLiteralAddress` failed for SSH, RDP and
   private IPv6 targets. Restored the original bytes.

The source hash after restoration matched the original hash, and the restored
test suite passed. Expected mutant failures are not failures in the submitted
source. These mutations test permissive and over-restrictive regressions.

## Separate adversarial maintainer self-review

Reviewed the final API boundary, literal-IP dials, mapped IPv4 handling,
protected-prefix precedence, metadata exclusions, private target usability,
error sanitization, cancellation and connection cleanup. Added explicit
refusal of standard IPv6 translation/tunnel ranges because mapped-address
normalization alone does not cover NAT64/6to4/Teredo. No custom resolver,
credential, production signing secret or network listener was introduced.

Reviewed private CI checkout and token lifetime: short-lived contents-read
token is used only in fetch/show steps, without storing credentials in Git
config. Signature verification trusts the base signer file and does not
execute PR code. Application tests do not receive a persisted checkout token.

This is implementation-session self-review, not an independent security audit.
Remaining limits are recorded in `SECURITY-INVARIANTS.md`, the product plan
and ADR 0001. Private branch protection was unavailable on the current GitHub
plan; the maintainer authorized public visibility so protection can be enforced.
Successful checks alone do not prove the server protection settings.

## Protocol lab slice 1: hostname-scoped pins (2026-10-13)

Scope: standard-library hostname selection and the TCP guard, with no SSH/RDP
implementation, credential or external server connection. The same local
analysis/build gates apply. Tests use only injected resolvers/dialers and
`net.Pipe`. Added a bounded hostname fuzz target; CI runs it for fifteen seconds
and local fuzzing ran for ten seconds without a failure. Linux race evidence
is obtained from CI, not inferred from local Windows tests.

Deliberate mutations of `named.go`:

1. Changed the per-target pin refusal condition to `!pinned && false`.
   Source compiled; `TestNamedTargetRebindingDoesNotApproveAnotherServer`
   failed when DNS rebound to a different globally approved server.
2. Replaced the final allowed TCP call with `return nil, ErrDenied`.
   Source compiled; `TestNamedTargetResolvesOnceAndDialsPinnedLiteral`
   failed for the usable private IPv4/IPv6 and mapped targets on SSH/RDP ports.
3. Disabled the late-success cancellation branch in `policy.go` with an
   always-false conjunction. Source compiled;
   `TestCanceledSuccessfulDialClosesConnection` failed. Restored original bytes.

Restored original source bytes after each mutation, checked byte equality,
and reran the suite successfully. Statement coverage was 100% for the package;
coverage alone is not evidence of complete security or browser usability.

Separate adversarial maintainer self-review: checked hostname bounds, label
syntax, root-dot/search-domain handling in pinned Go resolver source, copied
pins, global-policy versus per-target approval, full-answer refusal, mapped
IPv4, cancellation before/after resolution, sanitized DNS errors and lack of
second hostname resolution. Found that the pre-existing guard could return
a connection after the dialer reported late success with a canceled context.
Added close-and-refuse handling and a behavioral test. Reviewed the restored
final source and the first-answer/no-fallback availability tradeoff separately
from implementation. No dependency or real credential was introduced.

This remains implementation-session maintainer self-review, not an independent
audit. It proves a library boundary under synthetic transports, not integration
with SSH, guacd, a browser, installation DNS or network isolation. Outstanding
protocol adoption and identity checks are recorded in `PROTOCOL-LAB.md`.

## Protocol lab slice 2: SSH host identity and PTY (2026-10-13)

Scope: reviewed/pinned SSH dependency, guarded stream integration, host identity,
key authentication and one remote session channel. A synthetic echo server uses
fresh Ed25519 keys and an ephemeral loopback TCP listener. Only tests listen;
the production library has no listener, local process, credential import or
browser route. No external server or real user credential is contacted/loaded.

Tests demonstrate changed-key refusal before server authentication callbacks or
user signatures; refusal of none-auth, authentication/PTY/shell failures and
legacy negotiation; exact Unicode/control-byte input/output; resize and extended
output; frame/dimension limits; unsolicited forwarding refusal; deadline cleanup;
active cancellation of readers and backpressured output. They exercise the SSH
wire protocol, not a real Bash/OS PTY or browser clipboard. Host-key configuration
fuzzing ran locally for ten seconds without a failure; CI runs it for fifteen.

Compiled security mutations, all followed by byte-for-byte source restoration:

1. Added `&& false` to host pin mismatch refusal:
   `TestSSHChangedHostKeyStopsBeforeAuthentication` failed.
2. Reversed host pin comparison to reject the approved key:
   `TestSSHVerifiedKeyOpensRemotePTYWithExactUnicodeInputAndResize` failed.
3. Disabled signed-key enforcement with `&& false`: the none-auth subtest in
   `TestSSHRefusesNoneAuthAndAuthenticationOrPTYFailure` failed.
4. Removed active context cancellation's close call:
   `TestSSHSessionCancellationUnblocksReadersAndClosesRemote` failed.
5. Added a temporary blank OpenPGP import. The source compiled; the local
   dependency gate refused it before application tests. Removed the import and
   verified original source bytes. CI applies the same dependency exclusion.

Restored local format/module/vet/tests/build/analysis gates and platform builds
apply as before. Dependency scan detail matters: zero imported-package and
reachable-symbol vulnerabilities, with the excluded module-only OpenPGP advisory
recorded in `DEPENDENCIES.md`. Do not describe the entire module as clean.
Linux race/fuzz evidence comes from CI; Windows compilation is not race evidence.

Separate adversarial maintainer self-review inspected final trust and cleanup
paths: trusted per-target host pin, no second dial, Ed25519-only identities,
supported algorithms/SHA-2 MACs, signer gating, no fallback, none-auth refusal,
setup deadline transfer, close on failures, context watcher shutdown, channel
request denial, and bounded input/size. Fixed EOF normalization so wrapped EOF
diagnostics cannot cross the public error boundary. Reviewed parser/queue/channel
limits from the pinned dependency, graph/license notices, and excluded OpenPGP.
Shuffled gates exposed a transport/context timer ordering race: raw deadline
could expire while context Err remained nil. Added elapsed-deadline classification
and deterministic evidence, then reran the restored gates.

This is implementation-session self-review, not an independent audit. Host-key
rotation UI, ownership/auth/vault, actual Linux shell/browser matrix, worker
isolation, aggregate quotas, idle/revocation policy, SSH exit-status UX and RDP
remain unimplemented. Buffered output already received before close can still
be read; a future application must enforce revocation on its output path too.

## Protocol lab slice 3: local browser terminal (2026-10-13)

Edge verified locally against fresh-key synthetic SSH, with clipboard APIs
mocked so the workstation clipboard is not read or changed. Native Linux
Chromium clipboard/Bash PTY, Unicode, bracketed paste, no appended Enter,
Ctrl+C and kernel resize are required CI gates. The test harness has no lasting
service; its private bootstrap code travels on child stdin and is never printed.
Only the isolated browser test accepts the fixture's self-signed HTTPS certificate.
The handler still enforces TLS 1.3, loopback peer, Host and exact Origin.

Local Node paste/frame tests, ten-second control fuzzing, Go format/module/vet/
shuffled tests/build/analysis, dependency audits and platform compilation apply.
Vendor reconstruction from locked xterm bytes must produce a clean Git tree.
Browser requests are checked for external origins; this is page-level evidence,
not a complete installation egress capture or full browser/OS matrix.

Behavioral mutations all compiled/loaded and failed the intended assertions:

1. Removed owner-cookie refusal: `TestLabSocketRequiresExactOriginOwnerAndSingleSession` failed.
2. Reversed owner-cookie refusal to deny a valid owner:
   `TestLabInputResizeOutputCreditAndLogoutRevocation` failed.
3. Disabled mandatory Origin comparison: missing-Origin owner socket test failed.
4. Replaced output-credit wait with an immediate timer:
   `TestLabOutputWaitsForMatchingCredit` failed.
5. Forced paste review false: Node control/multiline review assertions failed.
6. Refused every otherwise allowed paste: Node allowed-input assertions failed.

Restored original source bytes after every mutation and reran the affected
gates. No mutated code, traces, credentials or diagnostic artifacts are tracked.

Separate adversarial maintainer self-review checked grant replay/expiry, cookie
flags, exact origin and host, loopback peer enforcement, one active slot,
cancel/close ordering, bounded render credit/rate and strict unique control
fields. Added peer checks to prevent accidental externally bound lab exposure;
disposed the renderer and dropped late frames on logout. Clipboard failure
callbacks cannot reopen a panel after revocation. Reviewed test-only shell
environment, temporary working directory, process-group/FD cleanup, JS graph,
vendor bytes, CSP style tradeoff and absence of remote asset/HTML rendering.

This remains maintainer self-review, not an independent security audit. Lab
capability authentication is not production auth/vault/ownership. Real network
hosts, load, vim/nano/tmux/htop, native Windows/macOS clipboard and Safari/Firefox
remain future evidence. No product deployment or release is created here.
