# Foundation verification

## Interactive workstation UI preview — 2026-10-15

`scripts/demo.ps1` opens a disposable Edge development context and a private
loopback TLS fixture for manual feedback. `INTERACTIVE-DEMO-AZ.md` states the
simulation boundary. Synthetic terminal commands never spawn a local process
or dial a host; desktop PNGs and input are a generated test picture, not Windows
or a native RDP authentication claim. Simulated workers and portable custody
initialization are confined to browserlab `_test.go` files. Runtime embedding
does not include the demo driver; `cmd/keybash` gains no flag/permission bypass.

The normal browser UI performs one-use bootstrap and mandatory MFA. Initial
reauthentication consumes an ordinary recovery code rather than replaying the
enrollment TOTP or racing the 30-second boundary. Owned credentials/connections
are seeded through the normal CSRF-protected APIs after proof. No ready session
is injected, no policy/pin check is weakened and no production data is loaded.
The separate about:blank guide exposes only synthetic account/factor data in
its disposable context; passwords/keys are passed to the driver through stdin,
not arguments, URLs, environment or log output. The guide is never a product
route or an injected application script. Self-signed acceptance is scoped to
the development browser context; OS trust and normal profiles stay unchanged.

Local `scripts/check.ps1 -Analysis` passed formatting, module verification,
vet, shuffled suites, builds, staticcheck, gosec, govulncheck and actionlint.
Tagged vet and `scripts/demo.ps1 -Check` passed on Edge. The latter verifies
the guide and its workspace action, MFA refusal before enrollment, two owned
sample connections, actual terminal echo, independently compared desktop
pixels after keyboard and mouse input, and account logout removing both views.
Workspace, terminal and desktop screenshots were visually inspected; no secret
reveal was photographed. The headed launcher was also opened successfully for
manual feedback. Linux CI additionally runs the new checks under race/Chromium,
retaining all prior native RDP, protocol, browser and fuzz gates.

Three compiling behavioral sabotages failed the intended assertions, then the
original source was restored byte-for-byte and the demo/browser checks reran:

- Permit a clipboard instruction: unsafe/malformed input refusal failed.
- Refuse every input: the valid key/mouse acceptance assertion failed.
- Remove SSH fixture context closure: cancellation did not release its read.

### Separate adversarial maintainer self-review

Reviewed the preview after implementation for production seam leakage,
process/dial paths, bounded command/input/image work and queues, cancellation,
sample secret handling, ordinary MFA/CSRF/owner admission, browser context and
TLS scope, helper-page access, disclosure labels and actual input assertions.
The guide's initially collapsed recovery textarea caused a browser timeout;
initialization now sets the synthetic value without requiring a hidden form
control to be interactable. Pixel comparisons replaced a weaker check that
could pass on the initial image. Both guide and desktop behavior now run in
the automated path, not just in a manual-only branch.

This is maintainer self-review, not independent audit. A preview cannot validate
real Windows/Linux sessions, shell programs, browser clipboard/keyboard matrix,
native RDP resize/clipboard, worker installation or production deployment.
The existing session/output quotas remain. Shutdown is bounded to one hour;
abrupt termination may leave synthetic encrypted test files/temporary browser
profile remnants. No forensic erase, general browser/host egress sandbox or
production readiness claim. No new dependency, release, or Porch/Rootwell change.

## Owned remote-session follow-up — 2026-10-15

`OWNED-REMOTE-LAB.md` describes the linked synthetic account/MFA/custody,
owned connection and SSH/native RDP browser boundary. The prior main CI and
CodeQL repeats passed before this branch began. No real credential, service
deployment or release; Porch/Rootwell remain untouched.

The local full formatting/module/vet/shuffled-suite/build/staticcheck/gosec/
govulncheck/actionlint gate passed, plus Linux tagged cross-vet/analysis and
Edge's existing password/custody/terminal/RDP fixtures. The portable owned
browser fixture exercises bootstrap, mandatory MFA, own credential import,
connection UI, exact terminal input and cross-tab account logout. Required CI
adds the actual SSH key-auth/PTY fixture and isolated native RDP NLA/viewer/
broker path with the same public identity/custody/connection API. Native-only
loopback substitutions are confined to test files. These are laboratory
measurements, not a production isolated SSH-worker or shipped RDP launcher.

Behavioral source mutations were each checked against their intended assertion,
then restored byte-for-byte in finally blocks:

| Mutation | Intended detection |
|---|---|
| Remove exact browser-session binding | other browser consumed lease |
| Permit an already active capability | lease replay accepted |
| Remove pending/consumption expiry checks | expired lease accepted |
| Permit a third owner lease | returned 200 instead of expected 429 |
| Refuse all otherwise valid grants | returned 401 instead of expected 200 |
| Omit stored approval comparison | changed approval silently retargeted connection |
| Omit owner from envelope AAD | connection ciphertext owner rebind accepted |
| Omit connection-deletion cancellation | connection deletion did not revoke |
| Skip fresh proof during consumption | stale proof redeemed lease |
| Ignore ready-stage loss during cancellation sweep | MFA downgrade retained remote output authority |
| Count all successful RDP protocol frames as activity | output-driven RDP credit extended idle |

### Separate adversarial maintainer self-review

Reviewed the final admission path separately: immutable guarded catalog/pin
copies and changed-approval binding; optional encrypted connection namespace;
cross-account and cross-browser references; fresh MFA at grant and consumption;
one-use/expiry/quota accounting; first-frame CSRF before worker invocation;
setup/owner/request cancellation and late stream cleanup; account-revision,
credential/connection deletion; locks versus network writes and slow bodies;
bounded parser/input/output work; trusted launcher contract, asset escaping,
secret URL/storage absence and abandoned/BFCache browser state.

Findings fixed: responses/assets no longer hold the account mutex while writing;
pre-proof upgraded sockets have their own owner/aggregate cap and logout
cancellation; account input rechecks its lease context; copied target approval
fingerprints prevent retargeting after catalog replacement; retired pages
cannot start late async connections.
MFA replacement also immediately revokes that browser's pending/active remote
leases as it reenters enrollment, including output-only sessions; the old
account factor remains intact until replacement confirmation. The portable
duplex pipe exposed an
existing relay deadlock: input writes blocked the same reader that needed to
consume output ACKs. A bounded ordered 32-frame input/resize worker keeps ACK
reads available, closes on overflow and joins on cancellation. The portable
browser regression now passes; existing terminal/RDP gates are repeated.
RDP idle accounting also distinguishes successfully validated key/mouse input
from output-driven Guacamole ack/sync/nop frames; refused input cannot refresh
idle. An explicit regression and bypass mutation cover this distinction.

Limits: trusted worker implementations must enforce their own TLS/SSH identity
and cooperative cancellation; only the stock SSH connector and synthetic native
launcher are measured. No production RDP launcher, installed SSH sandbox,
operator catalog deployment/configuration, trust UI, complete browser/server/
clipboard/load matrix or restore/rotation is claimed. SSH disconnect cannot
guarantee killing remote background processes. Whole-database rollback and
service/key-holder compromise remain in the documented custody threat model.
This is maintainer self-review, not independent audit. Candidate independent
security review and finding resolution still precede production release.

## Durable custody follow-up — 2026-10-15

The earlier sections are historical foundation/protocol/password-lab evidence.
This follow-up covers the implemented Linux loopback durable identity/custody
boundary described in `CUSTODY-LAB.md`, using synthetic accounts/keys only.
The local full analysis gate passed: formatting, bounded paste tests, module
verification, shuffled Go tests/vet/build, staticcheck, gosec, govulncheck and
actionlint. Linux vet/build/staticcheck/gosec also ran by cross-targeting the
local analysis; Linux runtime permission/CLI/race and native/browser gates are
required CI evidence, not inferred from Windows tests. Edge exercised the old
password lab and new bootstrap/MFA/custody browser fixture. Its account screen
was visually inspected; no production server or real credentials were used.

Deliberate source sabotage produced the intended failing assertions:

| Mutation | Intended failing observation |
|---|---|
| Remove bootstrap expiry | expired bootstrap accepted |
| Refuse every bootstrap as expired | valid bootstrap denied |
| Remove ready-stage requirement | password-only session opened vault |
| Remove fresh-proof requirement | credential POST returned 200 instead of 403 |
| Ignore greatest consumed OTP counter | enrollment OTP replay accepted |
| Keep a consumed recovery digest | recovery code replay accepted |
| Omit owner from AAD | ciphertext rebind to another owner accepted |
| Refuse every parsed valid SSH key | valid Ed25519 key import refused |
| Allow owner credential number 257 | owner credential quota bypassed |
| Allow wrapping after the 2^31 cap | wrap message limit bypassed |

Each temporary edit was restored byte-for-byte in a finally block before the
next case; the final local gates then passed on restored source. Initial
diagnostic assertion strings were corrected to match the actual test messages,
and the affected sabotage was repeated successfully. No failed test/build was
treated as an intended detection without checking its assertion. Native RDP
identity/input/viewer mutation gates continue unchanged in required CI.

CodeQL follow-up: its initial password-hash query classified random recovery
tokens as user passwords. Login passwords already use Argon2id. Recovery
verifiers now additionally use HMAC-SHA256 under an independently HKDF-derived
instance/purpose key rather than an unkeyed random-token digest. The alert is
addressed in code, not dismissed. Instance/owner/purpose binding is directly
tested, and follow-up sabotage of the MAC key and code-dependent verifier was
detected before restoration and repeat gates. No existing production schema
or user database is migrated: this remains an unreleased synthetic laboratory.

Linux CI correctly refused the original portable fixture's final data root:
Go's numbered `testing.TempDir` child follows the process umask and was 0755.
The fixture now creates its own explicit 0700 data child, matching the Linux
provisioning/CLI tests. Production permission requirements remain enforced.

### Adversarial maintainer self-review

Reviewed the final trust transitions separately from implementation: setup
code race/expiry/reissue, exclusive DB access, key separation/private file
admission, envelope/tag/owner binding, metadata authentication and message
budget, durable failure/recovery/replay transactions, immutable IDs/revisions,
password-only/fresh authority, in-flight KDF/import work, HTTP/body-lock and
secret-response cancellation, offline recovery, browser DOM/storage/history,
seed/codes visibility and dependency/parser limits. Findings fixed included
committing invalid MFA attempt budgets rather than rolling them back, keeping
the active seed during replacement, validating the Ed25519 seed/public halves,
reading slow bodies before the session mutex, and waiting for canceled-write
callbacks before a handler can finish/reuse its response writer. Random-nonce
GCM's nil argument is its documented API; narrowly scoped analysis annotations
explain that fact and intentional secret serialization into encryption.

Explicit limits: local service/key-holder compromise is trusted, old DB restore
can resurrect factor/recovery state, no crash/power-loss injection or tested
key rotation/restore, no real credential/remote-worker integration, no complete
browser/OS/clipboard matrix, process-memory erasure or DDoS guarantee. The
blocklist is deliberately limited and barcode transitive maintenance remains
an update review point. This is maintainer self-review, not independent audit.
An exact candidate independent security review and material-finding resolution
remain mandatory before first production credential/remote-access release.

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
The first Linux race run found that a parent-shell readiness marker could
precede foreground-group assignment for the sleeping child. The interrupt test
now waits for a marker emitted by that foreground child itself; no timeout,
assertion or required gate was weakened.

This remains maintainer self-review, not an independent security audit. Lab
capability authentication is not production auth/vault/ownership. Real network
hosts, load, vim/nano/tmux/htop, native Windows/macOS clipboard and Safari/Firefox
remain future evidence. No product deployment or release is created here.

## Protocol lab slice 4a: credential-free RDP boundaries (2026-10-13)

Fresh in-memory certificate/key loopback fixtures perform initial RDP HYBRID
negotiation and real Go TLS 1.2/1.3 handshakes, then observe closure without
application data. Ed25519, RSA and ECDSA succeed; changed/expired/future/client-
purpose/CA/missing-usage certificates, weak RSA and old TLS fail. Fixed-size
confirmation tests refuse downgrade, missing negotiation, malformed framing,
failure responses and remote lengths. Cancellation during negotiation and TLS,
stalled-write deadlines, late dial success and failed-dial cleanup are covered.
These are not CredSSP, Windows account or native FreeRDP interoperability tests.

The first PR scan flagged the custom-pin TLS configuration's disabled standard
certificate verification. The final model imports a copied bounded approved
leaf as the only trust anchor, keeps standard TLS/name verification enabled,
and additionally requires the exact DER pin. Tests refuse hostname mismatch,
missing roots, invalid imports/CN-only names, and changed pins even when a
broader test-only trust pool would otherwise accept the certificate. No scan
finding was dismissed and no rule was disabled. The first Linux worker run
also found that UID 65534 could not traverse the runner's private temporary
directory. The final test binary lives in its own temporary /tmp directory;
only that directory/binary is executable by the fixed child, with cleanup.
Runner directory permissions and child privilege restrictions remain intact.

Private wire/text tests cover split UTF-8/emoji, CRLF/LF and arbitrary text bytes,
both directions and distinct sessions, exact 32 KiB success/overquota refusal,
canonical base64, MIME/type/stream/replay refusal and buffer clearing. HTML is
not a permitted clipboard format. No browser/OS clipboard or desktop is used.
Local ten-second fuzz runs cover confirmation and combined instruction/text
parsing; CI requires fifteen-second runs plus Linux race/shuffle and cross-vet/
build. Standard Go/Node/static/security/vulnerability/workflow gates still apply.
No new module or vendored native/browser dependency.

Behavioral mutations compiled and failed their intended assertions:

1. Skip digest mismatch refusal: changed-pin identity tests failed, including
   a changed certificate otherwise accepted by a test-only broader trust pool.
2. Refuse matching digest: valid TLS 1.2/1.3 probe tests failed.
3. Accept TLS/legacy selection along with HYBRID: downgrade test failed.
4. Admit HTML clipboard: HTML refusal test failed.
5. Refuse text/plain: valid Unicode stream test failed.
6. Skip cumulative text quota: overquota test failed.

Original source bytes were restored after each mutation, then affected tests
reran successfully. Mutations and diagnostic outputs are not tracked.
Pin mutations were repeated after enabling standard TLS/name verification.

Required CI's tagged worker experiment creates a transient empty netns, drops
UID/GID/groups/all capabilities and sets no-new-privileges, then runs the fixed
test child with an empty environment apart from synthetic test metadata. Child
assertions verify the namespace/interface/identity and refused loopback/IPv4/
IPv6 TCP and DNS UDP. The host loopback sentinel observes no connection. The
same child run without namespace creation must fail the namespace assertion;
there is no skip on setup failure. This is test-only network isolation, not a
native worker, filesystem sandbox or approved-target broker.

Separate adversarial maintainer self-review inspected raw transport ownership,
cancellation/timer order, remote-size allocation, independent DER pin trust,
TLS cipher floor, usage/key/critical-extension policy, no credential or returned
connection, per-direction buffer ownership, poisoned-stream cleanup and tagged
root setup/privilege drop. Added explicit AEAD TLS 1.2 suites and refusal of
unhandled critical extensions. Checked that probe success is documented as
incapable of authorizing a later native connection, and that the code exposes
no guacd launcher, browser tunnel or raw instruction forwarding entry point.

This is maintainer self-review, not independent audit. Native source/build/CVE
inventory, actual pin and CredSSP behavior, usable approved-only egress and
filesystem/resource sandbox, desktop/browser clipboard, ownership/vault and
production packaging remain gates in ADR 0003. No real credentials, deployment
or release are used/created. Porch and Rootwell remain untouched.


## Protocol lab slice 4b: isolated native RDP (2026-10-14)

The pinned Guacamole 1.6.0/FreeRDP 3.32.2 Linux source builder verifies archives
before extraction, preserves license/NOTICE and records OS/native inventory.
The actual C callback compiles with warnings as errors and passes separate
Clang analysis. Native CI at `88abfb4` passed synthetic correct/incorrect NLA
password, decoded primary-surface PNG output, broker/worker revocation, wrong
IPC UID, sandbox/removed-netns checks and the full certificate/downgrade matrix.
The final refusal cases additionally require closure before context expiry;
a timeout alone must fail. No real remote accounts or production service.

Both directions of actual native identity sabotage compiled and failed their
intended assertions in required CI:

1. Replace the native C callback with unconditional acceptance: the changed-leaf
   peer observed CredSSP data and failed "native worker sent CredSSP before
   certificate refusal".
2. Replace it with unconditional refusal: the valid account failed "native
   account did not authenticate".

The disposable callback was restored byte-for-byte against the repository's
source, rebuilt, and the full native matrix passed again. Mutated code and CI
inventories/diagnostics are not tracked. Earlier Go mutations also failed valid
and refusal assertions: NLA-to-legacy parameters, deny-all valid plan/broker,
reusable broker, excess per-direction quota and both permissive/restrictive
paste-review behavior. Original bytes were restored and affected tests rerun.

Separate adversarial maintainer self-review examined actual TLS-before-CredSSP
ordering, independent name/pin binding, read-only trust/IPC capabilities,
SO_PEERCRED, real host UID/capability drop after trusted mount setup, process
lifetime and raw-stream cancellation/quotas. Checked exact argument-schema drift
refusal, no credential retry/TOFU/cleartext account cookie, GDI PostConnect
lifecycle and first native event error retention. Continuous event batches are
bounded before display/input work. Native clipboard, touch, dynamic display,
files, arbitrary channels, audio, gateway, drive and recording stay disabled.
Concurrent PNG test streams have individual/aggregate, dimension and layer
limits; that test consumer is not a browser instruction validation boundary.
Temporary GDB stack tooling was removed after the rendering diagnosis.

The Linux browser gate exposed queued dialog-close events clearing a newly
reopened paste preview. Close handlers now check whether the dialog is still
closed; an atomic close/reopen regression preserves the new preview/pending
input and confirms canceled text does not transmit. Local Edge evidence uses
its existing mocked clipboard; required Linux Chromium/real-Bash evidence
remains part of the final CI gate.

The full CI run then hit a duration-fuzz cancellation failure with no reported
crashing input. The pinned Go source retains the parent/child cancellation
window described in [Go #75804](https://github.com/golang/go/issues/75804).
CI now uses the documented count budget: every fuzz target must complete two
million executions with a hard three-minute timeout. No error is suppressed,
no failed run is treated as success and no check is disabled. This preserves
the pinned toolchain and supplies explicit fuzz work instead of duration-only
termination. The final CI gate must pass with this policy.

This remains maintainer self-review, not independent audit. Go/JS/actions
CodeQL and native Clang are separate evidence; C CodeQL is not claimed without
confirmed GitHub language coverage. Browser RDP/clipboard/keyboard/resize,
real Windows interoperability, production launcher/authorization/vault,
minimal runtime filesystem/syscall filtering, aggregate cgroup quotas,
packaging and independent candidate review remain required before production.
Porch and Rootwell remain untouched; no deployment or release was created.

## Protocol lab slice 4c: bounded browser RDP (2026-10-14)

The desktop profile reuses loopback TLS 1.3, exact Host/Origin, owner grant,
cookie, one-active-socket and expiry/logout controls. Official Apache JS is
bundled reproducibly with its source digest, per-module manifest and licenses;
the isolated public release-key verification is recorded in BROWSER-RDP-LAB.md.
The browser cannot select a target, credential, native argument or auxiliary
stream. The server adapter validates exact drawing/input shapes and state.

Local tests cover concurrent images and drawing order, preserved decoded pixels,
malformed/truncated PNGs, static normalization stripping ancillary/APNG metadata
and trailing content, SVG refusal, layer/canvas/stack/image/work limits, unsafe
or replayed input and blocked/late operations after cancellation. Local Edge
also measures pixels, actual key/mouse input, held Shift release on blur,
cookie flags, local asset requests, untouched clipboard/storage and display
removal after logout. Portable synthetic rendering alone is not native evidence.

The native/browser baseline at 8372713 passed required CI 38564471070: Chromium
rendered actual isolated native NLA output, the authenticated peer observed the
'a' key and mouse, changed icon pixels reached the browser, and logout stopped
worker/broker. The actual C identity acceptance/refusal mutations and restored
full native/browser matrix passed. All required checks and confirmed CodeQL
actions/C-C++/Go/Python/JavaScript-TypeScript checks passed that baseline.
The final static-PNG normalization and cumulative work limits require those
same gates again before merge. No native success is inferred from a ready UI.

Nine temporary, compiling behavioral mutations failed their intended assertions:

1. Allow header-only/truncated PNGs: invalid image reached the viewer.
2. Reject every drawing operation: valid native drawing refused.
3. Accept browser clipboard: unsafe opcode accepted.
4. Reject every browser input: valid viewer input refused.
5. Raise aggregate canvas quota: quota assertion failed.
6. Permit SVG image starts: unsafe drawing accepted.
7. Remove cumulative rendering cap: excess render work accepted.
8. Remove cumulative decoding cap: excess decoded pixels accepted.
9. Forward original PNG instead of normalized pixels: remote ancillary/animation/
   trailing content reached the browser.

The original source was restored byte-for-byte and all affected viewer tests
passed. Mutation diagnostics remain outside the repository. The new schema fuzz
target joins the existing targets at two million executions with a hard timeout;
no check or failure is suppressed.

Separate adversarial maintainer self-review examined upstream image/task ordering,
canvas rounding/autosizing, PNG-versus-browser decoder differences, compressed
amplification, cumulative work, interleaved-image deadlock, native/browser blob
ack ownership and display-sync credits, focus and held-key state, and revocation.
Findings produced static PNG re-encoding and lifetime work caps. The test-only
native peer now records exact input markers and independently authenticates;
the five-field native mouse metadata follows the pinned actual protocol shape.
Remote names/diagnostics never become application HTML. The reviewed CSP adds
Blob images only to the desktop profile; terminal permissions stay unchanged.

This is maintainer self-review, not independent audit. Native clipboard and
remote resize remain disabled; layouts/reconnect, real Windows/browser matrix,
login/MFA, ownership/vault, production worker packaging/quotas, restore and
independent candidate review remain gates. No real credential, installer,
deployment or release is introduced. Porch and Rootwell remain untouched.

## Identity slice 1: password login and session lifecycle (2026-10-15)

Read Porch's login/session and Rootwell's login/gate as references only;
implemented separate Keybash source and assets. No reference repository build,
Git operation or mutation. This first identity lab has named synthetic accounts
in memory, no persistent account store or real credentials, and no remote-access
entry point. MFA is explicitly absent, not silently treated as complete.

The existing pinned crypto module supplies Argon2id/Blake2b; no dependency
version changed. Fixed 64 MiB/three-pass/four-lane work, independent random salts,
opaque hash values, exact Unicode password bytes and constant-time comparison
are tested. The browser interface measures protected navigation, login/change/
logout, cookie flags and script invisibility, password clearing, no secret URL
or persistent browser storage, malformed account replies and uncertain logout.
Local Edge evidence is separate from required Linux Chromium/race evidence.

Unit tests observe correct/wrong/unknown/cross-account passwords, token rotation,
CSRF/Origin/Host/peer/TLS, duplicate cookies and strict JSON including lone
surrogates, attempt/KDF/session capacities, owner isolation, idle renewal,
non-renewing status, idle/absolute/background expiry and stale derivation/close.
The new JSON fuzz target performs no KDF and must complete two million executions
with a hard timeout in CI, alongside every existing target and native RDP gate.

Thirteen temporary compiling Go mutations failed the intended assertions:

1. Accept every password: wrong/unknown authentication assertion failed.
2. Reject every password: positive login assertion failed.
3. Bypass CSRF proof: unsafe request was accepted.
4. Accept duplicate session cookies: duplicate-cookie refusal failed.
5. Accept duplicate JSON fields: malformed-payload refusal failed.
6. Serve the account page anonymously: protected-navigation refusal failed.
7. Remove background expiry: idle context stayed live without another request.
8. Reject all live sessions: positive owner metadata assertion failed.
9. Ignore account revision after hashing: stale work created a session.
10. Revoke every account on password change: unrelated owner was revoked.
11. Ignore the global attempt budget: excess attempts were allowed.
12. Raise the owner session cap: owner quota assertion failed.
13. Delete a session without canceling: revoked context stayed live.

Two browser asset mutations also failed explicit assertions: refusing successful
login prevented the account page, and treating a failed DELETE as success
claimed an unconfirmed logout. Each source/asset was restored byte-for-byte;
affected unit/browser tests passed after restoration. Mutation outputs remain
outside the repository and contain only synthetic fixtures.

Separate adversarial maintainer self-review inspected fixed KDF work/queues,
cookie parsing and token rotation, account ownership and generation changes,
CSRF scope, cancellation/expiry, JSON repair/duplicate semantics, UI deadlines,
failure recovery and history restoration. Findings changed unknown-user attempt
handling to the same bounded policy as known names, refused invalid Unicode
before JSON repair, covered response bodies under deadlines, and prevented
Playwright failed-fill diagnostics from printing the synthetic password values.
The login screen was visually inspected in local Edge. No claim of NIST
compliance, DDoS resistance, exact process-memory bounds or guaranteed RAM erasure.

Final capacity review permits rotation of the current browser at capacity while
still refusing additional sessions; it cannot evict another browser. Positive
renewal-at-capacity and late password-change-after-logout tests were added.
Owner-cap and stale-revision sabotage were repeated on the final source; two
additional mutations (remove the aggregate session cap and permit password
change after logout) failed their intended assertions. Sources were restored
byte-for-byte and the identity suite reran. The local JSON fuzz target completed
two million executions within its hard three-minute timeout; minimization uses
the Go defaults and no error/retry suppression is added.

This is maintainer self-review, not independent audit. Memory-only password
changes disappear on restart; trusted setup supplies accounts. Stable IDs,
durable transactional hashes/revisions, operator bootstrap/recovery, blocklist,
MFA/replay/recovery-code controls, encrypted seed/vault custody and resource
authorization remain separate gates. This cookie cannot authorize SSH/RDP or
secrets. No production access, deployment or release; Porch/Rootwell untouched.
