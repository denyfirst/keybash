# Foundation verification

## Source systemd services and aggregate kernel boundary — 2026-10-20

`LINUX-SERVICE-LAB.md` records the exact layout, source-only plan, identities,
finite profiles, startup guard, lifecycle, fixture scope and remaining gates.
The offline plan has no install/start action or arbitrary command/path inputs.
It refuses invalid identity/budget/digest settings and existing output. Its
four fixed public files use rooted exclusive staging. The generated gateway
has a dedicated UID/GID, no capabilities and private custody paths; its separate
root manager has a private network, narrowed capabilities and hidden custody
paths. An explicit different worker UID/GID is fixed at root startup, never
gateway IPC, and checked inside the unchanged protocol sandbox before input.
Both IDs omitted preserve legacy laboratory callers; partial pairs refuse.

The shared slice applies aggregate CPU/memory/swap/pids policy to both units
and inherited SSH descendants. ExecStartPre checks actual cgroup-v2 ancestry,
controller values and named/numeric service identities before runtime startup.
Missing, mismatched or unlimited kernel values refuse; root changes after
startup are trusted, not continuously monitored. Kernel memory enforcement can
end active sessions. It is deliberately not represented as a graceful busy
response or availability guarantee. Defaults are not measured sizing advice.

Portable tests cover accepted/refused profiles, command/directive injection,
mandatory unit boundaries, numeric overflow/malformed/unlimited kernel files,
wrong membership, swap bypass, outside-service refusal and dedicated/legacy
worker identities. Six compiling local mutations were executed: accept/refuse
service plans, bypass/refuse kernel validation, and accept/refuse worker IDs.
Each failed its intended assertion; sources restored byte-for-byte and both
affected packages reran successfully. Diagnostic logs are outside Git.
Local format/module/vet/shuffled full suite/build/staticcheck/gosec/govulncheck/
actionlint passed. Linux service-tagged cross-vet/staticcheck/gosec and test
compilation passed. Actual kernel execution requires the Linux CI gate below;
Windows cross-compilation is not execution evidence.

The required service gate builds and installs generated synthetic units only
on a disposable systemd/cgroup-v2 runner, refusing existing Keybash paths,
accounts, IDs and loaded units. It verifies the actual plan CLI/overwrite
refusal, systemd syntax, nonroot gateway trusted TLS, real synthetic SSH through
the root manager's inherited TCP descriptor, live dedicated child UID and
common cgroup, hidden custody key, stop/revocation/empty descendants and restart.
Each changed parent limit must refuse startup without a manager socket. Fixed
unprivileged probes require actual CPU throttling, pids rejection and OOM-kill
counters. A compiled launcher mutation deliberately uses the old worker UID;
the live-child identity assertion must fail, then sources/binaries restore and
the entire service gate reruns. Existing SSH/native RDP/browser/race/fuzz,
analysis and signature gates remain required with no bypass.

### Separate adversarial maintainer self-review

Reviewed offline template injection, staging overwrite/traversal, finite numeric
ranges and arithmetic, UID/GID narrowing and collisions, partial/default identity
semantics, root-only identity propagation, inherited descriptor/key separation,
worker self-check ordering, fixed service paths, runtime socket cleanup, cgroup
ancestry/inheritance, missing/unlimited controllers, supplementary groups,
capability/read-only/private-network compatibility, shutdown ordering and OOM
availability consequences. Go rooted staging replaces an unrestricted output
file open flagged by analysis. Kernel event counters prevent treating ordinary
probe failure or timeout as successful enforcement. The test cleanup uses its
own bounded context and removes only fixture-owned paths/identities/overrides.

No new dependency, browser authority, target/identity bypass, public listener,
secret URL/environment/logging, production install, release, Porch or Rootwell
change. Root/gateway/host remain trusted; manager CAP_SYS_ADMIN is still required
for namespace setup. The worker's older shared-per-UID NPROC backstop remains,
so the configured admission ceiling is not an active-workload guarantee. RDP
service/clipboard, production ingress, packaged install/upgrade/restore,
measured load/VM/browser matrix and independent exact-candidate audit remain.
This is separate maintainer self-review, not an independent security audit.

## Configurable finite remote capacity — 2026-10-20

`SESSION-CAPACITY.md` records the approved separation between operator-selected
parallelism and invariant parser/transport/resource safety controls. Capacity
is not a licensing tier. The existing root-owned catalog optionally contains
strict total/per-owner integers; a single runtime Catalog carries both targets
and capacity, so the latter cannot disappear through a target-only loader.
Existing catalogs/default lab callers retain 8/2. Explicit zero/null/unlimited,
invalid relationships, malformed/duplicate/unknown/coerced/overflow fields refuse.

The immutable validated policy is applied at pending/active lease admission,
independent pre-proof socket admission and separate SSH manager slots. Comparisons
and state changes use the original mutex/channel boundaries; no browser setter
exists. Fixed authenticated busy responses disclose no other owner's usage,
preserve live sessions and return capacity on existing cleanup paths. The
entry UI distinguishes full capacity from proof failure and rate budgets.
The same root-owned file is supplied to both CLIs and restart is required;
there is no cross-process live capacity negotiation. A smaller manager remains
an independent conservative backstop.

Portable tests cover defaults/custom/range boundaries, malformed settings,
invalid constructors, copied policy, three owners exceeding the old owner/global
constants, concurrency, pending expiry, logout, pre-proof socket refusal/return,
unchanged active leases and browser override refusal. The real Edge workflow
observes a blocked second connection, its named busy message, continued terminal
input/output and exactly one worker. The compiled Linux gateway gate now checks
configured 16/4 metadata after MFA. Linux manager gates use one actual SSH worker
plus pending reservations at capacities 1 and 10, and a separately compiled
manager CLI configured at ten; this is not a ten-active-worker benchmark.

Compiling local mutations must fail named assertions for accepting invalid
limits, refusing valid limits, ignoring catalog/gateway capacity, bypassing
owner/global lease caps, and accepting/refusing pre-proof sockets. A UI mutation
must fail its busy-message assertion. The required Linux gate mutates manager
overflow, use of the old default, and standalone CLI config propagation; original
sources/binaries are restored and affected gates rerun. Existing root provenance,
actual SSH/native RDP/browser/race/fuzz/signature/analysis gates stay required.
All eight local Go mutations and the UI mutation were executed, failed their
intended assertions, restored byte-for-byte and rerun successfully. Logs stay
outside Git. Final local format/module/vet/shuffled suite/build/staticcheck/
gosec/govulncheck/actionlint passed; Linux tagged cross-vet/staticcheck/gosec
and test compilation passed. The updated catalog fuzz run completed exactly
two million executions. Edge capacity and interactive SSH/RDP demo checks
passed. Actual Linux root/worker/mutation execution remains required CI evidence.

### Separate adversarial maintainer self-review

Reviewed operator provenance, optional-vs-malformed semantics, coherent snapshot
loading, integer bounds, immutable policy, independent lease/socket accounting,
counter release, concurrent admission, owner/CSRF/MFA boundaries, expired pending
leases, active-session preservation, manager pending/active slot lifetime and
root startup catalog parsing, both CLI propagation paths and fixed UI messages.

Findings shaped the code: runtime APIs return targets/capacity together; browser
payloads cannot override policy; zero means refusal in explicit JSON, not no cap;
attempt exhaustion remains HTTP 429 and capacity has a separate fixed 503 marker;
manager completion tests allow its conservative acknowledgement/release ordering
while measuring bounded capacity return. No new arbitrary exec, target/network
approval, secret URL/storage/logging, dependency or Porch/Rootwell change.

128 is an implementation admission ceiling, not a measured hardware promise.
Root/host/gateway remain trusted. Aggregate kernel CPU/RAM/pids enforcement,
installed service identities/units, production RDP/clipboard, load/VM/browser
profiles, recovery/release tooling and independent exact-candidate audit remain
gates. This is maintainer self-review, not an independent audit or a deployment.

## Offline operator catalog and SSH CLI — 2026-10-19

`OPERATOR-CATALOG-LAB.md` records the new administrator file boundary and the
explicit SSH-only integration command. Public target metadata is independent
of account credentials and browser owner decisions. One invalid entry refuses
the whole catalog; validation performs no network or worker operation. Runtime
loading admits only a bounded root-owned regular file through pinned no-follow
directory descriptors. No dependency, Porch/Rootwell, deployment or release
changes. Installed service/identity/cgroup/RDP/recovery/audit gates remain.

Portable tests measure accepted SSH and current RDP identities, certificate
name/time/purpose, exact keys/JSON, protected/forbidden endpoints, copied target
metadata, canceled dialing, duplicate IDs, array bounds and total byte limits.
The new fuzz target includes a valid public SSH catalog seed and malformed
inputs. Five local compiling mutations failed their intended assertions:
accept duplicate JSON keys; refuse all valid input; ignore protected networks;
ignore RDP identity refusal; accept an unsupported SSH host key algorithm.
Sources were restored byte-for-byte and affected package/CLI tests reran.
Diagnostic outputs are outside Git. Local full format/module/vet/shuffled suite/
build/staticcheck/gosec/govulncheck/actionlint passed; updated test-only inputs
were rerun. The local catalog fuzz run completed exactly two million executions.
Linux cross-vet/staticcheck/gosec and test compilation passed. Actual Linux
root/UID/race/process execution remains a required CI gate, separate from
Windows execution.

The required Linux operator gate executes root file refusal/success tests,
a separate UID/GID 65533 reader which cannot overwrite the catalog, and the
compiled CLI at that UID: private initialization, pinned trusted TLS,
unauthenticated/pre-MFA refusal, bootstrap/MFA, configured metadata and clean
SIGTERM. File-owner bypass/refusal, directory-owner bypass and symlink-follow
mutations must fail their named assertions; originals are restored byte-for-
byte and rerun. A new two-million-execution fuzz gate joins all ten fuzz targets.
Existing actual SSH-process/manager/native RDP/browser gates remain required.
The new CLI test does not dial the synthetic target or prove a complete real
SSH session through that command; the existing manager/worker tests exercise
those lower layers independently.
The first CI attempt passed actual root-file, separate-UID reader and compiled
CLI/MFA/SIGTERM checks, then exposed a helper build-path permission mistake:
the runner tried to write a mutant into the protected root-owned executable
directory. Builds/logs now use a separate runner-owned temporary directory;
the protected directory stays non-writable. No failure was suppressed/retried
as success. The CLI fixture also uses a current TOTP counter so a time-step
boundary cannot age its first proof outside the permitted window.

### Separate adversarial maintainer self-review

Reviewed schema confusion/escaped duplicates/nulls/surrogates, bounded reads,
whole-snapshot refusal, per-target pin isolation, identity/credential separation,
canonical network parsing and protected-range precedence, root provenance,
symlink/ancestor/hardlink/FIFO handling, mutable root snapshots, gateway UID,
launcher selection, loopback TLS and SIGTERM lifecycle. There is no catalog
HTTP write/discovery/probe, environment expansion or arbitrary exec path.

Findings shaped the implementation: protected networks must be explicit and
nonempty; different target policies do not share endpoint approvals; metadata
files and direct parents cannot be gateway-owned/shared-writable; descriptor
walks reject symlinks without an lstat/open race; nonblocking open refuses FIFOs;
single-link and before/after stat checks constrain admitted snapshots; RDP
imports reuse existing complete leaf checks. `serve-lab` cannot acquire remote
authority through new flags. `serve-ssh-lab` rejects root/reserved gateway IDs,
unsupported platform or any RDP target and constructs only ManagerWorker.
No worker readiness is implied by a successful HTTPS listener.

Root/host/filesystem and the gateway remain trusted; root can edit a catalog
and the program cannot prove independent identity acquisition or completeness
of deployment protected CIDRs. This is a maintainer self-review, not independent
audit. No service is installed, no production credential is used, and the
existing exact-candidate independent review gate remains.

## Configured server identity review — 2026-10-19

`SERVER-TRUST-LAB.md` records the two authorities: immutable operator network/
identity configuration and an owner's explicit, fresh fingerprint decision.
No browser endpoint can provision targets, discover keys, dial a probe, alter
network permissions or choose a worker. Metadata review performs no network or
credential-worker operation. Existing source-only deployment/audit gates remain.
Main's previous CI/CodeQL repeats passed before this slice. No dependency version
changes; Porch and Rootwell are untouched.

The version 2 approval now includes canonical host, port and sorted IP pins,
in addition to target ID, protocol and identity. Old development records remain
readable but require explicit owner review before launch. The exact current
receipt and full independently entered SSH/RDP fingerprint are required at
creation/replacement. Transactional envelope revision CAS prevents stale pages
from overwriting later decisions; replacement cancels that connection's active
and pending leases while preserving other connections. The grant, consumption
and remote workspace gates all check trust. RDP expiry makes approval unavailable.

Portable tests observe valid/invalid fingerprints against independent OpenSSH/
certificate digests, canonical ordering, immutable metadata, host/port/IP changes,
unknown/duplicate/coerced fields, ready/fresh MFA, CSRF/owner isolation, legacy
blocking, encrypted reopen, stale revisions, expiry and scoped cancellation.
Edge's owned workflow observes wrong fingerprints, empty confirmation fields,
changed key/address blocking, Cancel, old-value refusal, explicit replacement,
terminal input and logout. The review dialog was visually inspected from a
synthetic screenshot. Interactive demo seeding uses independently configured
fixture fingerprints; its separate guide displays those public fingerprints.
No real account/host/key is used and OS trust/browser profiles stay unchanged.
After restoration, local formatting/module/vet/shuffled-suite/build/staticcheck/
gosec/govulncheck/actionlint passed, together with Edge's owned/trust/interactive
demo checks. Linux tagged cross-vet, cross-analysis and test/build compilation
passed; actual Linux race/process/native/browser execution remains required CI.

Nine compiling Go mutations failed their intended assertions:

1. Ignore the fingerprint comparison: wrong fingerprint accepted.
2. Refuse all proofs: valid server proof refused.
3. Omit network snapshot binding: port/IP/host changes retained approval.
4. Ignore prior revision: stale trust revision accepted.
5. Ignore owner fingerprint at launch: missing decision retained authority.
6. Skip revocation on replacement: active connection survived.
7. Ignore fresh proof: an expired reauthentication replaced trust.
8. Revoke all rows using a credential: an unrelated connection was canceled.
9. Remove the trust-write budget: excess confirmation wrote another revision.

Two browser asset mutations also failed named assertions: exposing Connect for
a changed server, and prefilling the fingerprint. Each source/asset was restored
byte-for-byte and affected tests reran. Diagnostic outputs stay outside Git.
The additional browser workflow is a required CI step alongside all previous
actual Linux SSH/manager, native RDP, browser, race and nine fuzz gates.

### Separate adversarial maintainer self-review

Reviewed authority selection, old-record behavior, complete target binding,
snapshot canonicalization/copying, certificate time, stale UI/async selection,
exact request schemas, fingerprint encodings, fresh/MFA/CSRF/owner checks,
record-revision CAS, transaction/revocation ordering, response uncertainty,
malformed metadata, text-only DOM rendering and existing worker verification.

Findings shaped the implementation: port and IP pins now join the versioned
digest; legacy fingerprints cannot default to trust; replacement uses the
authenticated envelope revision and revokes pending as well as active leases;
the UI never prepopulates confirmation or exposes a changed connection link;
late detail responses are tied to the selected ID/generation, action buttons
remain disabled until the review is valid, and target lists/details stay bounded.
Remote workspace checks take the session lock before reading trust/clock state.
Full metadata is fetched per selected target: the additional 16 possible IPv6
pins per target stay out of the bulk catalog response. The browser's existing
response byte ceiling remains unchanged.
Valid trust writes also share a per-owner five/minute budget and the existing
global attempt window; malformed/stale proofs cannot consume seals or revoke
leases. Limited requests preserve revision and live sessions, and capacity
returns after the ordinary minute window.

An unchanged catalog still relies on the worker to reject a changed real remote
key before credentials; this UI does not discover that replacement. A submitted
matching hash cannot prove the human checked an independent channel. The
operator catalog is global to MFA-ready accounts; no team/target ACL is claimed.
Operator provisioning, installed services, cgroups, production RDP/clipboard,
restore/release operations and independent exact-candidate review remain gates.
This is maintainer self-review, not independent audit.

## Separate SSH manager for an unprivileged gateway — 2026-10-19

`SSH-MANAGER-LAB.md` records the new Unix seqpacket authority boundary. The
gateway retains existing MFA/owner/target/pin authorization; root launches only
its administrator-fixed worker using three passed descriptors. Neither keys
nor terminal bytes enter the manager parser. No dependency version, custody
CLI permission, real credential, installation, deployment or release changes.
Main's previous CI/CodeQL repeats passed before this source slice.

Local portable format/module/vet/shuffled-suite/build/staticcheck/gosec/
govulncheck/actionlint passed. Linux process/browser-tagged cross-vet,
cross-staticcheck, cross-gosec and test compilation passed. These compilation
checks do not claim Linux execution on the Windows workstation. The required
Linux gate runs real reduced-UID gateway subprocesses and the unchanged static
worker; it additionally kills the separately compiled manager binary after
actual SSH authentication. Existing owned-browser/native RDP/fuzz gates remain.

Ordinary Linux tests observe seqpacket bounds, rights truncation, unexpected
reply FDs, atomic CLOEXEC, kernel peer credentials and descriptor kinds. Root
integration tests observe valid Unicode/resize/authentication, changed-pin
refusal before authentication, wrong UID/primary GID/root refusal, pending and
active lease capacity, returned capacity, malformed and repeated starts,
five-second setup expiry, cancellation/reaping, graceful shutdown and abrupt
manager loss. Negative setup results must return a plain nil stream and must
not reach the target dial for untrusted manager paths.

The Linux script compiles four new admission/descriptor mutations: accept wrong
peers; reject the valid gateway; accept unsafe three-FD sets; reject valid sets.
Each must fail its named assertion, not merely a timeout/build/setup failure.
It compares restored sources byte-for-byte and reruns all manager/process tests.
The previous two actual-child pin mutations and two sandbox-removal mutations
also remain mandatory, with no retries or failure suppression.

### Separate adversarial maintainer self-review

Reviewed the completed implementation separately for socket ownership and
ancestor replacement, UID versus group membership, authority in passed FDs,
capability cleanup, concurrent exec inheritance, pending/active admission,
timeout/cancellation races, false readiness, child/manager crash, normal EOF
versus explicit revocation and root configuration versus browser input.

Review changes: received rights use kernel MSG_CMSG_CLOEXEC instead of a racy
post-receive fcntl; the fixed image is revalidated before each admission hello
and target dial; only connected TCP and distinct oriented pipes are admitted;
the child-creating OS thread stays locked through Wait because Linux parent-
death signals follow that thread; completion is acknowledged after reaping,
while unexpected control loss cancels buffered output. Shared Linux launcher
setup is reused without moving SSH/secret parsing into the root manager.
Reviewing the pinned Go sendmsg implementation also corrected the empty-packet
fixture: Linux inserts a dummy data byte when Go sends only ancillary rights.
The zero-length record test sends no rights; unexpected reply rights remain
separately refused. Runtime launch still requires the exact fixed start string.
Interrupted recvmsg calls retry immediately rather than waiting for a new poll
edge. The gateway's changed-pin test requires actual dial and timely refusal,
so capacity rejection or an expired context cannot masquerade as pin evidence.
Cancellation now signals only Go's owned process handle (pidfd on supported
Linux); raw negative-PID group signaling was removed to avoid signaling an
unrelated group after PID reuse. The fixed bwrap parent-death/PID boundary owns
the inner worker; actual cancellation and standalone-manager crash gates must
still pass with this narrower signal authority.

The dedicated gateway UID is trusted to enforce catalog/owner policy. Manager
FD validation is not a second application-authorization check. Root remains
trusted, and direct private pipes do not protect against malicious root.
The laboratory's worker UID 65534, non-aggregate RLIMITs/runtime hints, lack of
cgroups/service units/installer, operator trust UI and deployment policy remain
explicit gates. This is maintainer self-review, not independent candidate audit.
Porch and Rootwell remain untouched.

## SSH worker process boundary — 2026-10-16

`SSH-PROCESS-LAB.md` records the privileged Linux/amd64 manager, static child,
single guarded connected TCP descriptor and same-connection SSH identity check.
This adds no public/root service, install/deploy command, real credential or
release. Main's previous complete CI/CodeQL repeats passed before this slice.
Porch and Rootwell remain untouched; no dependency version is changed.

Portable frame/core/key tests passed after restoration, as did the full local
format/module/vet/shuffled-suite/build/staticcheck/gosec/govulncheck/actionlint
gate. Linux cross-vet (including process/browser tags), cross-staticcheck and
cross-gosec passed. Edge's existing interactive owned preview check passed with
the new key wrapper; native Linux evidence is a separately required CI gate.

Six compiling local behavior mutations failed their intended assertions:
allow unknown frame types; refuse valid frames; accept a changed SSH host pin;
retain queued output after cancellation; cancel queued output on normal EOF;
retain a closed session key. Each source was restored byte-for-byte and affected
tests reran. Startup also refuses bad version/host/seed/user/pin/trailing bytes
before user authentication. A new two-million-execution frame fuzz gate is
added alongside the existing targets, not substituted for them.

The Linux process CI gate runs actual static-child key authentication/PTY/input,
resize bounds, changed-pin-before-auth, none-auth refusal, approved image/hash
refusal before dial, cancellation and full owned MFA/custody/browser/logout.
It then compiles permissive/restrictive host-pin mutations into the actual
child and removes network/seccomp isolation from separate manager binaries.
Each must fail its intended assertion. Sources are restored and compared byte
for byte, the original child rebuilt and all process tests rerun. The full CI
job budget grows from 25 to 35 minutes for these additional gates; individual
process/browser/fuzz timeouts remain bounded and failures are not retried.

### Separate adversarial maintainer self-review

Reviewed the completed source separately for parent approval/pin snapshots,
root-controlled immutable worker-image admission, inherited FD scope, private
startup secret handling and formatting, child privilege/thread boundaries,
namespace/filesystem/syscall restrictions, readiness versus authentication,
host verification before signing, frame lengths before allocation, output
queues/quotas, EOF versus revocation, setup deadlines and process reaping.

Findings changed the implementation: privilege dropping now uses trusted
setpriv before Go starts, avoiding per-thread privilege changes in a live Go
runtime; pin bytes are copied before asynchronous setup; child startup copies
its pin before clearing the serialized key bytes; parent process exit does not
discard final remote output; explicit cancellation still rejects partially
read/queued data. Frame integer bounds are explicit rather than suppressing
the analyzer. Linux-specific code is cross-analyzed locally; Linux execution
must pass the actual sandbox gate, not just compilation.
The first Linux run passed actual isolated authentication and then exposed an
interface-wrapped nil stream on changed-pin refusal. The factory now returns a
plain nil interface on every setup error; cleanup is nil-safe and a portable
regression asserts both no typed-nil escape and no target dial on refusal.
Restoring the typed-nil return made that regression fail its intended assertion;
the source was restored and the worker tests reran. The frame fuzz target also
completed two million executions locally. The shared owned browser driver now
enrolls with the current TOTP and consumes an ordinary one-use recovery code
for initial reauthentication, avoiding its former previous-counter boundary
race. This changes only test orchestration; runtime MFA/replay rules are intact.

Limits remain explicit: root setup manager and shared UID 65534 are a laboratory
boundary, not the deployment design. An authenticated privileged manager for
an unprivileged gateway, dedicated installation identity, aggregate cgroups,
operator target/host-key approval UI, service packaging and independent exact-
candidate audit remain gates. Runtime memory hints and RLIMITs are not a hard
aggregate memory/CPU guarantee. This self-review is not independent audit.

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
