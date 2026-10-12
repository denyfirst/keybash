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
