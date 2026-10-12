# Keybash engineering workflow

Keybash follows the Denyfirst signed development workflow read from Porch's
`CONTRIBUTING.md` and `docs/releasing.md`, and Rootwell's `docs/ENGINEERING.md`.
These are read-only references, not shared worktrees or runtime dependencies.

## Development

1. Start from current `main`, create a purpose-specific branch, and verify it.
2. Understand the trust boundary before implementing a behavior.
3. Cover success, refusal, malformed input, and relevant abuse behavior.
4. Sabotage security behavior in both directions; confirm the intended tests
   fail, restore the source, and rerun the affected gates.
5. Inspect status and the index. Stage paths by name; never `git add -A`.
6. Run the appropriate local gates, create a signed commit explaining why,
   and verify its signature against `.github/commit-signers`.
7. Open a PR and wait for every required check. A separate adversarial
   maintainer self-review records evidence and limitations. It is not an
   independent audit. Resolve findings and actual required approvals.
8. Merge with a merge commit only; never squash, rebase, auto-merge, `--admin`,
   or a ruleset bypass. Do not change old signed commits to fix failures.

The repository started private. The maintainer then authorized making this
repository public so GitHub Free can enforce branch protection. This permits
publishing this reviewed source repository, not publishing a production
artifact, signing a release, or deploying a service.

## Signing and initial trust

Commits and tags use the existing Denyfirst SSH signing identity; release
manifests use the existing, separate release identity. Only public keys are
stored in `.github/commit-signers` and `.allowed_signers`. No private key or
signing secret enters CI. GitHub authentication is a third, separate purpose.

A new repository needs a trust root before a PR can trust its base. The sole
bootstrap commit on `main` contains the public trust lists, ignore/line-ending
rules, and a minimal README. It is signed and locally verified. All subsequent
work uses topic branches and PRs. This is not an exception for feature work.

PR signature verification reads the signer list from the base commit and does
not execute PR code. A PR cannot add a key and trust that same key to authorize
itself. Key rotation requires authorization by an already trusted key.

## Gates

The initial implementation pins the Go toolchain in `go.mod`. Formatting,
module cleanliness, vet, shuffled tests, build, Linux race tests, staticcheck,
gosec, govulncheck, actionlint, and invariant citations are CI gates. Linux,
macOS, and Windows compilation is checked; this does not promise a Windows or
macOS deployment package. The first deployment target remains Linux.

Local PowerShell entry point: `./scripts/check.ps1`. CI tool versions are
listed in `.github/workflows/ci.yml`; local analysis uses those versions.
Diagnostic and mutation outputs belong outside the tracked repository.

No third-party GitHub actions run in the initial workflow. Private checkout
uses the job's short-lived, read-only GitHub token without persisting it in
Git config. Untrusted PR code receives no signing or production secrets.

## Dependencies

The first target guard uses the Go standard library only. xterm.js, the SSH
library, Guacamole/FreeRDP, database drivers, and password hashing libraries
are planned dependencies, not installed or approved by this foundation.
Each adoption needs a review of maintenance, license, transitive dependencies,
vulnerabilities, parser limits, and update policy. Runtime assets will be
bundled and locally served; external CDN and telemetry are not required.

## Releases

No release tag, binary release, image, or production service is created by
the foundation PR. Release tooling must later verify a signed tag, run gates,
produce a checksum/build manifest on a separate CI builder, reproduce bytes,
and obtain a local signature from the maintainer's release key. Signing never
skips a failed comparison. Tag deletion/movement and unsigned release paths
must be blocked before release automation is enabled.

Before first public release of credential custody or remote access, obtain
independent security review of an exact candidate commit and resolve material
findings. CI and maintainer self-review do not establish independent audit.
The product's actual feature and security claims must match the tested build.

## Repository protection

Require PR checks on `main`, signed commits, and merge commits only. Making the
repository public was explicitly authorized after GitHub rejected protection
on the private Free-plan repository. Verify the actual protection response;
do not report required checks as enforced until the server confirms them.
