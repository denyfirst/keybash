# Staying current

Keybash pins every version it builds or tests with: Go and its modules, the
native FreeRDP and guacamole-server sources, Node.js, pnpm, the browser test
packages and the analysis tools. A pin keeps builds exact, so it also has to
be moved on purpose. Two scheduled checks on `main` say when to move one
(`.github/workflows/freshness.yml`):

- **Nightly, 03:23 UTC:** govulncheck, at the pin CI uses, scans the module.
  Pull requests run the same scan; the nightly run catches advisories
  published after a change merged.
- **Weekly, Monday 04:41 UTC:** `cmd/keybash-freshness` compares every pin
  with its newest upstream release and prints a table.

Each job owns one issue, "Nightly vulnerability scan found something" and
"Pinned versions behind upstream". A run that finds something opens that
issue, or adds its report to it while it is open; a run that finds nothing
closes it. A failed lookup fails the job instead, so GitHub reports the
broken run. Either check can be started by hand from the Actions page, and
the version check runs locally from the repository root:

```sh
go run ./cmd/keybash-freshness
```

It exits 0 when every pin is current, 3 when one is behind and 1 when a pin
or a lookup failed.

## Where each newest version comes from

| Pin | Pinned in | Newest from |
|---|---|---|
| Go | `go.mod` | the highest stable release at go.dev |
| Direct Go modules and analysis tools | `go.mod`, the workflows | the Go module proxy's latest release |
| FreeRDP | `scripts/build-native-runtime.sh` | the highest non-draft, non-pre-release GitHub release |
| guacamole-server | the same script | the highest plain version tag on GitHub |
| Node.js | `ci.yml` | the highest LTS release in Node's index |
| pnpm, Playwright, xterm | `ci.yml`, `web/package.json` | the npm registry's `latest` |

## What the check trusts

It reads the repository's own files and asks only these fixed endpoints. Every
version, pinned or fetched, must be two to four dotted numbers. A
pre-release, a range, a build tag or anything carrying text is refused, and
the refusal fails the check rather than reaching the report. Upstream
answers are capped at 8 MiB and must be HTTP 200. Error text never enters the
table, so the issue body holds only file names, pin names and checked
versions. The GitHub token goes to the GitHub API only. Nothing fetched is run
or stored, and the jobs can read the code and write issues, nothing else.

A pin that disappears from its file, or appears twice with different
versions, fails the check too, so a changed file cannot silently stop
being watched (`TestPinsRefuseAFileWhoseFormatChanged`,
`TestPinsFromTheRepository`).

## Why not Dependabot

Every commit on `main` must be signed by a key in `.github/commit-signers`,
and CI verifies it. Dependabot's commits are not, so its pull requests could
never pass. CI also uses no third-party actions for Dependabot to update. The
weekly issue reports the same versions without that mismatch, and covers the
native sources and CI tools that Dependabot cannot see.

## Moving a pin

1. Read the release notes and advisories between the two versions.
2. Verify the new source the way the current one was verified: its published
   checksum or registry integrity, and a release signature where upstream
   signs.
3. Change the pin, its recorded hash and the docs that name it in one
   signed pull request. `DEPENDENCIES.md` and `NATIVE-RDP-LAB.md` hold the
   review.
4. Run the local gates; CI's native, browser and service labs decide.

A security release is adopted within days. Other releases follow when the
weekly issue shows them, after the same review.
