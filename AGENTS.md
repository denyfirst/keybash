# Working on Keybash

Read `docs/ENGINEERING.md`, `docs/PRODUCT-PLAN-AZ.md`, and
`docs/SECURITY-INVARIANTS.md` before changing code.

Keybash is exclusively self-hosted. Security comes before convenience.
Document trust boundaries and limits. Security changes need observable success,
refusal, malformed-input, and relevant abuse tests. Sabotage both directions
and demonstrate that the intended tests fail, then restore and rerun gates.

Use a purpose-specific branch, inspect the index, stage explicit paths, and
sign every commit with the configured Denyfirst commit identity. Follow the
PR, self-review, and release gates in `docs/ENGINEERING.md`. Never use
`git add -A`, squash, rebase, auto-merge, or an administrative bypass.

Porch and Rootwell are read-only references. Do not edit their files, worktrees,
Git configuration, index, branches, tags, remotes, or releases. Do not run
their build, formatting, dependency, or release scripts. Make Keybash changes
only within this repository. Private signing keys and production credentials
must never be copied into this repository, logs, tests, or CI.
