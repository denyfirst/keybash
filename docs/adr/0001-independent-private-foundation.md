# 0001 — Independent signed foundation

Date: 2026-10-12. Status: accepted for initial development.

## Decision

Keybash lives in its own repository and sibling folder beside Porch and
Rootwell. It is exclusively self-hosted and began private, as requested by
the maintainer. Existing products and their Git configuration remain read-only.

The first signed root commit establishes only public signer trust and basic
repository rules. Feature work follows on a topic branch and PR. Reuse the
existing Denyfirst commit/tag signing identity and the distinct release
identity; do not copy private material or store signing secrets in CI.

GitHub confirmed the organization's Free plan did not provide branch protection
for this private repository (API returned HTTP 403). The maintainer then
explicitly authorized public visibility to enable protected development.
Review and publish only this new repository, then require CI and signed commits
on main. This authorization does not extend to a production release or to
any changes in Porch or Rootwell. Maintainer procedure alone is not a substitute
for enforced protection.

## First implementation boundary

Begin with a standard-library-only outbound IP target guard, before protocols
or credentials. No server daemon, login, vault, terminal or RDP is exposed by
this commit. The guard permits exact approved address/port pairs and explicit
private unicast targets, while refusing platform endpoints and protected
control networks. This changes the execution order of the initial product
plan, not its self-hosted scope or security-first priority.

The Go toolchain and analysis tools follow the versions already used in
Rootwell's current workflow. Frontend, SSH library and Guacamole adoption
remain prototype decisions subject to separate dependency reviews.

## Consequences

Synthetic tests and deliberate mutations provide evidence for this boundary,
not a claim of an audited remote-access product. DNS must be resolved and
validated at the dial boundary before hostnames are supported. Deployment
must supply control/database networks and isolate worker egress. Metadata
protections alone cannot infer a custom address translator or network layout.

Release licensing, external audit, offline packaging and public launch remain
separate decisions. Development under Keybash does not establish trademark
clearance.
