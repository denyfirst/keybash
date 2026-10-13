# ADR 0002: Bind names to independently approved destination pins

Date: 2026-10-13. Status: accepted for the protocol lab library boundary.

## Problem

A hostname must not authorize whatever address it currently resolves to.
Even validating against the installation-wide target list would let a rebinding
name connect to another registered server. Passing the validated name to a
second dialer would allow DNS to change between checking and dialing.

## Decision

Keep the existing immutable IP/port policy. Add an immutable `NamedTarget`
holding a canonical logical hostname, port, and a copied set of at most sixteen
independently approved IP pins. Construction checks every pin against the
installation policy, including metadata and deployment control exclusions.

Resolve once per attempt using `net.Resolver.LookupNetIP`, `PreferGo` and
`StrictErrors`, with a rooted name and a five-second resolution/dial budget.
Check every returned address against both the policy and this target's pins.
Reject the whole answer if any address is unapproved, malformed, protected or
the answer exceeds sixteen addresses. Canonicalize IPv4-mapped IPv6 before
pin matching. Hand the first accepted literal endpoint to the existing guard;
never hand the name to a second TCP resolver. Do not retry another address.

Retain `Hostname()` for protocol identity verification. A pinned address does
not replace SSH host-key or RDP certificate verification. Late TCP success
after observed cancellation is closed before returning a connection.

Only Go's already pinned standard library is adopted here; no new runtime
dependency, credential input, network listener or persistent trust store.
ASCII DNS labels and explicit IDNA A-labels are supported. Unicode conversion,
address selection/fallback and automatic pin updates remain separate decisions.

## Consequences and limits

Legitimate address changes require an explicit approved configuration update.
A multi-address name with one unapproved address is refused even if another
address would be usable. The eventual UI must make this decision understandable
without teaching users to disable verification. Pins are trusted configuration,
not an authorization system; callers cannot obtain policy or pin selection from
an unchecked user request. The future session manager owns policy revocation.

The resolver is installation infrastructure, not an isolated network worker.
One API lookup can involve A/AAAA queries, caching, hosts files, or CNAMEs;
the claim is one logical lookup and no hostname re-resolution by the TCP dial.
Timeout handling relies on the standard resolver honoring context. Established
connections outlive the setup context and need later session lifecycle rules.

guacd does not use this Go connection. Before adopting it, a separate enforced
literal-target/egress path and RDP identity behavior must be demonstrated.

## Evidence and references

Success/refusal/abuse tests and hostname fuzzing are listed in
`../SECURITY-INVARIANTS.md`; mutation and self-review evidence is in
`../VERIFICATION.md`. Tests inject synthetic resolver/dial functions and
`net.Pipe`; they do not query external DNS or dial external servers.

Implementation uses the documented [Go resolver API](https://pkg.go.dev/net#Resolver.LookupNetIP)
and [DialContext](https://pkg.go.dev/net#Dialer.DialContext). The source of the
pinned Go 1.26.9 toolchain is inspected locally for rooted name handling;
no assumption of a single DNS wire packet or DNSSEC verification is made.
