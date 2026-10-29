# Operator-configured server identity review

19 October 2026. The owned loopback lab now requires an explicit owner decision
before creating or reapproving an SSH/RDP connection. This adds a user interface
for reviewing the existing trusted operator catalog. Installing that catalog,
network policy and workers as a production service remains a separate gate.
No real credentials, deployment, release or new dependency is introduced.

## Two different authorities

The local operator still supplies immutable `RemoteTarget` entries: stable ID,
label, protocol, guarded hostname/port/approved IP pins and an independently
approved SSH public key or RDP leaf certificate. The browser cannot add a host,
IP, port, key, worker URL or network permission. There is no discovery scan,
unauthenticated key probe or trust-on-first-use fallback. Reviewing metadata
performs no DNS, TCP, SSH, RDP or credential-worker operation.

A ready MFA account can select a configured server and inspect its hostname,
port, approved IP set, identity type and fingerprint. These are configuration
values, not observations of a live remote peer. The user compares the complete
target and fingerprint against a server console or another independently trusted
channel, then enters the full fingerprint. The field is never prefilled. Creating
the connection or replacing its approval needs a ready MFA session, ownership,
CSRF and the TLS boundary. Only the catalog's current identity can be approved,
so no fresh step-up is asked; deleting the connection asks for one.

SSH uses the standard OpenSSH `SHA256:` fingerprint of the wire public key,
with unpadded base64. RDP uses `SHA256:` followed by 64 lowercase hex digits
of SHA-256 over the complete approved leaf DER. This is not the Windows SHA-1
thumbprint; the local operator must provide the matching SHA-256 value.
Different case, whitespace, truncated hashes and noncanonical encodings refuse.

The application can require an exact explicit submitted comparison; it cannot
prove that the human actually used an independent channel. Copying the displayed
value alone establishes no independent trust. The UI and this document say so.
Host administrators, the gateway and the browser remain trusted under the
existing custody model. This change is not a PAM approval or team-sharing system.

## What the decision binds

The version 2 approval digest binds the stable target ID, protocol, canonical
hostname, port, entire sorted canonical IP pin set and identity bytes. Cosmetic
label changes and IP-order changes do not change authority. Adding/removing an
IP or changing a port, host, identity or protocol invalidates the decision.
The prior development digest did not include port/IP pins; old records require
an explicit new decision. Global installation policy is still independently
enforced by `NamedTarget` on every real connection.

Creation submits both the separately entered fingerprint and the exact catalog
approval receipt currently shown. A stale page cannot approve a changed network
snapshot merely because its host key stayed the same. The encrypted connection
stores the decision under its existing instance/kind/owner/ID/revision envelope.
Reapproval checks the exact previous encrypted revision transactionally, increments
it and consumes the normal global seal budget. Unknown/duplicate/coerced fields
and caller-selected owners or endpoints refuse.
Valid creation/reapproval shares a five-per-owner-per-minute trust budget,
separate from login and other accounts' budgets. Stale or
malformed reviews cannot spend encryption seals or revoke sessions. This is a
bounded write policy, not an authenticated-user or whole-service DDoS guarantee.

On replacement, all active and pending leases for that owner's connection are
revoked before another request can redeem them. Other connections remain live.
Both grant and consumption require the full current decision. The remote page
also refuses a mismatched decision before serving its workspace. An RDP
certificate outside its validity period makes only that target unavailable for
new approval and launch; the gateway still starts and other targets work.

The interface shows verified, changed, unverified or unavailable. Changed and
unverified rows have no Connect link. The review dialog shows the previous
fingerprint and the full current target; Cancel leaves authority unchanged.
Lost/uncertain responses do not display successful confirmation. The input clears
on submit, target change and backgrounding; cached review generations prevent a
late response for one selection from approving another selection.

An actual remote key change while the operator catalog stays unchanged is
refused by the SSH/RDP worker on the real authenticated connection, before user
credentials. This UI does not discover or automatically replace that remote key.
The operator must independently verify and change configuration. Configuration
is immutable for the running process; restart logs out all sessions and kills
leases. No runtime catalog-write HTTP endpoint is shipped.

## Persistence, evidence and remaining work

Opening an old database performs no migration or automatic trust. Missing owner
fingerprints remain readable as unverified metadata and cannot launch. The owner
can explicitly replace the decision using fresh proof. Corrupt envelopes refuse;
another account cannot read or rebind the encrypted decision. Database/whole-host
rollback protection and guaranteed memory erasure are not claimed.

`TestServerTrust*` and the target snapshot test cover standard fingerprint
formats, network binding, canonical ordering/copying, success/refusal/malformed
proofs, ready/fresh MFA, CSRF/ownership, stale revisions, grant/consume/page
blocking, legacy decisions, encrypted reopen, expiry and scoped revocation.
The required browser workflow uses independently computed fixture fingerprints,
measures wrong-fingerprint rejection, changed-key/address blocking, cancellation,
old-value refusal, explicit replacement, ordinary terminal input and logout.
The same updated owner-review flow also runs in actual Linux SSH-process and
native RDP browser gates. All targets/keys/passwords are synthetic.

Local compiling security mutations remove fingerprint, network, revision,
freshness and scoped revocation checks, and also refuse every valid proof.
Browser mutations expose a changed connection's Connect link or prefill the
fingerprint; their intended assertions must fail. Source bytes are restored and
the affected tests rerun. See `VERIFICATION.md` for exact evidence. Maintainer
self-review and CI are not independent audit of a release candidate.

Remaining gates include operator policy/catalog provisioning, installed
unprivileged gateway/manager identities, cgroups and production RDP launcher,
browser/OS/real-host clipboard and workspace matrix, backup/restore, release
packaging and independent exact-candidate security review. Porch and Rootwell
remain read-only references and are untouched.
