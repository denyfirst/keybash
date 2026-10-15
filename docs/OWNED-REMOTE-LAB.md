# Account-owned remote session laboratory

15 October 2026. Identity, encrypted custody, connection records and the SSH/
RDP browser transports now share an authorization boundary. This is still a
synthetic loopback laboratory, not an installable remote gateway or audited
production release. Porch and Rootwell remain read-only references.

## Admission and data

`identity.NewRemoteLab` receives an operator-approved immutable catalog of
random target IDs, display names, protocol, guarded `NamedTarget` and copied
SSH wire key/RDP leaf certificate. A browser cannot approve an IP, hostname,
port, host key, certificate, worker address or arbitrary URL. Catalog metadata
is instance-wide and visible to ready MFA accounts. There is no per-team target
ACL or sharing in this slice. Installation-specific control/database networks
still belong in the operator's guard policy, never automatic discovery.

Owned connection records reference an owned credential and catalog ID. The
record also authenticates a SHA256 approval fingerprint of catalog ID, protocol,
logical hostname and approved server identity. Reusing an ID with another
host/key/certificate blocks old connections/grants; it cannot silently retarget
saved credentials. Immutable guarded policy/pin snapshots still control the
actual dial. Catalog changes require a new service instance and revoke all
sessions; no browser hot-reload or permissive fallback exists.

Connection records use existing per-save random-key envelope encryption with
`connection` AAD kind/owner/record/revision. The optional `connections-v1`
namespace is created in the first authorized write transaction. Opening an
older custody DB does not rewrite it or auto-migrate its required schema.
Missing/deleted connection records refuse launch. Limits are 128 connections
per owner and 2048 overall, within the existing 256 MiB DB cap. The optional
namespace's deletion is an availability loss, not a new authority. Old backup/
whole-record rollback limits from `CUSTODY-LAB.md` still apply.

Connections can be created/listed/deleted after MFA. Creation/deletion and
launch require fresh password-plus-factor proof. The API accepts only exact
named scalar fields; an `owner`, replacement target/identity or extra field
is refused. SSH needs the owner's nonempty username/Ed25519 key; RDP needs the
owner's nonempty username/password. No password fallback or credential export
is added by launch. The normal custody reveal remains separately authorized.

## Single-use capability and revocation

`POST /api/remote/open` returns a random 256-bit capability with a 30-second
admission lifetime. Only its digest is retained. It is bound to the exact
browser session, account owner, connection and credential; another browser
of the same account cannot consume it. Both grant and consumption check ready
MFA state, fresh proof, current account revision, owner records, protocol/kind
and approval fingerprint. There are at most two pending/active leases per
owner and eight overall. Failed/closed setup consumes the capability too.

WebSocket upgrade uses the exact fixed `/api/remote/socket` path, secure
HttpOnly cookie and exact Origin after the common TLS 1.3, loopback, Host and
canonical-URL checks. No token is accepted in URLs, query strings, storage or
subprotocol headers. Before ANY worker/parser/dial starts, one bounded text
frame must supply CSRF plus capability within five seconds. At most two
upgraded sockets/owner and eight overall can be in admission/active state;
these bounds include sockets that never send a valid proof. This is not a
general TCP accept/DDoS or exact process-memory guarantee.

Lease consumption is serialized before setup. Network, worker creation, key
parsing and response writes do not hold the account mutex. The shared two-slot
KDF/parser budget bounds encrypted key work; setup cancellation fires after
ten seconds. Trusted worker implementations must honor cancellation and return
a stream whose Close unblocks all reads/writes. A nonconforming in-process
callback cannot be forcibly killed by a context; production worker processes
need their own tested kill/resource boundary. Late results are closed and can
never become ready after observed revocation. A fixed ready response is sent
only after setup; it is not a generic RDP authentication claim (`guacd ready`
alone still does not prove NLA).

Contexts bind active streams to logout, idle/absolute expiry, account password/
MFA/recovery revision change and service close. Credential/connection deletion
also cancels matching pending/active leases. Current owned input rechecks live
session state and refreshes idle; output/ACK/status polls do not. Socket close
closes that stream, while account logout cancels all its browser streams. Data
already sent and remote background processes cannot be retracted/guaranteed
killed by closing the transport. The one-second identity sweep remains the
background cancellation bound; individual input/admission checks are immediate.

## Transport and trusted workers

The stock `sshtransport.Worker` calls the existing guarded/pinned connector;
there is no raw browser-selected dial, local SSH agent or shell subprocess.
Key validation still precedes library parsing, and signing still requires
actual host-key verification on that connection. The SSH library currently
runs in-process; a production OS sandbox/launcher remains a separate gate.

`RDPWorker` is an explicit trusted launcher interface, not a plugin or public
worker registration endpoint. It receives exactly one owned username/password,
the guarded target and copied approved certificate. Its own native TLS must
verify that certificate before CredSSP, and cancellation must revoke the broker
and worker. Native CI connects this interface to the existing isolated test
launcher, validated Guacamole/FreeRDP viewer and one-use broker. The synthetic
loopback substitution remains only in `_test.go` files, never a production flag.
There is no shipped RDP launcher, unguarded guacd socket or probe-then-trust path.

`terminalweb.Relay` reuses bounded framing, output credit/quotas and control
validation after authorization; no second lab bootstrap cookie is minted.
The socket reader now remains available for output ACKs while remote input
writes wait: ordered input/resize uses a 32-frame queue (at most 1 MiB), with
overflow refusal. A synchronous duplex pipe exposed the previous shared-reader
deadlock. This queue is bounded independently of the existing per-second
frame/byte limit; repeated invalid/overflow traffic closes the connection.

## Browser and remaining product work

The custody page adds owned connections, catalog/credential selectors, deletion
and navigation to SSH/RDP views. Existing local xterm/Guacamole profiles are
reused. The capability stays in memory and is sent only in the first socket
frame; background/BFCache handling cannot revive an abandoned async launch.
SSH paste preview and focused RDP input remain enforced. RDP clipboard/remote
resize are still disabled. Explicit SSH clipboard permission applies only to
the terminal document. No external service, CDN or runtime dependency is added.

`cmd/keybash serve-lab` deliberately remains custody-only: operator catalog
configuration, an installed isolated launcher, target trust/approval UI and
safe deployment have not been packaged. The full linked flow is exercised by
the integration harness through `NewRemoteLab`. Real server credentials are
not used and production service/release is not authorized by this source PR.

Required evidence includes `TestOwnedRemoteLeaseOwnershipReplayExpiryAndRevocation`,
`TestOwnedRemoteExpiryLimitsAndDelete`, `TestOwnedRemoteSocketEchoLogoutAndLateSetup`,
`TestOwnedRemoteFreshStateCredentialDeletionAndOtherAccount`,
`TestOwnedConnectionEnvelopePersistenceAndOwnerBinding`,
`TestOwnedRemoteChangedApprovalRefusesStoredConnection`,
`TestOwnedRemoteConstructorAndMalformedRequests`, the portable browser pipe
regression, actual SSH key-auth/PTY browser integration and actual isolated
native NLA/viewer/broker integration. See `VERIFICATION.md` for sabotage and
separate adversarial maintainer self-review. Independent candidate audit,
installed workers, packaging/update/restore/key rotation, real host/browser/
clipboard/load matrices and separately authorized signed release remain gates.
