# Implemented Keybash security invariants

This file describes only code that exists. Planned login, vault,
RDP certificate, clipboard and deployment controls are in the product
plan and roadmap, not claims of this library lab. Tests use synthetic targets,
in-memory connections and an ephemeral loopback SSH echo fixture. They perform
no external server dials and load no real credentials.

| Invariant | Enforcement | Evidence |
|---|---|---|
| Unconfigured policy denies access | `targetguard.Policy.DialContext` | `TestEmptyAndNilPolicyDenyEveryDial` |
| Only approved address/port pairs are dialed | `Policy.permitted` at the dial boundary | `TestDialRejectsUnregisteredTargetWithoutNetwork` |
| Explicit private targets are usable | literal TCP dial, not a public-IP-only policy | `TestDialApprovedPrivateTargetUsesLiteralAddress` |
| Local, non-unicast, link-local and platform metadata endpoints cannot be approved | `canonicalEndpoint`, `Policy.isProtected`, `New` | `TestPolicyRejectsForbiddenApprovals` |
| Deployment-specific protected networks override approval | `New`, `Policy.isProtected` | `TestProtectedNetworksOverrideApprovalAndMappedAddress` |
| IPv4-mapped IPv6 does not bypass policy | unmap before approval/protection/dial | `TestMappedApprovedAddressDialsCanonicalIPv4`, `TestProtectedNetworksOverrideApprovalAndMappedAddress` |
| Caller mutation cannot change a policy snapshot | copied map and prefix list | `TestPolicyCopiesInputsAndSupportsConcurrentReads` |
| Already-canceled requests perform no network activity | pre-dial context check | `TestCanceledContextPerformsNoDial` |
| Dial errors do not reveal the target or underlying diagnostics | fixed public error | `TestDialErrorsDoNotExposeTargetOrDiagnostics` |
| A failed dial cannot leak an unexpected connection | close before returning a fixed error | `TestFailedDialClosesUnexpectedConnection` |
| A late successful dial cannot escape an observed cancellation | close before returning cancellation | `TestCanceledSuccessfulDialClosesConnection` |
| DNS is not a target approval authority, including other globally approved servers | per-target copied IP pins | `TestNamedTargetRebindingDoesNotApproveAnotherServer`, `TestNamedTargetCopiesPinsAndSupportsConcurrentReads` |
| The entire DNS result is checked before any target TCP activity | policy and pin checks for every answer, maximum 16 answers | `TestNamedTargetRejectsWholeAnswerBeforeAnyTCP` |
| One logical lookup, exact rooted hostname, literal-IP TCP dial | `NamedTarget.DialContext` | `TestNamedTargetResolvesOnceAndDialsPinnedLiteral` |
| Failure does not silently switch to another address | one selected literal endpoint | `TestNamedTargetUsesFirstPinnedAnswerWithoutFallback` |
| Bad hostname, missing pins, wrong port or missing policy cannot create a named target | `NewNamedTarget` | `TestNamedTargetConfigurationFailsClosed`, `FuzzCanonicalHostname` |
| Resolver errors and partial answers disclose no diagnostics and cause no TCP dial | fixed errors and shared deadline | `TestNamedTargetDNSFailureAndCancellationPerformNoTCP` |
| Changed server host keys stop before user authentication | copied approved host pin callback; signer gate | `TestSSHChangedHostKeyStopsBeforeAuthentication`, `TestSSHHostPinIsCopiedAndSignerCannotRunBeforeVerification` |
| Invalid or missing host/user identity cannot reach the network | bounded config validation before dial | `TestSSHInvalidConfigurationAndCanceledRequestsNeverDial`, `FuzzSSHHostKeyConfig` |
| A session requires configured key authentication, with no fallback | only verified key signer, refuse successful none-auth | `TestSSHRefusesNoneAuthAndAuthenticationOrPTYFailure` |
| Legacy key exchange cannot reach authentication | supported algorithm list, SHA-2 MACs | `TestSSHRefusesLegacyAlgorithmBeforeAuthentication` |
| Remote PTY input is forwarded exactly and resize is bounded | only session/pty/shell/window requests, no appended Enter | `TestSSHVerifiedKeyOpensRemotePTYWithExactUnicodeInputAndResize`, `TestSSHInputAndResizeBoundsDoNotSendRequests` |
| Server-initiated forwarding does not create channels | no exposed client or forwarding handler | `TestSSHRejectsUnsolicitedForwardingChannels` |
| Setup timeout/cancellation and failed setup close owned transports | deadline, close callback, ownership cleanup | `TestSSHHandshakeDeadlineAndCancellationCloseStalledTransport`, `TestSSHFailedDialAndDeadlineSetupCloseTransports` |
| Transport timeout remains a timeout if the context timer is scheduled later | elapsed-deadline classification | `TestSSHTransportDeadlinePrecedesContextTimer` |
| Active cancellation closes the stream and releases blocked I/O | per-session context watcher and idempotent close | `TestSSHSessionCancellationUnblocksReadersAndClosesRemote`, `TestSSHCancellationStopsBackpressuredRemoteOutput` |
| Public SSH errors do not reflect network or server diagnostic text | fixed errors and normalized EOF | `TestSSHUnconfiguredTerminalAndErrorsAreSafe`, `TestSSHRefusesNoneAuthAndAuthenticationOrPTYFailure` |

## Limits

The IP guard accepts parsed IP/port pairs. `NamedTarget` adds ASCII hostname
resolution with independently approved per-host pins and a five-second total
resolution/dial budget (a shorter caller deadline wins). Search suffixes are
disabled by looking up a rooted name. All answers must pass policy and pin
checks. The first returned address is selected; address fallback, IDNA
conversion, automated approval and DNS discovery are not implemented.

The public SSH library path accepts `NamedTarget` and uses its returned stream
without another hostname dial. Configuration/pins must be supplied by a trusted,
authorized owner; no application login or ownership system exists yet.
In particular, guacd has its own
network path; this Go guard does not constrain it. The configured DNS resolver
is trusted infrastructure and may itself require network access. This is not
a DNS sandbox or DNSSEC guarantee. SSH identity is a separate approved host pin.

SSH currently accepts Ed25519 host/user keys only, with a ten-second setup
budget and parent-context session lifetime. There is no host-key trust UI,
private key import, password/certificate auth, browser terminal, worker process,
or sandbox. The synthetic echo fixture proves SSH protocol requests and exact
byte transport, not Bash/OS PTY, vim/tmux, browser paste or clipboard behavior.
Channel windows impose backpressure; both output streams need consumption.
Aggregate connection quotas, worker isolation, application revocation, idle
limits, exit-status presentation and independent security review remain future
gates. Closing a stream does not guarantee killing all remote processes.

The operator must supply the installation's database/control networks; the
guard cannot infer them. Revocation will create new policy snapshots and stop
old sessions in the future session manager. Policy changes do not close an
already-open connection in this package. A successful TCP dial is neither
SSH/RDP authentication nor proof of the server's identity.

Standard NAT64, 6to4, Teredo, IPv4-compatible IPv6 and reserved 240/4 targets
are refused. Custom translation prefixes are not detected automatically and
must be denied in deployment policy; translator-aware support is deferred.

Platform address references: [AWS IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html),
[Alibaba ENS metadata](https://www.alibabacloud.com/help/en/ens/instance-metadata),
and [Azure platform IP](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16).
