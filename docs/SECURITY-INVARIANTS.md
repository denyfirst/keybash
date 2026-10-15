# Implemented Keybash security invariants

This file describes only code that exists. Durable login/MFA and encrypted
custody exist in a Linux loopback laboratory; production RDP access, browser
RDP clipboard and deployment controls remain product gates. Tests use synthetic targets,
in-memory connections and ephemeral loopback SSH/browser fixtures. They perform
no external server dials and load no real credentials.

| Invariant | Enforcement | Evidence |
|---|---|---|
| Initial registration requires a single-use expiring local setup code; it cannot reopen | atomic bootstrap state and keyed metadata | `TestCustodyBootstrapSingleUseExpiryAndExclusiveOpen`, `TestCustodyOfflineRecoveryBootstrapRenewalAndSealLimit` |
| Password-only persistent sessions cannot access custody | explicit enroll/challenge/ready state and rotated cookies | `TestPersistentPasswordSessionsCannotOpenVault`, `TestCustodyHTTPBootstrapMFAAndVault` |
| Factor replay and recovery reuse are refused across restart/concurrency | transactional greatest counter, hashed one-time codes, durable failed-attempt budget | `TestCustodyMFAReplayRecoveryAndRestart`, `TestCustodyFactorFailuresPersistAndReplacementKeepsOldMFA` |
| Old MFA survives an abandoned replacement; old sessions die on account revision changes | pending session seed and atomic replacement | `TestCustodyHTTPBootstrapMFAAndVault`, `TestCustodyRandomEnvelopesQuotaAndHTTPIsolation` |
| Secrets are encrypted at rest and authenticated to immutable owner/record IDs | separate random instance key, HKDF purposes, per-save random DEK and random-nonce GCM, metadata MAC/seal budget | `TestCustodyCiphertextOwnerBindingTamperAndPlaintextAbsence`, `TestCustodyRandomEnvelopesQuotaAndHTTPIsolation`, `TestCustodyOfflineRecoveryBootstrapRenewalAndSealLimit` |
| Sensitive custody mutations/reveal require fresh password plus factor; owner is never browser supplied | server ready/fresh/session owner checks, strict JSON | `TestCustodyHTTPBootstrapMFAAndVault`, `TestCustodyRandomEnvelopesQuotaAndHTTPIsolation`, `TestCustodyCancelledReauthentication` |
| Slow bodies do not hold session revocation; malformed/ambiguous fields refuse | bounded read before account mutex, exact scalar fields | `TestCustodyStrictFieldsAndSlowBodyIsolation`, `FuzzCustodyFields` |
| SSH import bounds cost before parsing and rejects key confusion | bounded OpenSSH Ed25519/bcrypt preflight, seed/public consistency | `TestCustodySSHImportBoundsAndPasswordBlocklist`, `TestCustodySSHRejectsCostBombAndMismatchedPublic` |
| Linux provisioning refuses shared files, symlinks, concurrent writers and a key inside DB storage | owned 0700 roots, 0600 regular files, exclusive rooted opens | `TestCustodyLinuxPrivateProvisioning`, `TestOperatorLinuxInitBootstrapAndOfflineRecovery` |
| Custody UI uses local assets, no secret URLs/storage, and clears explicit reveal | strict response handling, text DOM, explicit user copy and expiry/hide | `TestBrowserDurableCustody` |
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
| Browser lab requires TLS 1.3, loopback peer/Host and exact Origin | `terminalweb.Lab` before grant/upgrade | `TestLabHTTPSHostOriginAndOneUseGrant`, `TestLabSocketRequiresExactOriginOwnerAndSingleSession` |
| One-use lab grant yields restricted cookie and one active owner stream | hashed random tokens, Secure/HttpOnly/Strict cookie, active slot | `TestLabHTTPSHostOriginAndOneUseGrant`, `TestLabSocketRequiresExactOriginOwnerAndSingleSession` |
| Logout, expiry and excess input revoke the stream | shared cancellation and stream close | `TestLabInputResizeOutputCreditAndLogoutRevocation`, `TestLabExpiryAndRateCloseOwnedStream` |
| Output cannot advance without matching, nonduplicate render credit | sequence, one pending output frame, bounded queue | `TestLabOutputWaitsForMatchingCredit`, `TestLabInvalidConfigurationAndControlBounds` |
| Lab output has a total 8 MiB ceiling, beyond bounded queues/scrollback | total byte counter before transmission, client ceiling | `TestLabOutputQuotaClosesBeforeExtraData` |
| Malformed/oversized/unknown or duplicate control fields do not reach SSH operations | bounded strict control decoding and WebSocket limit | `TestLabMalformedOversizedAndUnexpectedAckCloseStream`, `TestLabInvalidConfigurationAndControlBounds`, `FuzzTerminalControl` |
| Browser transport preserves input and bounded resize | binary input and typed resize control | `TestLabInputResizeOutputCreditAndLogoutRevocation` |
| Real Linux PTY handles Unicode, Ctrl+C and applied kernel resize | fresh-key SSH fixture, test-only Bash PTY | `TestSSHLinuxBashPTYUnicodeInterruptAndKernelResize` |
| RDP probe requires HYBRID and fixed-size valid confirmation | bounded X.224/TPKT experiment, no downgrade | `TestRDPNegotiationRejectsDowngradeMalformedAndOversized`, `FuzzRDPConfirmation` |
| Credential-free probe requires the approved current leaf, name and TLS >=1.2 | standard TLS verification, exact DER pin, usage/key checks | `TestRDPHybridTLSProbeVerifiesPinWithoutCredentialsAndCloses`, `TestRDPChangedExpiredAndWrongPurposeCertificatesRefused`, `TestRDPProbeRSAAndECDSAHandshakeAndWeakRSARefusal`, `TestRDPPinCertificateKeyAndCriticalExtensionConstraints`, `TestRDPIdentityImportNameBoundsAndCopiedCertificate`, `TestRDPPinRequiredEvenForOtherwiseTrustedCertificate`, `TestRDPProbeRefusesNameMismatchAndMissingApprovedRoot` |
| Probe returns no live stream and timeout/cancellation close I/O | owned transport close, five-second budget | `TestRDPInvalidConfigurationCanceledAndFailedDialClose`, `TestRDPProbeCancellationUnblocksNegotiationAndTLS`, `TestRDPProbeDeadlineClosesStalledConnection` |
| Private text prototype preserves fragmented Unicode and isolates sessions/directions | owned per-direction accumulator; completed end only | `TestRDPClipboardUnicodeFragmentedBothDirectionsAndSessionIsolation` |
| Prototype refuses nontext types, malformed base64/UTF-8, wrong IDs, replay and excess text | clipboard/blob/end only, strict encoding, 32 KiB total | `TestRDPClipboardRejectsTypesReplayMalformedAndQuota`, `TestRDPClipboardExactQuotaAndRevocation` |
| Guacamole prototype bounds lengths and rejects invalid UTF-8 | 48 KiB per instruction, 16 elements, codepoint lengths | `TestRDPWireCodepointsBoundsAndMalformed`, `FuzzRDPWireAndClipboard` |
| Empty test netns denies host/network TCP and DNS UDP without capabilities | CI fixed child; removed namespace must fail | `TestRDPEmptyWorkerNamespaceDeniesEgress`, `TestRDPWorkerNamespaceChild` |
| Native parameters require NLA and closed auxiliary channels; credentials are redacted | private exact-schema plan and refusal-only authentication callback | `TestNativePlanEnforcesNLAChannelsAndRedactsCredentials`, `TestNativeArgumentsRejectUnknownDuplicateMissingAndVersion` |
| Unknown native argument schemas refuse before credentials; context closure owns IPC | bounded setup and transport cleanup | `TestNativeHandshakeStrictSchemaReadyAndContextCleanup` |
| Unsolicited native files/pipes/clipboard/prompts and excess output are refused | fixed opcode boundary, 8 MiB/8192 instruction ceiling | `TestNativeStreamRefusesUnsolicitedStreamsAndBoundsOutput` |
| A broker binds the logical identity to its guarded target and cannot be reused | private name-bound single-use raw transport capability | `TestNativeBrokerBindsIdentityToGuardedTarget`, `TestNativeBrokerRawUnicodeSingleUseAndCancellation` |
| Broker quotas, failed/late/canceled dials close both streams | 16 MiB per direction, cancellation/EOF cleanup | `TestNativeBrokerQuotaClosesBothDirections`, `TestNativeBrokerFailedAndCanceledDialsCloseOwnedConnections` |
| Native TLS refuses changed/invalid certificates and downgrade before any CredSSP data | mandatory OpenSSL exact-leaf/name/usage/time/critical/key hook; no TOFU/ignore | `TestNativeRDPCertificateRefusalBeforeCredentials` |
| Synthetic correct NLA password yields decoded desktop images; wrong password refuses; cancellation stops worker/broker | actual pinned native peer, bounded PNG decode, test-only process supervision | `TestNativeRDPAuthenticationRenderingAndRevocation` |
| Native worker has private network/filesystem/PID boundaries and no groups/capabilities; cannot replace trust or independently dial | test-only Bubblewrap/setpriv/read-only mounts and resource limits | `TestNativeRDPSandboxPreparation`, `TestNativeRDPChild` |
| Reaching private IPC does not authorize a process with the wrong host UID | Unix peer credential check before accepting the capability | `TestNativeRDPControlIPCRejectsWrongUID` |
| Desktop profile keeps the existing TLS/owner/Origin boundary and exposes a fixed local asset set | immutable desktop profile, self-only scripts/Blob-only images | `TestDesktopProfileKeepsOwnerOriginAndClosedAssetBoundary` |
| Browser drawing is typed/bounded and decoded PNGs normalize before ordered forwarding | private viewer state, static PNG re-encoding/staging, layer/geometry/stack limits | `TestViewerValidatedPNGGroupingInputAndRevocation`, `TestViewerNormalizesPNGWithoutMetadataAnimationOrTrailingData`, `TestViewerRefusesMalformedAndExcessDrawing`, `TestViewerInvalidPNGIsNeverForwarded`, `FuzzViewerDrawingSchemas` |
| Compressed images and drawing cannot spend unbounded pixel work | lifetime decode/render work counters before expensive operations | `TestViewerTotalDecodeAndRenderWorkAreBounded` |
| Browser input cannot select targets/credentials/streams or replay credits | one bounded instruction, opcode/state/keysym/coordinate limits | `TestViewerInputRefusesArbitraryParametersReplayAndBounds` |
| Revocation closes partial image reads and refuses late input/output | atomic closed state and native transport teardown | `TestViewerPartialImageAndCancellationCloseReaders`, `TestViewerValidatedPNGGroupingInputAndRevocation` |
| Browser pixels and input are independently measured; logout removes the display and native stream | isolated Edge/Chromium fixture and actual native NLA peer markers | `TestBrowserRDPViewerLab`, `TestNativeRDPBrowserDesktopAndRevocation` |
| Passwords use independently salted fixed-cost Argon2id and exact Unicode bytes | opaque versioned hash, constant-time comparison, byte/codepoint limits | `TestPasswordSaltUnicodeAndWrongPassword` |
| Login creates a fresh owner session; logout/password change cannot revoke another account | hashed random token, owner-bound session and revision recheck | `TestIdentityLoginGateRotationLogoutAndAccountIsolation`, `TestIdentityPasswordChangeRevokesOnlyItsOwner`, `TestIdentityRefusesWrongUnknownAndCrossAccountPassword` |
| Identity mutation requires exact TLS/peer/Host/Origin and session-bound CSRF; duplicate/forged cookies refuse | common HTTP boundary before hashing and standard HMAC proof | `TestIdentityTLSOriginCSRFAndCookieBoundary`, `TestIdentityLoginRejectsUntrustedTransportBeforeHash` |
| JSON credentials reject duplicate/unknown/coerced fields, invalid UTF-8/surrogates and excess input | bounded scalar preflight and exact two-string decoder | `TestIdentityStrictJSONAndBodyBounds`, `FuzzIdentityJSON` |
| Known/unknown accounts share bounded attempt policy; KDF and sessions have finite capacity | global/name windows, two slots, owner/aggregate session caps | `TestIdentityAttemptBucketsAreUniformAndBounded`, `TestIdentityRateKDFAndSessionQuotas`, `TestIdentityActivityRenewalAndOwnerSessionQuota` |
| Status polling cannot extend idle/absolute sessions; expiry cancels without another request | idle/absolute checks plus one-second background sweep | `TestIdentityIdleAbsoluteExpiryAndStatusDoesNotExtend`, `TestIdentityBackgroundExpiryCancelsWithoutRequest` |
| Stale password derivation, logout and service closure cannot commit late authentication changes | revision/context/live-session recheck under lock | `TestIdentityRevocationDuringDerivationAndClose`, `TestIdentityPasswordChangeCannotFinishAfterLogout` |
| Missing/duplicate identities or non-loopback origins cannot initialize login | copied account configuration and numeric origin checks | `TestIdentityConfigurationRefusesMissingDuplicateOrUntrusted` |
| Browser login/change/logout preserve password clearing, protected navigation and truthful failure state | local fixed assets, bounded response/deadline, no storage or secret URLs | `TestBrowserPasswordLogin` |

Browser evidence is additionally enforced by `web/paste.test.mjs` and the
`browserlab` tagged `TestBrowserTerminalLab`: paste review/cancel/approve, byte
limits, invisible/bidi preview, copy/fallback, HTML/OSC clipboard isolation,
no persistent browser storage, same-origin page requests and renderer removal
after logout. Linux adds native headless clipboard, bracketed Bash paste and
kernel resize. Windows uses a mocked clipboard to protect the workstation.

## Limits

The separate identity lab implements password-only, memory-resident accounts
and owner sessions. It has no persistent IDs/hash storage, operator bootstrap,
blocklist, MFA/recovery, vault or remote-resource authorization. Its cookie is
not accepted by the protocol labs and opens no worker. See `IDENTITY-LAB.md`.
Fixed attempt windows can be exhausted deliberately; KDF concurrency is not a
process-memory or DDoS guarantee. Production durability/ownership and independent
candidate review remain gates before real credentials or remote access.

The initial RDP probe is a pre-credential experiment and private text prototype. The
probe checks its own TLS, closes it, and never sends CredSSP; it cannot authorize
guacd's connection. Its imported leaf is the only trust anchor; standard TLS/name
verification remains enabled with an extra exact DER pin. A separate pinned
native Linux lab enforces its own TLS identity before CredSSP, authenticates a
synthetic account and decodes desktop images through a one-use broker and
test-only worker sandbox. Both actual C callback mutations must fail before
restoration and a full rerun. Refusal timeouts are failures, not proof. Native
clipboard/touch/dynamic display are disabled. A loopback browser RDP lab now
uses the bounded viewer adapter, local Apache JS and existing owner transport.
It is fixed-viewport and has finite memory/work/output quotas. It is not a
general Guacamole tunnel or product entry point. There is no application
ownership/vault, production launcher, aggregate cgroup quotas or
minimal runtime filesystem/syscall filter. The empty earlier namespace also
denies approved destinations. Codec tests are not desktop/browser clipboard
evidence. See ADR 0003 and `NATIVE-RDP-LAB.md`.

The IP guard accepts parsed IP/port pairs. `NamedTarget` adds ASCII hostname
resolution with independently approved per-host pins and a five-second total
resolution/dial budget (a shorter caller deadline wins). Search suffixes are
disabled by looking up a rooted name. All answers must pass policy and pin
checks. The first returned address is selected; address fallback, IDNA
conversion, automated approval and DNS discovery are not implemented.

The public SSH library path accepts `NamedTarget` and uses its returned stream
without another hostname dial. Configuration/pins must be supplied by a trusted,
authorized owner; no application login or ownership system exists yet.
The native lab constrains guacd with a private netns and a single broker stream;
the guard alone cannot constrain an independently launched guacd. The configured DNS resolver
is trusted infrastructure and may itself require network access. This is not
a DNS sandbox or DNSSEC guarantee. SSH identity is a separate approved host pin.

SSH currently accepts Ed25519 host/user keys only, with a ten-second setup
budget and parent-context session lifetime. There is no host-key trust UI,
private key import, password/certificate auth, production workspace, worker
process or sandbox. Browser and real Bash evidence is confined to the laboratory;
vim/tmux and full browser/OS behavior remain unmeasured.
Channel windows impose backpressure; both output streams need consumption.
Aggregate connection quotas, worker isolation, application revocation, idle
limits, exit-status presentation and independent security review remain future
gates. Closing a stream does not guarantee killing all remote processes.

The terminal lab is not product login/MFA or ownership authorization. Its bootstrap code
is passed via test process stdin, never URLs/environment/logs; it accepts no
browser-selected target or credential. No test shell implementation is compiled
into runtime packages. Automated browser contexts accept only the fixture's
self-signed certificate for testing; production TLS trust is still a deployment
gate. The xterm stylesheet needs inline style support, while scripts remain
self-only without eval/inline script permissions. This tradeoff is reviewed in
the dependency document; terminal text is never inserted as application HTML.

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
