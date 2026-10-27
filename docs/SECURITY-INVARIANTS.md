# Implemented Keybash security invariants

This file describes only code that exists. Durable login/MFA, encrypted custody
and separate SSH/RDP source service integrations exist for Linux loopback tests;
production ingress, packaging and release remain product gates. Tests use synthetic targets,
in-memory connections and ephemeral loopback SSH/browser fixtures. They perform
no external server dials and load no real credentials.

| Invariant | Enforcement | Evidence |
|---|---|---|
| RDP launch authority is bound to the exact gateway peer and five typed capabilities; public trust cannot be rewritten | root Unix seqpacket manager, connected TCP, oriented independent pipes and sealed bounded memfds mounted read-only | `TestRDPManagerConfigurationAndIdentityRefusal`, `TestRDPManagerPacketsBoundRightsAndPeer`, `TestRDPManagerDescriptorKindsAndSealedTrust` |
| RDP cannot choose a command/runtime or access vault paths; missing or changed runtime content refuses | fixed static worker, root-controlled full ordered file/directory inventory, dedicated identity, private namespaces, denylist seccomp and capability drop | `TestNativeRDPManagerRuntimeAndProvenance`, `TestNativeRDPManagerAuthenticationRevocationAndRefusal` |
| Both worker filters kill foreign architectures and x32, deny namespace creation and a shared kernel surface (userfaultfd, pidfd/process-memory helpers, new mount API, handle lookups, io_uring entry, module/kexec loading, administrative calls) with EPERM, and still allow the calls each worker needs | generated cBPF evaluated instruction by instruction with a strict evaluator that refuses unknown opcodes | `TestSSHSeccompDecisions`, `TestRDPSeccompDecisions`, `TestEvaluateFollowsEveryBranch`, `TestEvaluateRefusesWhatItCannotRead` |
| Installed RDP descendants inherit checked aggregate limits; manager stop revokes I/O and the gateway | optional fixed service profile, exact actual cgroup/UID preflight, BindsTo, control-group kill and reaped lease | `TestServiceRDPPlanAndSharedKernelBoundary`, `TestNativeRDPSystemdServiceBoundary` |
| Workspace clipboard is explicit text-only, finite and isolated; partial or malformed text cannot reach native paste | per-session/per-direction strict codec, 32 KiB per transfer, a 128-transfer burst refilling one per second, completed text notification and immutable native profile | `TestWorkspaceTextBothDirectionsAndResize`, `TestWorkspaceRefusesAuxiliaryMalformedReplayAndLimits`, `TestWorkspaceRemoteClipboardIsCompletedTextWithDistinctStream`, `TestWorkspacePlanKeepsNLAAndClosedAuxiliaryChannels`, `TestPacerBurstRateRefillAndRefusal` |
| Remote clipboard cannot silently write local clipboard or survive a revoked asynchronous read | user-action API calls, text panel fallback, generation checks and cleared UI buffers | `TestBrowserRDPWorkspacePortable`, `TestNativeRDPWorkspaceClipboardAndDisplay` |
| Desktop requests and reported geometry remain finite without opening other native channels | even 64x64..1920x1080 requests, four/second rate, bounded actual drawing schemas and fixed display-update profile | `TestWorkspaceRefusesAuxiliaryMalformedReplayAndLimits`, `TestNativeRDPWorkspaceClipboardAndDisplay` |
| Manager exit and owner cancellation revoke already buffered native/viewer data | lease context canceled on both normal done and peer loss; context checks before/after buffered reads and before writes | `TestViewerAndNativeBufferedDataRefuseRevokedLeaseOrOwner`, `TestNativeRDPSystemdServiceBoundary` |
| Offline service plans cannot inject commands or disable finite aggregate bounds | fixed templates, canonical digest, distinct explicit identities, bounded numeric profiles and exclusive rooted staging | `TestServicePlanFiniteIdentityAndInjection`, `TestSSHWorkerIdentityValidation` |
| Generated services refuse outside their exact actual kernel boundary or dedicated identities | ExecStartPre account/UID/GID/groups plus cgroup-v2 ancestor/controller/value checks before runtime starts | `TestServiceKernelSnapshotRefusesUnenforcedAndWrongGroup`, `TestServiceCheckOutsideInstalledBoundaryRefuses`, `TestKeybashSystemdServiceBoundary` |
| Actual systemd SSH descendants share aggregate limits and stop with their manager | common slice, root-selected worker identity, control-group kill, gateway binding and actual CPU/pids/OOM counters | `TestKeybashSystemdServiceBoundary`, `TestKeybashServiceResourceProbeChild` |
| Remote capacity is an immutable finite operator policy; malformed/zero/unlimited settings cannot silently fall back | one Catalog snapshot, strict optional total/per-owner schema and copied validated Limits | `TestSessionLimitsFiniteBounds`, `TestOperatorCapacityStrictAndLegacy`, `TestRemoteCapacityRejectsInvalidConstructorAndBrowserOverrides` |
| Pending/active leases and independently bounded pre-proof sockets enforce owner/global capacity without evicting live work | mutex admission, configured budgets, fixed busy response and normal expiry/logout/handler cleanup | `TestRemoteCapacityConfiguredOwnersGlobalAndReturn`, `TestRemoteCapacityConcurrentAdmissionAndExpiry`, `TestRemoteCapacityPreProofSocketsAndLiveLease`, `TestBrowserCapacityWorkflow` |
| Root manager capacity replaces the old constant and counts pending/active worker slots | validated ManagerConfig capacity and root-owned catalog startup, slot held through reaping | `TestSSHManagerCapacityValidation`, `TestSSHManagerConfiguredCapacity`, `TestSSHManagerCLIConfiguredCapacity`, `TestOperatorCatalogCLIUnprivilegedTLS` |
| Only a bounded exact-schema offline catalog can provision targets; one bad entry refuses the entire snapshot | versioned duplicate/unknown/coercion refusal, canonical IDs/IPs/CIDRs, per-target policy and copied public identities | `TestOperatorCatalogSSHAndNetworkBinding`, `TestOperatorCatalogRejectsAmbiguousAndForbidden`, `TestOperatorCatalogWholeSnapshotLimits`, `TestOperatorCatalogSSHKeyConstraints`, `TestOperatorCatalogRDPCertificate`, `FuzzOperatorCatalog` |
| Gateway cannot supply or modify its own operator catalog | Linux pinned no-follow directory walk, root ownership, no shared writable direct parent/file, regular single-link bounded snapshot | `TestOperatorCatalogLinuxRootFiles`, `TestOperatorCatalogLinuxUnprivilegedReader`, `TestOperatorCatalogUnsupportedHostRefuses` |
| The explicit SSH CLI needs an SSH-only catalog and separate nonroot manager adapter; custody-only CLI cannot silently gain remote authority | explicit flags/UID/platform/protocol checks, unchanged MFA/TLS/owner boundary and no in-process fallback | `TestOperatorRemoteFlagsAndProtocolGate`, `TestOperatorCatalogCLIUnprivilegedTLS` |
| Owner trust binds the exact host/port/IP pin set and identity; changing only a port or IP invalidates launch | canonical copied target snapshot and version 2 approval digest checked at grant, consumption and workspace entry | `TestServerTrustFingerprintFormatsAndNetworkBinding`, `TestServerTrustChangeReapprovalRevokesAndCAS`, `TestNamedTargetSnapshotIsSortedCopiedAndNetworkFree` |
| New and legacy connections need an explicit full fingerprint and current snapshot; wrong/stale/malformed proofs cannot create authority | strict fields, ready/fresh MFA, owner/CSRF checks and exact digest comparison | `TestServerTrustProofGate`, `TestServerTrustProofRefusalAndMetadata`, `TestServerTrustFreshMFAOwnerAndCSRF`, `TestServerTrustLegacyRequiresExplicitDecisionAndPersists` |
| Trust replacement persists atomically, rejects stale browser revisions and revokes only that connection's active/pending leases | authenticated envelope revision CAS, fsynced transaction and scoped cancellation under the session lock | `TestServerTrustReopenAndStaleRevision`, `TestServerTrustChangeReapprovalRevokesAndCAS`, `TestServerTrustReplacementKeepsOtherConnection` |
| Repeated valid trust confirmations have a finite write budget; refusal preserves revision and active sessions | per-owner five/minute trust bucket before writes | `TestServerTrustMutationBudget` |
| Changed/expired/unreviewed identities are blocked in the UI and API; fingerprint input never prefills itself | typed server metadata, generation-bound review, absent Connect links and worker identity checks retained | `TestServerTrustExpiredUnavailableAndRevisionBounds`, `TestBrowserServerTrustWorkflow` |
| Only the configured unprivileged gateway UID/primary GID can reserve a fixed root-managed SSH launch; root/wrong peers and excess leases refuse | Unix seqpacket, protected root socket, SO_PEERCRED and eight pending/active slots | `TestSSHManagerPacketsBoundRightsAndPeer`, `TestSSHManagerUnprivilegedGateway`, `TestSSHManagerRejectsWrongPeer`, `TestSSHManagerMalformedReplayAndQuota` |
| Manager IPC accepts only a connected TCP descriptor and two distinct, correctly oriented pipes; keys bypass manager parsing | fixed three-FD packet, atomic CLOEXEC, truncation/type/direction checks | `TestSSHManagerDescriptorKinds`, `TestSSHManagerPacketsBoundRightsAndPeer`, `TestSSHManagerMalformedReplayAndQuota` |
| Gateway revocation, repeated launch and manager shutdown/crash cannot retain an isolated SSH connection | one lease per control socket, owned-process cancellation/parent-death boundary and reaped acknowledgement | `TestSSHManagerUnprivilegedGateway`, `TestSSHManagerShutdownRevokesGateway`, `TestSSHManagerCrashRevokesGateway`, `TestSSHManagerMalformedReplayAndQuota`, `TestSSHManagerRefusalIsNilBeforeDial` |
| SSH worker IPC bounds allocation and rejects repeated startup; cancellation drops queued data while clean EOF drains it; long output is not cut at a lifetime total | typed binary frames, bounded queues and explicit lifetime checks | `TestWorkerFrameBoundsAndSchemas`, `TestSSHWorkerCoreUnexpectedInputCloses`, `TestProcessOutputDropsBufferedDataAfterRevocation`, `TestProcessOutputDrainsAfterCleanWorkerExit`, `TestProcessOutputHasNoLifetimeTotal`, `FuzzSSHWorkerFrames` |
| The separate SSH child verifies the actual connection's host pin before configured key authentication; revocation joins its managed process | fixed Linux sandbox, inherited guarded TCP descriptor and original SSH verification gate | `TestSSHWorkerCorePinInputResizeAndCancellation`, `TestSSHWorkerCoreChangedPinRefusesBeforeAuth`, `TestSSHProcessIsolatedAuthenticationAndRevocation`, `TestSSHProcessChangedPinNeverAuthenticates`, `TestSSHProcessRequiresConfiguredKeyAuthentication`, `TestSSHProcessOwnedBrowser` |
| Invalid worker images cannot reach a target dial; session keys refuse malformed/closed material and redact formatting | root-controlled hash-bound static image and one-session key handoff | `TestSSHProcessImageAndPolicyRefuseBeforeDial`, `TestSessionKeyHandoffAndClose` |
| A worker receives exactly one validated credential, a key or a password, in a versioned start frame; what the gateway encodes is what the worker decodes, and nothing missing, malformed, oversized or of another kind crosses | sealed `sshkey.Credential`, PKCS#8 handoff bounded to 8 KiB, password rules shared with import | `TestSessionHandoffRoundTrip`, `TestSSHWorkerCorePasswordHandoff`, `TestSSHWorkerCoreMalformedStartupNeverAuthenticates`, `TestSessionKeyTypesStrengthAndAlgorithms`, `TestSessionPasswordBoundsAndClose` |
| Interactive UI preview stays synthetic; its bounded desktop input refuses clipboard/arbitrary instructions, wrong demo credentials and cancellation | only browserlab `_test.go` workers; fixed command simulation with no dial/process execution | `TestDemoInputBoundary`, `TestDemoWorkerCancellation`, `TestInteractiveDemoBrowser` |
| Owned connections cannot select another owner's credential or authenticate relocated ciphertext | connection envelope kind/owner AAD, server ownership references | `TestOwnedRemoteFreshStateCredentialDeletionAndOtherAccount`, `TestOwnedConnectionEnvelopePersistenceAndOwnerBinding` |
| Launch requires a ready MFA session at the current account revision on both grant and consumption; creating, trusting or deleting connections and deleting credentials still require fresh proof | session-bound single-use 30-second capability, current account/record checks | `TestOwnedRemoteLeaseOwnershipReplayExpiryAndRevocation`, `TestOwnedRemoteFreshStateCredentialDeletionAndOtherAccount`, `TestOwnedRemoteExpiryLimitsAndDelete` |
| Reused target IDs cannot silently retarget credentials to another approved identity | authenticated connection approval fingerprint | `TestOwnedRemoteChangedApprovalRefusesStoredConnection` |
| Logout, MFA readiness loss, deletion and late setup cannot escape the account's remote cancellation context | bound lease contexts, stream/socket close and rechecks | `TestOwnedRemoteSocketEchoLogoutAndLateSetup`, `TestOwnedRemoteFreshStateCredentialDeletionAndOtherAccount`, `TestOwnedRemoteMFADowngradeStopsOutputAuthority` |
| Browser supplied owner/target overrides and missing trusted launchers refuse | exact fields, immutable catalog, protocol/credential-kind matching | `TestOwnedRemoteConstructorAndMalformedRequests` |
| Integrated SSH and native RDP take the selected owned credential through MFA to browser input/logout | authorized relay plus actual key-auth/PTY and isolated NLA/viewer/broker fixtures | `TestBrowserOwnedSSHConnectionAndLogout`, `TestNativeRDPOwnedIdentityVaultAndBrowser`, `TestBrowserOwnedRemotePortable` |
| Initial registration requires a single-use expiring local setup code; it cannot reopen | atomic bootstrap state and keyed metadata | `TestCustodyBootstrapSingleUseExpiryAndExclusiveOpen`, `TestCustodyOfflineRecoveryBootstrapRenewalAndSealLimit` |
| A password alone cannot enroll the first factor of an operator-created or factor-reset account: the seed appears only after that account's own unexpired one-time setup code, wrong codes spend its MFA budget, enrollment spends the code and recovery replaces it | 256-bit code, digest and 72-hour expiry inside the encrypted account record, owner-bound check before seed issuance and again at confirmation | `TestFirstEnrollmentNeedsOperatorSetupCode`, `TestRecoverySetupCodes`, `TestAccountSetupFieldsMustBeConsistent`, `TestOperatorLinuxInitBootstrapAndOfflineRecovery` |
| Password-only persistent sessions cannot access custody | explicit enroll/challenge/ready state and rotated cookies | `TestPersistentPasswordSessionsCannotOpenVault`, `TestCustodyHTTPBootstrapMFAAndVault` |
| Factor replay and recovery reuse are refused across restart/concurrency | transactional greatest counter, hashed one-time codes, durable failed-attempt budget | `TestCustodyMFAReplayRecoveryAndRestart`, `TestCustodyFactorFailuresPersistAndReplacementKeepsOldMFA` |
| Old MFA survives an abandoned replacement; old sessions die on account revision changes | pending session seed and atomic replacement | `TestCustodyHTTPBootstrapMFAAndVault`, `TestCustodyRandomEnvelopesQuotaAndHTTPIsolation` |
| Secrets are encrypted at rest and authenticated to immutable owner/record IDs | separate random instance key, HKDF purposes, per-save random DEK and random-nonce GCM, metadata MAC/seal budget | `TestCustodyCiphertextOwnerBindingTamperAndPlaintextAbsence`, `TestCustodyRandomEnvelopesQuotaAndHTTPIsolation`, `TestCustodyOfflineRecoveryBootstrapRenewalAndSealLimit` |
| Sensitive custody mutations/reveal require fresh password plus factor (completing sign-in counts until the password check is two minutes old); owner is never browser supplied | server ready/fresh/session owner checks, strict JSON | `TestCustodyHTTPBootstrapMFAAndVault`, `TestCustodyRandomEnvelopesQuotaAndHTTPIsolation`, `TestCustodyCancelledReauthentication`, `TestSignInFreshnessStartsAtPasswordCheck` |
| Slow bodies do not hold session revocation; malformed/ambiguous fields refuse | bounded read before account mutex, exact scalar fields | `TestCustodyStrictFieldsAndSlowBodyIsolation`, `FuzzCustodyFields` |
| SSH import bounds cost before parsing and rejects key confusion and weak keys | bounded OpenSSH Ed25519/ECDSA/RSA and bcrypt preflight, type/strength check, stored public half must be the private key's own | `TestCustodySSHImportBoundsAndPasswordBlocklist`, `TestCustodySSHRejectsCostBombAndMismatchedPublic`, `TestCustodySSHImportKeyTypes` |
| Linux provisioning refuses shared files, symlinks, concurrent writers and a key inside DB storage | owned 0700 roots, 0600 regular files, exclusive rooted opens | `TestCustodyLinuxPrivateProvisioning`, `TestOperatorLinuxInitBootstrapAndOfflineRecovery` |
| A backup holds no key and no plaintext; it opens only with its instance key, and every header field is bound to its body | logical copy in one read transaction, per-file HKDF key from the instance key, random-nonce GCM with the header as associated data | `TestBackupRestoresEveryRecordAndResetsMFA`, `TestRestoreRefusesWrongKeyTamperingAndExistingFiles`, `TestOperatorLinuxBackupKeyRecoveryAndRestore` |
| Only a store that would restore is backed up, and only such a backup restores: known flat namespaces, every record readable, one name index per account, owned records, write quotas | the same full verification before a backup and inside the restore transaction; canonical sorted entries | `TestBackupRefusesWhatItCouldNotRestore`, `TestBackupHoldsTheWriteQuotas`, `TestRestoreRefusesMalformedOrInconsistentBodies`, `FuzzBackupFile` |
| Restore never replaces a file, leaves nothing on refusal, and no restored database ever carries an old factor or recovery code | exclusive create; copy, verification and MFA reset with fresh setup codes commit in one transaction; own file removed on failure | `TestBackupRestoresEveryRecordAndResetsMFA`, `TestRestoreRefusesWrongKeyTamperingAndExistingFiles`, `TestOperatorLinuxBackupKeyRecoveryAndRestore` |
| The instance key leaves only as a checked recovery code from a key that opens the store, and is written back only to a new private key file | four-byte check, canonical base32, exclusive 0600 create; backups refused beside the key | `TestInstanceKeyCodeRoundTripAndTypos`, `TestBackupNeverBesideItsKey`, `TestOperatorLinuxBackupKeyRecoveryAndRestore` |
| Custody UI uses local assets, no secret URLs/storage, and clears explicit reveal | strict response handling, text DOM, explicit user copy and expiry/hide | `TestBrowserDurableCustody` |
| Pages load one pinned typeface and their stylesheets from this server only, with exact types; no sheet loads another URL, import or inline style, and every text colour stays legible in both schemes | hash-pinned font, `font-src 'self'` on every page policy, fixed public asset list, contrast check over the stylesheet tokens | `TestTheTypefaceIsTheOneChosenAndCarriesItsLicence`, `TestEveryPageLoadsTheSharedDesign`, `TestPagesServeTheSharedDesignFromHere`, `TestEveryColourTextIsSetInIsLegible` |
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
| A server with no DNS name is approved by one canonical SSH address with no addresses list; it never resolves a name and dials only that literal through its policy; RDP keeps a name | `NewAddressTarget`, catalog literal branch | `TestAddressTargetDialsTheApprovedLiteralWithoutDNS`, `TestOperatorCatalogAddressOnlySSHTarget`, `TestOperatorCatalogRDPCertificate` |
| Failure does not silently switch to another address | one selected literal endpoint | `TestNamedTargetUsesFirstPinnedAnswerWithoutFallback` |
| Bad hostname, missing pins, wrong port or missing policy cannot create a named target | `NewNamedTarget` | `TestNamedTargetConfigurationFailsClosed`, `FuzzCanonicalHostname` |
| Resolver errors and partial answers disclose no diagnostics and cause no TCP dial | fixed errors and shared deadline | `TestNamedTargetDNSFailureAndCancellationPerformNoTCP` |
| Changed server host keys stop before user authentication | copied approved host pin callback; signer gate | `TestSSHChangedHostKeyStopsBeforeAuthentication`, `TestSSHHostPinIsCopiedAndSignerCannotRunBeforeVerification` |
| Invalid or missing host/user identity cannot reach the network | bounded config validation before dial | `TestSSHInvalidConfigurationAndCanceledRequestsNeverDial`, `FuzzSSHHostKeyConfig` |
| A session requires its one configured credential, with no fallback | only verified key signer or password, refuse successful none-auth; an RDP target takes only a password | `TestSSHRefusesNoneAuthAndAuthenticationOrPTYFailure`, `TestOwnedSSHCredentialKinds` |
| A password reaches only a host whose key matched its pin, through password or a single hidden keyboard-interactive prompt; RSA keys never sign with SHA-1 | credential offered only after host verification; SHA-2-only algorithm list; visible or multiple prompts refuse | `TestSSHPasswordAuthenticationAfterHostVerification`, `TestSSHUserKeyTypesAndNoSHA1` |
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
| Output cannot advance beyond a 32-frame window of in-order, nonduplicate render credit for frames actually sent; a browser that stops acknowledging releases the stream | sequence window, bounded queue, credit timeout | `TestLabOutputWaitsForMatchingCredit`, `TestLabInvalidConfigurationAndControlBounds`, `TestLabStalledCreditReleasesStream`, `TestRelayRefusesUnsentCredit` |
| Owned sessions have no lifetime output total and render credit does not spend the typed-input budget; bulk output keeps the session interactive | window bounds memory; only input/resize count toward 128 frames and 256 KiB per second | `TestRelayAcknowledgedBulkOutputHasNoLifetimeCeiling`, `TestLabExpiryAndRateCloseOwnedStream` |
| The original terminal lab keeps a total 8 MiB ceiling | total byte counter before transmission | `TestLabOutputQuotaClosesBeforeExtraData` |
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
| Unsolicited native files/pipes/clipboard/prompts are refused; native output beyond 16 MiB or 16384 instructions per second is paced, not ended, and revocation ends a pause | fixed opcode boundary, continuous byte/instruction budgets that backpressure guacd | `TestNativeStreamRefusesUnsolicitedStreamsAndBoundsOutput`, `TestNativeStreamLongSessionIsPacedNotEnded`, `TestPauseStopsOnRevocation` |
| A broker binds the logical identity to its guarded target and cannot be reused | private name-bound single-use raw transport capability | `TestNativeBrokerBindsIdentityToGuardedTarget`, `TestNativeBrokerRawUnicodeSingleUseAndCancellation` |
| Broker end of either direction and failed/late/canceled dials close both streams; a long desktop is not cut at a lifetime total | bounded copy buffer, cancellation/EOF cleanup | `TestNativeBrokerLongStreamAndEndClosesBothDirections`, `TestNativeBrokerFailedAndCanceledDialsCloseOwnedConnections` |
| Native TLS refuses changed/invalid certificates and downgrade before any CredSSP data | mandatory OpenSSL exact-leaf/name/usage/time/critical/key hook; no TOFU/ignore | `TestNativeRDPCertificateRefusalBeforeCredentials` |
| Synthetic correct NLA password yields decoded desktop images; wrong password refuses; cancellation stops worker/broker | actual pinned native peer, bounded PNG decode, test-only process supervision | `TestNativeRDPAuthenticationRenderingAndRevocation` |
| Native worker has private network/filesystem/PID boundaries and no groups/capabilities; cannot replace trust or independently dial | test-only Bubblewrap/setpriv/read-only mounts and resource limits | `TestNativeRDPSandboxPreparation`, `TestNativeRDPChild` |
| Reaching private IPC does not authorize a process with the wrong host UID | Unix peer credential check before accepting the capability | `TestNativeRDPControlIPCRejectsWrongUID` |
| Desktop profile keeps the existing TLS/owner/Origin boundary and exposes a fixed local asset set | immutable desktop profile, self-only scripts/Blob-only images | `TestDesktopProfileKeepsOwnerOriginAndClosedAssetBoundary` |
| Browser drawing is typed/bounded and decoded PNGs normalize before ordered forwarding | private viewer state, static PNG re-encoding/staging, layer/geometry/stack limits | `TestViewerValidatedPNGGroupingInputAndRevocation`, `TestViewerNormalizesPNGWithoutMetadataAnimationOrTrailingData`, `TestViewerRefusesMalformedAndExcessDrawing`, `TestViewerInvalidPNGIsNeverForwarded`, `FuzzViewerDrawingSchemas` |
| Compressed images and drawing cannot spend pixel work faster than a fixed rate (32M decoded, 64M drawn pixels per second); excess pauses the session's reader, a single oversized cost refuses | continuous decode/render budgets checked before expensive operations | `TestViewerDecodeAndRenderWorkArePacedNotEnded`, `TestViewerRevocationEndsAPacedWait`, `TestPacerBurstRateRefillAndRefusal` |
| Browser input cannot select targets/credentials/streams or replay credits | one bounded instruction, opcode/state/keysym/coordinate limits | `TestViewerInputRefusesArbitraryParametersReplayAndBounds` |
| Revocation closes partial image reads and refuses late input/output | atomic closed state and native transport teardown | `TestViewerPartialImageAndCancellationCloseReaders`, `TestViewerValidatedPNGGroupingInputAndRevocation` |
| Browser pixels and input are independently measured; logout removes the display and native stream | isolated Edge/Chromium fixture and actual native NLA peer markers | `TestBrowserRDPViewerLab`, `TestNativeRDPBrowserDesktopAndRevocation` |
| Passwords use independently salted fixed-cost Argon2id and exact Unicode bytes | opaque versioned hash, constant-time comparison, byte/codepoint limits | `TestPasswordSaltUnicodeAndWrongPassword` |
| Login creates a fresh owner session; logout/password change cannot revoke another account | hashed random token, owner-bound session and revision recheck | `TestIdentityLoginGateRotationLogoutAndAccountIsolation`, `TestIdentityPasswordChangeRevokesOnlyItsOwner`, `TestIdentityRefusesWrongUnknownAndCrossAccountPassword` |
| Identity mutation requires exact TLS/peer/Host/Origin and session-bound CSRF; duplicate/forged cookies refuse | common HTTP boundary before hashing and standard HMAC proof | `TestIdentityTLSOriginCSRFAndCookieBoundary`, `TestIdentityLoginRejectsUntrustedTransportBeforeHash` |
| JSON credentials reject duplicate/unknown/coerced fields, invalid UTF-8/surrogates and excess input | bounded scalar preflight and exact two-string decoder | `TestIdentityStrictJSONAndBodyBounds`, `FuzzIdentityJSON` |
| Known/unknown accounts share bounded attempt policy; KDF and sessions have finite capacity | per-name login and per-account purpose windows, two slots, owner/aggregate session caps | `TestIdentityAttemptBucketsAreUniformAndBounded`, `TestIdentityRateKDFAndSessionQuotas`, `TestIdentityActivityRenewalAndOwnerSessionQuota` |
| Failed logins, from one name or a flood of names, cannot lock out another account or a signed-in owner's reauthentication; capacity refusals create no attempt state and a full table never evicts a counter | no shared window; KDF slot before recording; refusal at 8192 keys; one-second expiry sweep | `TestIdentityFailedLoginsCannotLockOutOthers`, `TestIdentityCapacityRefusalCreatesNoAttemptState`, `TestIdentityAttemptBucketsAreUniformAndBounded` |
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
Failures against one name still deny that name for a minute, and per-source
limits await network ingress; KDF concurrency is not a process-memory or DDoS
guarantee. Production durability/ownership and independent
candidate review remain gates before real credentials or remote access.

The initial RDP probe is a pre-credential experiment and private text prototype. The
probe checks its own TLS, closes it, and never sends CredSSP; it cannot authorize
guacd's connection. Its imported leaf is the only trust anchor; standard TLS/name
verification remains enabled with an extra exact DER pin. A separate pinned
native Linux lab enforces its own TLS identity before CredSSP, authenticates a
synthetic account and decodes desktop images through a one-use broker and
test-only worker sandbox. Both actual C callback mutations must fail before
restoration and a full rerun. Refusal timeouts are failures, not proof. Native
clipboard/touch/dynamic display remain disabled in that original profile. Its
loopback viewer is fixed-viewport with finite memory/work/output quotas. The
separate source manager profile adds bounded text/display controls, a minimal
read-only runtime, syscall denylist, installed service identities and aggregate
cgroups; it composes with the custody/owner boundary. It is still no general
Guacamole tunnel or public product listener. The earlier empty namespace also
denies approved destinations. Codec-only tests cannot establish native/browser
clipboard evidence. See ADR 0003, `NATIVE-RDP-LAB.md` and
`RDP-WORKSPACE-INTEGRATION.md` for their distinct acceptance boundaries.

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

SSH accepts Ed25519 host keys. User keys may be Ed25519, ECDSA P-256/384/521 or
RSA 2048–8192 bits signing only with SHA-2, or the account may use a password.
Setup has a ten-second budget and a parent-context session lifetime. The owned
custody lab imports bounded OpenSSH keys and supplies MFA, ownership, session quotas, idle limits and revocation.
The original library worker runs in process; `SSH-PROCESS-LAB.md` adds a separate
constrained Linux/amd64 worker. `SSH-MANAGER-LAB.md` adds an authenticated separate
root manager for an unprivileged gateway. `SERVER-TRUST-LAB.md` adds owner review
of the immutable operator catalog; it is not discovery or catalog provisioning.
Root-owned operator configuration and source systemd/aggregate-cgroup integration
are implemented. A packaged installer, password/certificate SSH auth and
independent candidate review remain gates.
Browser and real Bash evidence is confined to the laboratory; vim/tmux and the
full browser/OS matrix remain unmeasured. Channel windows impose backpressure;
both output streams need consumption. Closing a stream does not guarantee
killing all remote processes.

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
