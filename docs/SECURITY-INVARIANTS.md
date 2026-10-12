# Implemented Keybash security invariants

This file describes only code that exists. Planned login, vault, SSH host-key,
RDP certificate, DNS, clipboard and deployment controls are in the product
plan and roadmap, not claims of this foundation. Tests use synthetic targets
and in-memory connections; they perform no external network dials.

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

## Limits

The guard accepts parsed IP/port pairs, not hostnames. It is not yet wired into
an SSH/RDP worker. Integration must approve and dial the same resolved address
without asking guacd or another library to resolve the hostname again. A
resolver's returned IP still needs the same protection and exact-target checks.

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
