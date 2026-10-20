# Keybash roadmap

Stages are evidence gates, not delivery dates. Update decisions as we learn.

1. **Foundation (completed):** independent signed repository with the
   maintainer-authorized public visibility and enforced branch protection,
   product/threat plan, engineering workflow, fail-closed IP target guard,
   negative and mutation evidence, reproducible local/CI checks.
2. **Protocol lab (started):** hostname-scoped pinned DNS dialing and SSH
   identity/key-auth/PTY library and browser lab implemented, with Linux Bash
   fixture checks. Credential-free RDP negotiation/pinned TLS, bounded text codec
   and an empty Linux netns experiment are implemented. A pinned native lab adds
   actual TLS identity enforcement, synthetic NLA login, decoded desktop images,
   a one-use guarded broker and isolated worker/revocation checks. Next measure
   actual browser desktop copy/paste, keyboard layouts, resize and reconnect behavior.
   A loopback RDP viewer adds bounded PNG/canvas rendering, focused keyboard/
   mouse, held-key release, fullscreen and native-to-browser revocation evidence. No production credential custody at this stage.
   The native build/broker and required success/refusal/mutation fixtures are
   tracked in `NATIVE-RDP-LAB.md`; passing Go codec tests alone
   cannot complete its native acceptance gate.
3. **Identity and custody:** local login/MFA, server-side ownership checks,
   encrypted credential persistence, safe import/export, recovery and session
   revocation. Describe the server's ability to access active credentials.
   An isolated memory-only password-login lab implements individual accounts,
   Argon2id, browser login/password change, bounded attempts/sessions and active
   expiry/logout. Durable accounts/bootstrap/MFA, owner-scoped encrypted key/password custody
   and fresh proof now have a Linux loopback lab; see `CUSTODY-LAB.md`.
   Remote-resource ownership and revocation now connect the synthetic SSH/native
   RDP browser fixtures (`OWNED-REMOTE-LAB.md`). Installed isolated workers,
   operator configuration, restore/rotation and audited release remain gates.
   The SSH process boundary now has an authenticated separate Unix manager for
   an unprivileged gateway (`SSH-MANAGER-LAB.md`); installed service identities,
   aggregate cgroups and the production RDP launcher remain gates.
4. **Workspace:** Denyfirst UI, connections/search/favorites, terminal/RDP tabs,
   bounded clipboard behavior, reconnect states and accessible keyboard flows.
   The configured-server identity review now requires explicit owner fingerprints,
   full network snapshot binding and fresh reapproval of changed/legacy records
   (`SERVER-TRUST-LAB.md`). Operator catalog provisioning remains a gate.
5. **Self-host packaging:** Linux deployment, isolated workers and egress,
   trusted TLS, offline runtime, safe upgrades and fresh-system restore.
   A root-owned offline target catalog and explicit nonroot SSH-only loopback
   CLI now bind operator policy to the manager (`OPERATOR-CATALOG-LAB.md`).
   Installed service identities/units and production RDP integration remain.
   Remote admission now has immutable operator total/per-owner capacity and
   matching SSH manager slots (`SESSION-CAPACITY.md`); kernel CPU/RAM/pids and
   measured host sizing remain part of service integration.
6. **Candidate and release:** load/browser matrix, independent security review,
   findings resolution, protected signed tags, separated build/sign/reproduce
   path, and a separately authorized public release.

Sharing, SFTP, jump hosts and mobile parity remain later decisions. We do not
copy application code from Porch or Rootwell to accelerate these stages.
