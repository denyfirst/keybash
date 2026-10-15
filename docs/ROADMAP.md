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
   Remote-resource ownership/worker integration, restore/rotation and audited
   production release remain gates.
4. **Workspace:** Denyfirst UI, connections/search/favorites, terminal/RDP tabs,
   bounded clipboard behavior, reconnect states and accessible keyboard flows.
5. **Self-host packaging:** Linux deployment, isolated workers and egress,
   trusted TLS, offline runtime, safe upgrades and fresh-system restore.
6. **Candidate and release:** load/browser matrix, independent security review,
   findings resolution, protected signed tags, separated build/sign/reproduce
   path, and a separately authorized public release.

Sharing, SFTP, jump hosts and mobile parity remain later decisions. We do not
copy application code from Porch or Rootwell to accelerate these stages.
