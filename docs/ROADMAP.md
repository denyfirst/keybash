# Keybash roadmap

Stages are evidence gates, not delivery dates. Update decisions as we learn.

1. **Foundation (current PR):** independent signed repository with the
   maintainer-authorized public visibility and enforced branch protection,
   product/threat plan, engineering workflow, fail-closed IP target guard,
   negative and mutation evidence, reproducible local/CI checks.
2. **Protocol lab:** review candidate dependencies; prove SSH remote PTY and
   RDP transport with synthetic credentials. Integrate pinned DNS resolution
   with the guard, verify SSH host keys/RDP certificates, and measure copy/paste
   and keyboard behavior. No production credential custody at this stage.
3. **Identity and custody:** local login/MFA, server-side ownership checks,
   encrypted credential persistence, safe import/export, recovery and session
   revocation. Describe the server's ability to access active credentials.
4. **Workspace:** Denyfirst UI, connections/search/favorites, terminal/RDP tabs,
   bounded clipboard behavior, reconnect states and accessible keyboard flows.
5. **Self-host packaging:** Linux deployment, isolated workers and egress,
   trusted TLS, offline runtime, safe upgrades and fresh-system restore.
6. **Candidate and release:** load/browser matrix, independent security review,
   findings resolution, protected signed tags, separated build/sign/reproduce
   path, and a separately authorized public release.

Sharing, SFTP, jump hosts and mobile parity remain later decisions. We do not
copy application code from Porch or Rootwell to accelerate these stages.
