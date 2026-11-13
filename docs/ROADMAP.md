# Keybash roadmap

Stages are evidence gates, not delivery dates. Update decisions as we learn.

21 October source integration: the separate RDP manager/runtime, explicit
text clipboard, bounded display-update profile and optional shared-cgroup RDP
service plan are implemented. Required actual native/browser/service evidence
is tracked in `RDP-WORKSPACE-INTEGRATION.md`; the disposable test-VM guide is
`TEST-SETUP.md`. These additions do not complete
the real Windows/browser matrix, production installer, restore or release gates.

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
   operator configuration, key rotation and audited release remain gates.
   Offline backup, instance key recovery and restore to a clean directory
   exist (`BACKUP-RESTORE.md`).
   The SSH process boundary now has an authenticated separate Unix manager for
   an unprivileged gateway (`SSH-MANAGER-LAB.md`). Source service identities,
   aggregate cgroups and a separate RDP manager are implemented; packaged
   installation and production release remain gates.
4. **Workspace:** Denyfirst UI, connections/search/favorites, terminal/RDP tabs,
   bounded clipboard behavior, reconnect states and accessible keyboard flows.
   The configured-server identity review now requires explicit owner fingerprints,
   full network snapshot binding and fresh reapproval of changed/legacy records
   (`SERVER-TRUST-LAB.md`). Operator catalog provisioning remains a gate.
5. **Self-host packaging:** Linux deployment, isolated workers and egress,
   trusted TLS, offline runtime, safe upgrades and fresh-system restore.
   A root-owned offline target catalog and explicit nonroot SSH-only loopback
   CLI now bind operator policy to the manager (`OPERATOR-CATALOG-LAB.md`).
   Source service identities/units and RDP integration are present; production
   packaging and real Windows acceptance remain.
   Remote admission now has immutable operator total/per-owner capacity and
   matching manager slots (`SESSION-CAPACITY.md`); checked kernel CPU/RAM/pids
   are in the source service plan, while measured host sizing remains a gate.
   A source systemd plan now separates gateway/worker identities and binds
   gateway/manager/SSH descendants to checked aggregate cgroup-v2 CPU/memory/pids
   limits (`LINUX-SERVICE-LAB.md`). Disposable CI installs synthetic units and
   measures actual SSH, restart/revocation and kernel enforcement. A packaged
   fresh-host installer, trusted public ingress and measured sizing remain.
6. **Candidate and release:** load/browser matrix, independent security review,
   findings resolution, protected signed tags, separated build/sign/reproduce
   path, and a separately authorized public release.

Sharing, SFTP, jump hosts and mobile parity remain later decisions. We do not
copy application code from Porch or Rootwell to accelerate these stages.

## Desktop picture and staying current (11 November 2026)

Measured on the test VM with two VM-only instrumented builds (never
committed) on a real Windows Server 2025 desktop:

- Before PR 70: 9 to 20 frames a second in motion; the gateway's reader was
  busy about 55% of the time, mostly writing PNGs again; the browser answered
  each frame in 8 to 21 ms.
- With PR 70's parallel rebuild: still 11 to 20 frames a second, but the
  gateway now mostly waits on guacd, the VM is about 80% idle and guacd uses
  about 45% of one core. The remaining limits are Windows' legacy bitmap path
  (`disable-gfx`) and a half-resolution picture on high-DPI screens: at 200%
  scale the browser stretches the desktop twice, so text is less sharp than
  in Hyper-V's own console.

State of the art: the RDP Graphics Pipeline (MS-RDPEGFX) with H.264 (AVC420,
AVC444) decoded in the browser on the GPU through WebCodecs. guacamole-server
1.6.0, the latest release, decodes the pipeline into pictures; offering H.264
is an open upstream pull request (apache/guacamole-server#733). Third-party
projects pass H.264 to WebCodecs (rustguac, guac-extra), FreeRDP merged a
WebCodecs H.264 decoder for its WebAssembly build, and IronRDP (Rust,
memory-safe) merged client graphics-pipeline support with AVC420 in 2026.

In order:

1. **FreeRDP 3.32.2 to 3.33.1.** 3.33.0 and 3.33.1 carry 24 security
   advisories. Among those that reach Keybash's client: an out-of-bounds write
   in client GDI OpaqueRect clipping (high), a use-after-free in the brush
   cache drawing orders, and heap corruption in the Progressive codec (high,
   graphics pipeline). This comes before anything turns the pipeline on.
   Done in PR 72: the archive's checksum and release signature were verified
   before pinning, and the native CI lab built and passed with it.
2. **Toolchain:** Go 1.27, golang.org/x/sys 0.50, the Node 24 LTS patch,
   Playwright 1.65 and pnpm 12 (its lockfile checked in CI).
   Done in PR 73, with Node 26 instead: it became the active LTS line in
   October. pnpm 12's native binary is pinned by hash and run without npm.
3. **Staying current:** Dependabot for Go modules, the web lockfile and GitHub
   Actions; a weekly workflow that compares the pinned native sources and
   tools (FreeRDP, guacamole-server, Go, Node, pnpm) with their upstream
   releases and opens an issue when one is behind; govulncheck nightly, not
   only on pull requests. Security releases are adopted within days.
   Done in PR 74 without Dependabot, whose unsigned commits cannot pass the
   signature gate: one weekly check covers Go, modules, native sources, Node,
   pnpm, browser packages and analysis tools (`STAYING-CURRENT.md`).
4. **A sharp desktop on high-DPI screens:** the page asks for the screen's
   device pixels and the matching remote DPI, within raised size bounds that
   keep their tests and budgets.
   Done in PR 76: Windows' scales 100 to 200%, bounds and budgets times the
   area at most (`BROWSER-RDP-LAB.md`, Scaled screens).
5. **Graphics pipeline experiment** (after 1): RemoteFX Progressive on the
   test VM, measured with the same instrumented build.
6. **ADR 0007 (to propose): H.264 to the browser through WebCodecs.** The
   default keeps today's rule that the browser never parses bytes made by the
   remote server: guacd and FreeRDP decode the stream inside the sandbox, and
   Keybash's own encoder writes the stream the browser decodes, with lossless
   pictures kept for still text. A strictly validated passthrough of Windows'
   own H.264 is the faster alternative to measure against it. Codec choices
   wait for the project licence: OpenH264 (BSD-2-Clause) or FFmpeg (LGPL),
   never a GPL encoder.
7. **Watch:** IronRDP as a memory-safe replacement for FreeRDP once its client
   graphics pipeline is ready for production.

The QOI-style picture draft (ADR 0006) is set aside: the gateway is no longer
the bottleneck.
