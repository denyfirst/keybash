# RDP workspace integration work record

Scope: source-only Linux/amd64 RDP manager and isolated native runtime, bounded
explicit text clipboard, bounded desktop resizing and a fresh disposable test
VM setup path. No release artifact or customer deployment is authorized here.
Porch and Rootwell remain untouched. Existing SSH gates remain required.

Trust boundary: the gateway owns login/MFA, owner authorization, catalog/trust
and guarded dialing. A separate root manager accepts a single already-connected
TCP descriptor, two correctly oriented pipes and two immutable sealed public
trust memfds from the exact gateway UID/GID (exactly five descriptors).
It never parses credentials or accepts a command/path/target from IPC. The
fixed worker runs under a separate nonroot identity, private network/PID/mount
namespaces and a read-only hash-bound runtime. Only private loopback listeners
exist there. The native X509 callback remains mandatory before CredSSP.
Host root and the gateway remain trusted. This is not a zero-knowledge model.

The original native lab remains clipboard/resize-disabled. Only the fixed RDP
manager selects the workspace profile. It admits text/plain up to 32 KiB,
128 transfers per direction, explicit local clipboard actions and even display
sizes from 64x64 to 1920x1080 at at most four requests/second. HTML/files and
auxiliary channels remain refused. The 8 MiB output/instruction/pixel-work
laboratory ceilings remain; this is not a long-session production claim.

The user has no test VMs yet and requested a setup guide. `TEST-SETUP-AZ.md`
provides the separate Ubuntu/Linux/Windows setup and pinned source build path;
no VM or customer service has been deployed from this workstation.

Acceptance work:

- [ ] Exact-peer manager IPC, runtime/image provenance, isolated native worker,
  cancellation/reaping and installed service/cgroup integration.
- [ ] Text-only, bounded, explicit user copy/paste; permission fallback, no
  automatic local clipboard writes, session isolation and revocation.
- [ ] Bounded size request, validated native resize and browser geometry.
- [ ] Source test setup on an empty supported VM, trusted local TLS access,
  explicit operator approvals and step-by-step SSH/Windows test instructions.
- [ ] Positive/refusal/malformed/abuse and both-direction mutation evidence,
  native/browser/service CI, signed PR and adversarial self-review.

Real Windows VM/browser matrix, sizing, production installer/upgrade/restore,
independent exact-candidate audit and separately authorized release remain
distinct gates. CI cannot supply the user's VM or verify an unavailable host.
