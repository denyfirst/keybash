# RDP workspace integration work record

Scope: source-only Linux/amd64 RDP manager and isolated native runtime, bounded
explicit text clipboard, bounded desktop resizing and a fresh disposable test
VM setup path. No release artifact or customer deployment is authorized here.
Porch and Rootwell remain untouched. Existing SSH gates remain required.

Trust boundary: the gateway owns login/MFA, owner authorization, catalog/trust
and guarded dialing. A separate root manager accepts a single already-connected
TCP descriptor and two correctly oriented pipes from the exact gateway UID/GID.
It never parses credentials or accepts a command/path/target from IPC. The
fixed worker runs under a separate nonroot identity, private network/PID/mount
namespaces and a read-only hash-bound runtime. Only private loopback listeners
exist there. The native X509 callback remains mandatory before CredSSP.
Host root and the gateway remain trusted. This is not a zero-knowledge model.

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
