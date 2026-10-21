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

Implemented source and its required acceptance boundaries:

| Boundary | Required observable evidence |
| --- | --- |
| Manager IPC and minimal runtime | Exact peer and five descriptor types/seals, malformed/truncated rights, digest/ownership/mode/refusal, native NLA, pin refusal before CredSSP and canceled I/O |
| Installed service lifecycle | Actual generated gateway/SSH/RDP units, live distinct worker identity, exact cgroup membership and aggregate values, stop/reap, mismatched-limit refusal and restart |
| Clipboard | Completed UTF-8 only, stream collisions and malformed/NUL/oversize refusal, explicit copy/paste, permission fallback, actual headless OS clipboard through native CLIPRDR, session cleanup and late-read refusal |
| Desktop size | Bounded request/flood refusal, actual DISPLAYCONTROL monitor layout, native display resize and browser geometry |
| Separate VM preparation | `TEST-SETUP-AZ.md`: fresh Ubuntu source build, approved Linux/Windows identities, trusted HTTPS, account/MFA setup and first connection instructions; customer VMs are not provisioned or tested |

`native/clipboard.c` uses the already pinned WinPR conversion API after querying
capacities. It validates surrogate pairs and termination, refuses lossy UTF-8
roundtrips, snapshots input under the native clipboard lock and handles
Guacamole's initial empty state or one final NUL as framing. Native
ASan/UBSan tests compare Unicode golden wire bytes, malformed text, exact bounds
and empty clipboard. Both accept-all/refuse-all conversions must fail their
intended assertions, followed by the normal unchanged sanitized test. Both
allow-all/refuse-all syscall filter overlays must fail the actual public-only
manager/helper startup test; the full unmodified native suite follows them.
Existing actual C X509 callback mutations, SSH, ownership/MFA, race/browser and
all ten two-million-execution fuzz gates remain required.

The public preflight never sends native select/connect or credentials. Failure
diagnostics use separate Go overlay binaries and cannot turn a failed normal
candidate into acceptance. Normal runtime/native stderr remains discarded.

Adversarial maintainer self-review covered privilege and descriptor lifetime,
target/identity binding, parser limits, clipboard/stream ownership, cancellation
races, mount/runtime provenance and actual service lifecycle. Findings changed
raw descriptor-number closes to CLOEXEC, used read-only data mounts for memfds
without realpaths, fixed the guacd port option, bound root/directory modes and
rejected special permission bits, added complete Unicode conversion and framing
checks, and made fixed diagnostic state atomic. This is self-review, not an
independent candidate audit.
Further review added a clipboard snapshot under its native lock, immediate
lease/owner checks for buffered data and unconditional revocation on manager
done. Both local accept-all/refuse-all revocation mutations fail the intended
assertions; the unchanged RDP suite reruns after the overlays. The minimal
runtime also inventories the dynamically loaded OpenSSL provider required by
WinPR's NTLM path; strong TLS/identity checks remain mandatory.

Local Go 1.26.10 formatting/module/vet/shuffled tests/build/static/security/
vulnerability/workflow gates and both portable Edge desktop/workspace browser
tests passed. Linux tagged cross-vet/staticcheck passed. Final exact-head native,
installed service, browser, race/fuzz, signatures and all CodeQL checks must pass
before a merge commit. [PR 18](https://github.com/denyfirst/keybash/pull/18) records
the exact final candidate and CI evidence; diagnostic/mutant binaries are never
substituted for its normal candidate.

Real Windows VM/browser matrix, sizing, production installer/upgrade/restore,
independent exact-candidate audit and separately authorized release remain
distinct gates. CI cannot supply the user's VM or verify an unavailable host.
