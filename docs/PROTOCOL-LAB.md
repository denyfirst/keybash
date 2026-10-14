# Keybash protocol lab

The protocol stage starts with secure destination selection. It is not yet a
browser application or remote-access deployment. Use synthetic keys/accounts
only. No production credential custody or release is authorized by this lab.

## Slice 1: destination selection (implemented)

`targetguard.NewNamedTarget` takes a trusted hostname, port, independently
approved IP pins, and installation policy. One logical lookup validates the
whole result before TCP and dials the selected literal address. Private IPv4
and ULA targets remain usable. Rebinding to another registered server, mixed
safe/unsafe answers, mapped metadata addresses and malformed names are denied.

There is no listener, secret file, local shell or browser route. Tests use
synthetic in-memory transports. This slice adds no runtime dependency.
See ADR 0002 for availability tradeoffs and deployment limits.

## Slice 2: SSH identity and remote PTY (library lab implemented)

Adopted `golang.org/x/crypto v0.58.0`; exact graph, licenses, vulnerability
scope, limits and update owner are recorded in `DEPENDENCIES.md`. The public
`sshtransport.Connect` receives a guarded `NamedTarget` and trusted per-target
configuration, then passes its connection to `ssh.NewClientConn` without
re-resolution. The approved host key is copied and checked before key
authentication. The initial lab accepts Ed25519 host/user keys only; no automatic
trust, password, agent, or keyboard-interactive fallback.

A synthetic SSH echo server uses fresh in-memory keys and an ephemeral loopback
test listener. It shows real SSH authentication, PTY/shell request negotiation,
resize, exact Unicode/control-byte streams, extended output, setup timeout and
active cancellation. Bad host keys stop before user authentication; a server
accepting `none` cannot open a PTY. Input is capped at 32 KiB per write and
dimensions at 500 columns/200 rows. Both stdout and stderr must be consumed by
the owner; channel windows provide backpressure. No forwarding API is exposed.

The fixture does not execute Bash, allocate an OS PTY or prove vim/tmux behavior.
Production `NamedTarget` dialing and synthetic SSH transport are tested at their
separate boundaries; the fixture's private test seam does not relax the guard's
loopback ban. There is no browser entry point, vault, credential import or
application user authorization. No user's real SSH keys/agent or server inventory.

Primary API reference: [Go SSH package](https://pkg.go.dev/golang.org/x/crypto/ssh).
Exact dependency versions and test evidence belong in the adoption PR.

## Slice 3: browser terminal (lab implemented)

Local xterm `6.0.0`, bounded Coder WebSocket transport and test-only PTY tooling
are reviewed in `DEPENDENCIES.md`. Runtime page requests use local bundled
assets. Remote output stays in the terminal renderer; title/link hooks are not
reflected into application HTML. OSC 52 and OSC 8 are explicitly consumed.

The handler requires TLS 1.3, numeric loopback origin/peer and exact Host/Origin.
A cryptographically random five-minute one-use bootstrap grants a fifteen-minute
Secure/HttpOnly/SameSite=Strict owner cookie. Only one socket is active; logout
and absolute expiry cancel the stream. No target/credential choice is accepted
from the browser. This is a lab capability boundary, not product login/MFA.

Output is sequenced, limited to 8 KiB chunks and paced by xterm render callbacks.
Input is limited to 32 KiB; control JSON to 1 KiB, with unique known fields.
Multiline, control and bidi/invisible text needs a visible paste review. Cancel
transmits nothing; approve forwards through xterm's paste semantics, without
appending Enter. Bracketed paste is not a universal guarantee against execution.
Clipboard requires a user action and has a fallback panel; buffers are cleared
on close. Logout disposes the renderer and drops late output.

Edge verification uses synthetic SSH echo and a mocked clipboard to protect the
workstation clipboard. Linux CI uses Chromium, native headless Clipboard API,
and a real Bash OS PTY through the synthetic SSH server: Unicode, approved paste,
no added Enter, bracketed multiline paste, Ctrl+C and kernel resize. The fixed
Bash process exists only in test files, with fresh keys, a temporary directory,
minimal environment and process-group cleanup. No production local shell path.

The test seam does not weaken the production target guard's loopback ban. Browser
TLS certificate acceptance is confined to the isolated synthetic test context;
it is not production TLS verification. No permanent preview service is left
running. vim/nano/tmux/htop, real network hosts, performance, Safari/Firefox,
native Windows/macOS clipboard and a complete keyboard/layout matrix remain
unmeasured. No full browser matrix or offline egress-capture claim is made.
The [xterm.js security guide](https://xtermjs.org/docs/guides/security/)
informs these integration gates; using the renderer alone does not secure SSH.

## Slice 4a: credential-free RDP boundaries (lab implemented)

`rdplab.Probe` performs fixed-size initial RDP negotiation and an actual TLS
handshake with Go's standard library, an imported approved leaf, standard TLS
name/certificate verification and an additional exact DER SHA-256 pin. Only
HYBRID, TLS >=1.2 and the checked pinned leaf are accepted. It accepts no
credential and closes every outcome. Fresh-key loopback fixtures cover valid
Ed25519/RSA/ECDSA, old TLS, changed/expired/future/purpose certs, weak keys,
malformed/downgrade responses, cancellation and timeouts. This proves neither
account authentication nor CredSSP/NLA interoperability; the fixture only speaks
negotiation and TLS. Probe success cannot authorize a different connection.

A private bounded Guacamole text prototype preserves split Unicode, controls
and line endings both ways. It admits only text/plain with 32 KiB total decoded
text, isolates session buffers, refuses malformed/replayed/wrong-stream data
and clears on close. No desktop, browser or OS clipboard is connected.

Required Linux CI proves an empty unnamed network namespace, UID/GID/capability
drop and failed network attempts, with a no-namespace sabotage check. The child
still sees the host filesystem; no guacd or authorized egress route exists.
This is not a production sandbox. See [ADR 0003](adr/0003-rdp-precredential-boundaries.md).

## Slice 4b: native RDP (synthetic lab implemented)

The private native adapter, one-use guarded stream broker, actual TLS identity
hook and test-only Linux worker/peer launcher are implemented.
`NATIVE-RDP-LAB.md` records pinned sources and boundaries. Required native CI
proves synthetic NLA login, bounded decoded desktop images, actual certificate
refusal before CredSSP, sandbox/broker cancellation and callback sabotage in
both directions. Native clipboard/dynamic display remain disabled. There is no browser RDP tunnel or desktop
clipboard evidence yet; those remain the next protocol-lab gate.

Guacamole JS and production guacd/FreeRDP remain candidates. Before adoption, record exact
versions, licenses, transitive/native build inventory, security reports, resource
limits and update policy. guacd stays on an isolated unpublished worker network.
It must receive a validated literal destination and have independently enforced
egress; the Go guard does not protect guacd automatically.

Require NLA and TLS identity verification. Demonstrate the exact pinned version's
hostname/CA or explicit approved fingerprint behavior while dialing a literal IP.
Do not use blanket certificate-ignore or automatic first-use trust to solve
that integration. Changed/untrusted certificates must fail before a session.
Only then measure Unicode text clipboard both ways, per-session buffers,
permission refusal, keyboard layouts and reconnect behavior against a synthetic
RDP fixture. File/image clipboard and device redirection remain deferred.

Sources checked on 2026-10-13:
[Guacamole RDP options](https://guacamole.apache.org/doc/gug/configuring-guacamole.html),
[security reports](https://guacamole.apache.org/security/), and
[guacd isolation](https://guacamole.apache.org/doc/gug/guacamole-docker.html).
These are investigation gates, not claims that RDP or clipboard already works.
