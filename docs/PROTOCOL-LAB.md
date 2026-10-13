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

## Slice 3: browser terminal

Review and pin xterm.js and any transport dependency, including transitive
packages and licenses. Bundle assets locally. Treat remote output and escape
sequences as untrusted; isolate terminal state from application credentials.
Disable unsolicited OSC clipboard writes. A WebSocket route requires explicit
lab isolation and later authentication/origin/authorization/lifecycle gates.

Measure selection/copy, paste, multiline preview, Ctrl+C, resize and Unicode
in Chrome/Edge first. Never announce a full browser matrix before measuring it.
The [xterm.js security guide](https://xtermjs.org/docs/guides/security/)
informs these integration gates; using the renderer alone does not secure SSH.

## Slice 4: RDP transport and clipboard

Guacamole JS/guacd and FreeRDP remain candidates. Before adoption, record exact
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
