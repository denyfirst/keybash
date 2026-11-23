# Keybash RDP proxy (ADR 0008, step 2)

17 November 2026. Design for the credential-injecting proxy that replaces
guacd and FreeRDP when a desktop runs in the browser (ADR 0008, D). Since
20 November (step 3e3 of `BROWSER-RDP-PAGE.md`) every desktop runs it, and
guacd and FreeRDP have left; the text below keeps the order it was built in.

## Where it runs

The boundary stays exactly as `RDP-WORKSPACE-INTEGRATION.md` describes it:

- the gateway dials Windows through the target guard;
- the root RDP manager hands the connected socket, two pipes and the two
  sealed trust files to the fixed worker;
- the worker runs under its own identity, in private network, PID and mount
  namespaces, with no capabilities, `no_new_privs`, seccomp and a read-only
  runtime.

The Go worker keeps every check it makes today, and keeps descriptor 3 (the
socket to Windows) to itself. Instead of guacd it starts
`/opt/keybash-rdp/bin/keybash-rdp-proxy`, which reaches Windows through the
same loopback bridge guacd uses (`127.0.0.1:3390`), and talks to the gateway
over the worker's pipes. The proxy is written in Rust on IronRDP's connector,
TLS and RDCleanPath crates, at the commit `scripts/build-ironrdp-web.sh` pins.

## What crosses the pipes

Frames of a type byte, a 32-bit length and the payload, both ways, each at
most 64 KiB:

- **Setup**, once, gateway to proxy, before anything else: format version,
  user name, domain, password, whether the clipboard is allowed, and the
  largest desktop the account may open (`identity.DesktopBounds`). The values
  are checked as today's plan checks them (`newNativePlan`).
- **Browser**, gateway to proxy: one WebSocket binary message from the
  browser, unchanged.
- **Desktop**, proxy to gateway: bytes for the browser, sent as one binary
  message.
- **Ended**, proxy to gateway: one fixed code: credentials refused (which for
  now also covers an account Windows refuses), unreachable, certificate
  changed, refused, remote ended. The gateway maps it to the end-reason words
  it already has, and shows nothing else.

The proxy reads the pinned certificate from `/run/keybash/approved.pem` and
the server name from `/run/keybash/name`, as FreeRDP does now.

## The handshake

1. The browser sends an RDCleanPath request. Only its X.224 connection
   request is used, and it must ask for TLS alone. The destination and token
   fields are ignored: the target and the access are the gateway's. A
   preconnection blob is refused.
2. The proxy sends Windows its own X.224 request (TLS, CredSSP, CredSSP with
   early user authorization), and Windows must select NLA. The request carries
   no routing cookie: nothing about the account (user name, domain, password)
   crosses the network before TLS. It then completes TLS 1.2 or 1.3 with its own verifier (`rdp-proxy/src/pin.rs`):
   - the leaf certificate must be byte for byte the pinned one, inside its
     validity dates, or the session ends as "certificate changed" before any
     credential is sent;
   - the handshake signature is still checked with that certificate's key, so
     the pinned certificate alone, which is public, does not pass;
   - no platform roots, no resumption, no key log.
   IronRDP's own callback verifier is not used: it asks the callback only after
   platform-root validation fails, so a publicly trusted certificate for the
   name would pass without the pin, and the sandbox has no root store anyway.
   The certificate's fixed rules (not a CA, server use, key strength, the name)
   were checked when it was approved (`internal/rdpcert`).
3. The proxy completes CredSSP with NTLM. Kerberos network requests are
   refused: the sandbox has no route to a KDC.
4. The proxy answers the RDCleanPath request with the X.224 confirmation
   (TLS) and the pinned certificate.
5. The browser's MCS Connect Initial is decoded, checked and re-encoded. It
   is never forwarded as it came.
   - The selected protocol is set to what Windows selected.
   - The desktop size and scale must be within the bounds: even, at least 200
     by 200, at most full HD times one of Windows' scales (`desktop_allowed`).
   - Only allowed static channels, each once: `drdynvc` always, and `cliprdr`
     when the clipboard is allowed. The page asks for nothing else, so any
     other channel (drives, printers, smart cards, sound, RemoteApp) ends the
     session as "refused". Dropping it instead would shift the channel numbers
     Windows answers with.
   - No monitor layout: one monitor, the desktop's size.
   - The redirection, message-channel and UDP blocks are removed.

The whole handshake, from the browser's first byte to the checked Connect
Initial, must finish within 30 seconds, so a stalled browser or server cannot
hold a worker.

## After the handshake

The proxy relays both ways and checks what it passes on
(`rdp-proxy/src/channels.rs`):

- Every TPKT and fast-path PDU is framed and bounded (at most 65,535 bytes, at
  least its own header) and checked whole before it passes.
- Windows' MCS Connect Response must number exactly the static channels the
  browser asked for. Only the I/O and user channels, `drdynvc` and, when the
  account allows the clipboard, `cliprdr` carry data; the browser may join no
  other.
- The browser's Client Info, its first message on the I/O channel, is written
  again before it reaches Windows:
  - it names the account the proxy signed in with, with no password and no
    redirection cookie in the password's place, so the page cannot sign in
    as anyone else through Keybash;
  - it carries no auto-reconnect cookie, so the page cannot reach a session
    the proxy did not sign in for;
  - a program to run instead of the desktop, a working folder or RemoteApp
    ends the session as "refused". Today's guacd path never asks for them.
- `drdynvc` chunks must come in order, uncompressed, and a message is at most
  16 MiB.
- Anything malformed, oversized or out of order ends the session as
  "refused".
- On `drdynvc`, Windows may ask for any dynamic channel, but the browser may
  open only these two:
  - `Microsoft::Windows::RDS::Graphics`;
  - `Microsoft::Windows::RDS::DisplayControl`, whose monitor layouts must be one
    primary monitor at the origin, within the desktop bounds, whole in one PDU.
  The browser's page registers nothing else, so it refuses the rest itself. If
  it opens another channel anyway, or data arrives on a channel that is not
  open, the session ends. Soft-sync, which needs the UDP transport, is refused.
- On `cliprdr`, only text, within the gateway's own limits
  (`rdp-proxy/src/clipboard.rs`). Every clipboard message is gathered whole,
  checked and written again in chunks; nothing passes as it came:
  - capabilities keep only long format names, so neither side offers files or
    locks;
  - a format list keeps only Unicode text (`CF_UNICODETEXT`);
  - a side may ask only for Unicode text, at most 64 requests waiting, and data
    passes only to a side that asked;
  - data passes only from a side whose latest list offered text, as valid text
    of at most 32 KiB in UTF-8, cut at its first NUL, and paced as the gateway
    paces it (a burst of 128 transfers, then one a second, each way). Text that
    fails any of these reaches the asker as a failure, and the session goes on.
    A response over 64 KiB is counted, never kept;
  - file contents, locks and anything else end the session; the browser's
    temporary directory, which is only for files, never reaches Windows;
  - the browser's clipboard speaks only after Windows' clipboard opens with
    its Monitor Ready (MS-RDPECLIP 1.3.2.1). Windows' clipboard program,
    rdpclip, can stop answering a session, even across new connections, and
    IronRDP still sends its capabilities, temporary directory and format list
    with each paste. Before Windows' clipboard opens, those three are checked
    and dropped, so the paste fails on the page and the desktop goes on;
    anything else from the browser ends the session. Nothing is recorded, so
    IronRDP says them again once Windows' clipboard opens.
    - Seen on 2026-11-23 against the test VM's Windows Server 2025: the proxy
      heard nothing from Windows on `cliprdr`, and every paste ended the
      desktop as "refused". Restarting rdpclip in the session opened the
      clipboard, and the paste went through.
    - Windows' capabilities still come once per desktop. If rdpclip starts
      over after the clipboard opened, its second capabilities end the
      desktop, and the next connection opens the clipboard again.
- Revocation, the idle limit and sign-out end the session as they do now.
  The gateway closes the pipes, and the manager ends the worker.

What the proxy cannot check is the video content: graphics-pipeline records
and H.264 reach the browser's WebAssembly and its sandboxed decoder (ADR 0008,
Decision).

## Order of pull requests

- **2a.** The proxy crate (`rdp-proxy/`, built by `scripts/build-rdp-proxy.sh`):
  - pipe framing, setup, the handshake with the pinned verifier, the checked
    Connect Initial, the deadline and the relay;
  - unit tests for each rule, with malformed and oversized input, and an
    end-to-end test that plays the browser with IronRDP's own connector;
  - CI runs the tests, clippy and rustfmt, builds twice and compares the
    bytes, and checks licences and advisories on its compiled crates.
  - On 17 November the end-to-end test passed against the test VM's Windows
    Server 2025 (NLA with HYBRID_EX, TLS 1.3). It runs against any NLA server
    named in `KEYBASH_PROXY_TEST`. Since 3e1, CI's proxy job runs it against
    Keybash's test peer (`rdp-testpeer/`, IronRDP's own server; a trailing
    `,peer` in the variable), and checks that the peer opened a desktop.
- **2b.** The worker starts the proxy instead of guacd for a desktop that
  asks for it:
  - the gateway asks the manager with a second fixed lease packet
    (`start-proxy/v1`), and the manager refuses it unless the approved runtime
    holds the proxy (`/opt/keybash-rdp/bin/keybash-rdp-proxy`, bound into the
    runtime inventory like every other file);
  - the manager passes the worker one fixed word, and the worker keeps every
    check it makes for guacd, then starts the proxy on the same bridge, with
    its own pipes and an empty environment;
  - `rdplab.ManagerWorker.OpenBrowserRDP` sends the setup frame and returns a
    stream of whole messages, with the proxy's end code as the pages' word.
    The clipboard is on since the page arrived (3d);
  - `build-stage.sh --with-rdp-proxy` built the proxy into the runtime (since
    3e3, `--with-rdp` builds a runtime of the proxy alone);
  - the native lab ran the proxy in the sandbox against the FreeRDP sample
    server with NLA (since 3e3, against the test peer).
  The gateway's relay to the browser comes with the page in step 3.
- **2c.** The `drdynvc` allowlist with display-control bounds, then the text
  clipboard filter.
  - The first part is done. Unit tests cover each rule. An end-to-end test plays
    a whole desktop with IronRDP's own session code: it passed against the test
    VM's Windows Server 2025, where display control opened, a 1280 by 720 layout
    passed, and 3840 by 2160 at 100% ended the session.
  - The clipboard filter is the second part. Unit tests check each rule against
    IronRDP's own clipboard encoder and decoder. Against the test VM's Windows
    Server 2025, a desktop with IronRDP's clipboard client got long names only
    and had its text offer accepted. A command on the desktop read the
    browser's text (Windows asked for it) and wrote it back with " back"
    added; Windows' format lists reached the browser holding only Unicode
    text, and the paste returned "Keybash clipboard: héllo 🙂 back".
  - The gateway still sends the setup with the clipboard off. Step 3 turns it
    on with the page, whose clipboard runs only on the person's own copy and
    paste.
- **2d.** Randomised tests of every parser the proxy runs on bytes it does not
  control (`rdp-proxy/src/fuzz.rs`): the PDU splitter, the channel checks on
  whole desktops, the clipboard with messages cut at random, the Connect
  Initial check, the setup and pipe frames, and the trust files.
  - Each is fed mutations of real messages, after a valid start so the deeper
    states are reached, and plain noise. The seeds are fixed, so a failure
    repeats.
  - The rule for each: no panic, which release builds raise on integer
    overflow too, and whatever passes stays within its bounds.
  - CI runs 3,000 rounds of each; `KEYBASH_FUZZ_ROUNDS` runs more. They are
    ordinary tests on stable Rust, with no new dependency.
- **2e.** The Client Info written again (above). Until then the proxy passed
  it as the browser wrote it. Against the test VM's Windows Server 2025, the
  desktop, display control and the clipboard round trip came up with it
  written again.

Step 3 brings the page (`BROWSER-RDP-PAGE.md`).
