# Keybash RDP proxy (ADR 0008, step 2)

17 November 2026. Design for the credential-injecting proxy that replaces
guacd and FreeRDP when a desktop runs in the browser (ADR 0008, D). Nothing
here is wired to a page yet; step 3 does that.

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
   early user authorization), and Windows must select NLA. It then completes
   TLS 1.2 or 1.3 with its own verifier (`rdp-proxy/src/pin.rs`):
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
   - The desktop size and scale must be within the bounds
     (`identity.DesktopSize`, the same table in both languages).
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

The proxy relays both ways and checks what it passes on. Until 2c lands, the
relay is bounded only by the 64 KiB frames, TCP flow control and the session's
own limits.

- Every TPKT and fast-path PDU is framed and bounded. A malformed or oversized
  one ends the session as "refused".
- On `drdynvc`, Windows' create requests are answered by the proxy itself
  unless the channel is allowed:
  - `Microsoft::Windows::RDS::Graphics`;
  - `Microsoft::Windows::RDS::DisplayControl`, whose monitor layouts must be
    within the bounds.
  A refused channel never reaches the browser, and any data for it ends the
  session.
- On `cliprdr`, only text, within today's limits (32 KiB, the same pacing).
  File lists, file contents and other formats are dropped.
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
    named in `KEYBASH_PROXY_TEST`; 2b adds the FreeRDP sample server in CI.
- **2b.** The worker starts the proxy instead of guacd for a desktop that
  asks for it. The gateway relays browser frames to it, with today's byte and
  rate budgets. End reasons are wired. The native and service labs cover it.
- **2c.** The `drdynvc` allowlist with display-control bounds, then the text
  clipboard filter.

Step 3 then brings the page.
