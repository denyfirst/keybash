# Keybash desktop page on IronRDP (ADR 0008, step 3)

18 November 2026. Design for the desktop page that runs IronRDP in the
browser, through Keybash's RDP proxy (`BROWSER-RDP-PROXY.md`). It replaces
guacd and FreeRDP outright. Keybash has no users yet, so there is no
per-server choice and no release where both run (ADR 0008, update of 18
November).

## What stays the same for a person

The Servers page, the Open button, the desktop tab and its session bar look
and work as they do now:

- Screen: the size menu, and Smooth or Sharp, kept with the account;
- Copy: the desktop's text is shown in the copy panel, for the person to take;
- Paste: the person's own text, reviewed before it is sent;
- special keys (Ctrl+Alt+Del), fullscreen, disconnect and reconnect;
- the end reasons, in the same words.

What changes is underneath: Windows' RDP reaches the page, and IronRDP draws
the desktop on the GPU. H.264 is decoded by the browser's own decoder
(WebCodecs), as Keybash's IronRDP patch already provides.

## The module

- `scripts/build-ironrdp-web.sh` builds it from IronRDP's pinned commit with
  Keybash's patch (Rust 1.94.1, wasm-bindgen 0.2.129): `ironrdp_web.js` and
  `ironrdp_web_bg.wasm`. CI already builds it twice and compares the bytes,
  and checks licences and advisories on what it compiles.
- `scripts/vendor-ironrdp-web.py` vendors the two files into
  `web/vendor/ironrdp/`, with IronRDP's licences, the build's crate list
  (`CRATES.txt`) and a manifest:
  - IronRDP's commit;
  - the patch's SHA-256;
  - the toolchain;
  - each file's SHA-256.
  The gateway embeds them like every other asset, and serves only the two
  files the page loads, to a signed-in session, the WebAssembly as
  `application/wasm`. Git keeps their bytes exactly (`.gitattributes`).
- **The vendored bytes must equal the build.** CI rebuilds the module and
  fails unless the result is byte for byte what is vendored
  (`vendor-ironrdp-web.py --check`). A changed module can only arrive through
  the pinned source and the patch. A Go test checks the embedded files
  against the manifest.
- Before the module is vendored, the pin moves to IronRDP's newest commit,
  if its changes pass the same checks. The freshness check keeps watching
  IronRDP's releases.
- When the page loads the module (3d), and not before, the desktop page's
  Content Security Policy gains `'wasm-unsafe-eval'` in `script-src`, and
  nothing else. WebAssembly needs it to compile; it does not allow evaluating
  JavaScript. Other pages keep their policy. `connect-src` stays the gateway's
  own origin.

## Connecting

1. The person opens a server; the page gets a single-use lease, as now.
2. The page starts IronRDP's session with:
   - the address `wss://<the gateway's origin>/api/remote/desktop`;
   - the token `<csrf>.<lease>`. IronRDP carries it inside its first
     message, the RDCleanPath request, and never in the address;
   - CredSSP off, so it asks for TLS alone, as the proxy requires;
   - no user name and no password: the browser never holds the credential;
   - the size from the Screen menu, within `identity.DesktopSize`.
3. The gateway's new endpoint makes the checks the current socket makes: the
   origin, the signed-in session, the account's access to the server, and
   capacity. Then:
   - the first WebSocket message must be binary, at most 8 KiB, and a
     well-formed RDCleanPath request (strict DER);
   - its token's CSRF part is compared in constant time;
   - its lease is redeemed once, for this account and this server, as now;
   - `rdplab.ManagerWorker.OpenBrowserRDP` starts the proxy with the stored
     credential, the pinned certificate and the clipboard on;
   - the request goes on to the proxy with the token and destination
     removed: the proxy needs neither.
4. Then whole messages pass both ways, with today's limits: byte rates, the
   idle limit, revocation and sign-out. When the session ends, the gateway
   closes the socket with a code the page maps to its end-reason words. The
   proxy's own codes map as `OpenBrowserRDP` maps them now.

A desktop that has not drawn within 20 seconds of Open ends with a clear
message ("The desktop did not start"), and Reconnect tries again.

## The clipboard

The setup turns the clipboard on; the proxy keeps it to text
(`BROWSER-RDP-PROXY.md`). The page acts only on what the person does:

- what Windows copies is held in the page, and nothing writes the person's
  own clipboard by itself. Copy shows it in the copy panel, as now;
- Paste reads the person's own clipboard only when they press it, shows the
  text for review, and sends it only when they confirm.

## What leaves

Once the page passes the maintainer's test on the Windows VM, everything only
guacd and FreeRDP use leaves, each part in its own pull request:

- guacd and FreeRDP in the runtime, the stage build and the native lab;
- the PNG viewer path and `vendor/guacamole.mjs`;
- their freshness watches, dependency notes and lab documents;
- the security-invariant rows that only they meet. The rows the proxy meets
  stay or replace them.

## Order of pull requests

- **3a.** This design and the ADR's update.
- **3b.** The module: the pin moved to IronRDP master `abfc97b` (PR 92), then
  the vendored files and manifest, CI's byte check, and serving them. No page
  uses them yet, so the CSP waits for 3d.
- **3c.** The gateway's desktop endpoint, `/api/remote/desktop`
  (`internal/identity/remote_desktop.go`):
  - today's admission checks, and the page's proof read strictly from the
    RDCleanPath request (`internal/rdcleanpath`, whose encoding is byte for
    byte IronRDP's);
  - the request forwarded with an empty destination and token;
  - `terminalweb.RelayMessages`: whole binary messages, today's input budget,
    a 10-second write limit, and endings as WebSocket closes. Codes 4001 to
    4011 carry the reason's word, and 4020 a changed certificate;
  - only fast-path input (keys, mouse) counts as activity for the idle limit.
  Tested against a test proxy. The real proxy's own path through the worker
  sandbox is the native lab's (2b); the whole path meets Windows with the
  page in 3d.
- **3d.** The page: IronRDP in place of guacd on the desktop page, with the
  session bar, the clipboard, the end reasons, the timeout and the CSP's
  `'wasm-unsafe-eval'`. Browser tests
  for the page's rules, and the maintainer's test on the Windows VM.
- **3e.** guacd, FreeRDP and what only they use leave.
