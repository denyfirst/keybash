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
   - the size from the Screen menu, within the proxy's bounds (`desktop_allowed`).
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
- **3d.** The page: `/remote/rdp/<id>` serves `remote-desktop.html`, IronRDP
  in place of guacd, with the same session bar:
  - **The module** loads under the page's own policy, which alone adds
    `'wasm-unsafe-eval'`. The page's one WebSocket opens only to the desktop
    endpoint. IronRDP does not pass the socket's close on, so the page reads
    the close itself, and an ending is told only when its code and word
    agree. The page holds no user name or password.
  - **Input**:
    - each key goes as the scan code Windows' own driver reports;
    - a held modifier or lock key is sent once;
    - the pointer and the wheel go at most once a display frame, the wheel
      at most 255 units a message;
    - only the five mouse buttons IronRDP knows are sent;
    - Shift, Ctrl, Alt and the Windows key follow what each event says,
      so one held before the desktop had focus still counts;
    - a held key or button is let go when the desktop loses focus.
  - **The picture**: Windows' graphics pipeline. Where the browser decodes
    H.264, it is offered as in step 2, and Windows chooses 4:4:4 or 4:2:0,
    once its administrator turned H.264 on (ADR 0008). Windows Server 2025
    never used the older 4:2:0-only mode when that was offered alone. The
    page draws the main view, all that server sends. When the session ends,
    the picture is cleared. Keybash's patch hands the page records it draws
    on the GPU (`remote-desktop-gfx.mjs`), within fixed bounds:
    - the largest desktop (full HD at 200%);
    - 16 surfaces and twice that many pixels;
    - the 16 MiB small cache;
    - four video decoders, 4,096 items to a record.
    A record past these ends the desktop before anything is allocated for it.
  - **The rest**: the look Windows draws (ClearType, the theme; wallpaper,
    animations and live dragging off, as guacd had it), Smooth or Sharp, Fit
    or a fixed size through display control, and the 20-second start limit.
  - **The clipboard**: the gateway's setup turns it on for the proxy, which
    keeps it to bounded text. A paste goes to Windows' clipboard, and only
    once Windows has taken the format list does the remote's Ctrl+V follow.
  - **Tests**:
    - node tests for the input rules and the renderer's bounds;
    - `TestBrowserDesktopPage` in a real browser against a test proxy;
    - `TestOnlyTheDesktopPageMayCompileWebAssembly`;
    - the maintainer's test on the Windows VM.
  The native lab's owned-page test drove guacd's page, which the UI no
  longer reaches, so it leaves here; the native end-to-end test returns in 3e.
- **3e.** guacd, FreeRDP and what only they use leave, in steps, so nothing
  is left untested in between:
  - **3e1.** A test peer from the pinned IronRDP's own server
    (`rdp-testpeer/`, test-only, never shipped): TLS and NLA with one
    account, a grey desktop, and a line for each desktop, key press and
    click. CI's proxy job runs the proxy's end-to-end tests against it, so
    they no longer need Windows. The clipboard test, which drives Windows'
    own desktop, still needs Windows.
  - **3e2.** guacd's page, its viewer path and `vendor/guacamole.mjs` leave.
    The gateway's terminal socket is for terminals only: its proof is exactly
    the CSRF value and a lease, and a desktop's lease is used up there without
    starting anything. `identity.RDPWorker` is the RDP proxy alone, and its
    request carries no size: the proxy checks the page's own. The gateway's
    tests that went through guacd's path (sign-out during setup, idle, a
    server that changed, roles) now go through the desktop socket. The native
    lab's guacd desktop is reached only by its own tests until 3e3.
  - **3e3.** guacd and FreeRDP leave the runtime, the stage build and the
    native lab, whose NLA peer becomes the test peer, with their freshness
    watches, dependency notes and documents. The worker starts only the proxy,
    with no mode word; the manager has one start word; the runtime is the
    proxy, `setpriv` and their OS libraries, and its inventory requires the
    proxy. The native lab meets the sandboxed proxy with the test peer: the
    right and a wrong password, a wrong gateway, Windows' own certificate
    pinned exactly, eight certificate and protocol refusals, and the installed
    service; CI mutates the proxy's pin both ways there.
  - **3e4.** A native end-to-end test on the test peer: this page, the
    gateway, the manager and the sandboxed proxy, with input checked at the
    peer. It comes last, in a native lab that no longer builds FreeRDP.
    `TestNativeRDPDesktopFromThePageToThePeer` runs a fresh installation's
    pages in a real browser, the gateway as its own UID, the manager, the
    proxy in the worker's sandbox and the test peer: sign-up, the second
    factor, the saved password, the peer's grey desktop drawn on the page, a
    click, the pointer and a key seen by the peer, and signing out ending the
    desktop with its words and no picture left.
