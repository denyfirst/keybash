# 0008 — Which path video takes: guacd's output, or a browser RDP client behind a proxy

Date: 2026-11-16. Status: accepted on 17 November 2026. The maintainer chose
D after the prototype below (see Decision).

## Context

ADR 0007 brings H.264 to the browser in two halves. The first half, the RDP
graphics pipeline from Windows, is on for managed desktops since PR 76. With
it, the black areas after a resize and the half-drawn frames on scroll are
gone. On the test VM at 200% (2880x1442) a scroll carries 5.1 Mpx a second
against 1.4 on the classic path, but still at about 10 frames a second. Motion
is better but not smooth.

A whole-VM profile while scrolling (perf, 40 s, 7 processors):

- the VM was 68% idle, and nothing waited on a CPU quota;
- guacd used about 1.2 cores:
  - 40% of its time went to finding moved blocks (`guac_display_plan_find_copies` and the image hashes);
  - PNG compression (zlib, libpng) took about 7%;
  - FreeRDP's pipeline decoding barely registered;
- the gateway used about 0.9 cores, spread over decoding and writing images again, and garbage collection.

The limit is therefore the length of the chain each frame passes through, one
stage after another: Windows, FreeRDP, guacd's frame plan, PNG, the gateway,
the browser, the sync answer. guacd's frame plan alone is about 55 ms a frame
on one thread.

## Options

**B. guacd sends H.264 for moving regions.**
- What it is: Keybash patches guacd's output stage, as it already patches guacd for the repaint and the encoder.
  - Moving regions are encoded as H.264 in the sandboxed worker.
  - The browser decodes them with WebCodecs.
  - Still regions stay lossless PNG.
- Model: kept. The browser receives only video and pictures Keybash made.
- Speed: PNG and the gateway's per-picture work leave the moving path. guacd's frame plan stays, so the estimate is about 15-18 frames a second at 200%.
- Cost: the Keybash host encodes video for every desktop.

**D. A browser RDP client behind a credential-injecting proxy.**
- What it is:
  - The browser runs an RDP client, IronRDP compiled to WebAssembly (Apache-2.0).
  - It connects only to Keybash.
  - Keybash's RDP proxy completes TLS and NLA with Windows using the vault's credentials, then relays RDP between the two sides.
  - Devolutions Gateway ships this "proxy-based credential injection" since 2026.1.
  - The browser never holds the password or the Windows-side session keys.
  - Once the browser build has the graphics pipeline, Windows' own H.264 goes to the browser's hardware decoder with no re-encoding on the host.
- What exists today (IronRDP master, `fe9608b2ab`, 15 November 2026):
  - the graphics pipeline and H.264 decoding (AVC420 and AVC444) are in IronRDP's protocol crate and its native client;
  - its browser build does not use them: `crates/ironrdp-web/src/session.rs` sets `support_dyn_vc_gfx_protocol: false`, and the build has no WebCodecs bindings;
  - in the browser it draws the classic bitmap updates on a 2D canvas.
  - So the H.264 part of D is work for Keybash, or for IronRDP upstream: the pipeline in the browser build, and WebCodecs decoding.
- Speed: with that work, closest to Windows' own client, with most of the chain gone. Without it, the classic bitmap path minus guacd's chain.
- Cost: lowest host CPU per desktop.
- Model changes:
  - the browser now parses data the server sends (in memory-safe WebAssembly, inside the browser's sandbox) instead of only pictures Keybash checked;
  - the proxy keeps channel policy (clipboard, drives, printing), revocation and recording, but cannot check video content;
  - the page, the clipboard and the resize handling are rebuilt around a new client.

## Proposal

B and D both need a WebCodecs decoder in the browser. They differ in where
the H.264 comes from: Keybash's own encoder after guacd (B), or Windows itself
(D).

Build a time-boxed prototype of D on the test VM, not enabled for users:

1. IronRDP's web client as it is, behind a minimal credential-injecting proxy. This
   measures what removing guacd's chain alone gives, before any H.264 work.
2. Only if step 1 is at least as fast as today's graphics-pipeline path: the
   pipeline and WebCodecs in the browser build.

At each step, measure:

- frames a second and input latency at 100% and 200%;
- host and browser CPU, and memory.

Review what the browser then parses.

If step 1 is slower, B is the better path, and the prototype stops there. The maintainer then
chooses D, or B with those numbers, in a follow-up to this record. Until then
the PNG path with the graphics pipeline stays. B also remains the fallback if D's
security trade-off is not accepted.

## Step 1 results (16 November 2026)

Setup:

- The test VM and the Windows Server 2025 guest on the lab network. IronRDP's web client at `fe9608b2ab`, unchanged.
- A lab proxy, not part of this repository:
  - it completed TLS with Windows' pinned certificate and NLA with the stored credentials itself, in about 22 ms;
  - the browser asked for TLS only and never received the password;
  - Windows accepted the session after the proxy rewrote one field, the protocol named in the client's core data, from TLS to the one Windows had selected (HYBRID_EX).
- Workload: Settings maximized, the mouse wheel five notches down and five up, 60 ms apart, for about 25 seconds. Edge drove it, headless with the GPU on, on the PC that hosts both VMs. A first run with 15 notches each way reached the end of the list at 100%, and was dropped.
- Counters:
  - the page counted the animation frames in which the canvas was painted, and the pixels painted;
  - the proxy counted bytes;
  - CPU and memory came from the processes' own counters.

| | 100% (1440x721) | 200% (2880x1442) |
|---|---|---|
| Painted frames a second, median (range) | 36 (33-41) | 59 (47-83) |
| Pixels painted a second | about 29.5 Mpx | 84-123 Mpx |
| Windows to browser | about 2.0 MB/s | 3.0-4.6 MB/s |
| Browser CPU, all processes | about 0.5 core | about 1.4 cores |
| Proxy CPU, memory | about 1% of a core, 14 MB | about 1.5% of a core, 14 MB |
| Wheel to first paint, median of 12 single notches (range) | 54 ms (25-56) | 51 ms (43-62) |

Browser memory stayed between 0.6 and 0.95 GB across all of Edge's processes
at both scales, with no growth over a run.

Reading:

- Frame rate:
  - IronRDP paints regions as they arrive, so one Windows frame can span two animation frames.
  - In whole screens, the pixels painted come to about 25-30 screens a second at both scales.
  - The graphics-pipeline path ran at about 10 frames a second at 200% (see Context). That was counted on the gateway during a scroll by hand, so it is not the same counter.
- At 200% the browser is the limit. After the first seconds, every read at the proxy filled its 64 KiB buffer, so data was waiting for the browser. The painted rate fell from about 80 to about 55.
- Host cost almost leaves the Keybash host: 1-1.5% of one core and 14 MB, against about 2.1 cores and up to 700 MB for a 200% desktop on the guacd path.
- The price is bandwidth: classic bitmaps without H.264 take 2-4.6 MB/s while scrolling.
- The maintainer used both by hand on the same VM:
  - scrolling felt about the same;
  - IronRDP felt a little more alive;
  - closing windows looked better on Keybash, likely because the graphics pipeline delivers whole frames while the classic path draws region by region.

Not measured: Windows' CPU; the guacd path's bandwidth and input latency
under the same workload; Edge outside the headless driver, beyond the
maintainer's own use (a peak of 79 painted frames a second).

Against the proposal, step 1 is at least as fast as today's graphics-pipeline
path, at a small fraction of the host cost. Step 2, the pipeline and WebCodecs
in the browser build, is therefore the next measurement. It should cut the
bandwidth and the browser CPU, and give whole frames. The choice between B and
D stays with the maintainer after step 2.

## Step 2 results (17 November 2026)

What was built, in the lab only (not in this repository):

- IronRDP at `fe9608b2ab`, changed in about 150 lines of its graphics-pipeline crate and browser session, plus a new module of about 450 lines in the browser build:
  - the graphics-pipeline client now runs in the browser build, with its own CPU compositor switched off;
  - each frame's surface commands go to the page in one batch, in order;
  - bitmap codecs are decoded in WebAssembly, and H.264 is passed on undecoded.
- A page of about 430 lines of JavaScript:
  - it keeps each surface on a GPU canvas;
  - it decodes H.264 with WebCodecs: hardware preferred, low-latency mode, full-range BT.709 as MS-RDPEGFX requires;
  - it draws the changed areas once per frame;
  - when more than three frames wait, the session stops reading from Windows for up to 250 ms.
- The page offers H.264, where Windows chooses 4:4:4 or 4:2:0, or the lossless codecs only.

Windows Server 2025 sent no H.264 by default, although the client offered it.
The maintainer changed two settings on the test server:

- `AVC444ModePreferred` = 1, the policy "Prioritize H.264/AVC 444 graphics mode";
- `DWMFRAMEINTERVAL` = 15, which lifts Windows' cap of about 30 frames a second to about 60.

The test server has no GPU, so Windows encodes H.264 on its CPU.

Workload and counters are as in step 1. The page also counted the H.264
pictures decoded, and the time from each wheel event to the first frame data
reaching the page. All numbers below come from runs made one after another,
after the settings change.

| | Lossless, 100% | H.264, 100% | Lossless, 200% | H.264, 200% |
|---|---|---|---|---|
| Pictures Windows sent a second, median | not counted | 77 | not counted | 40 |
| Whole frames painted a second, median | 37 | 62 | 24 | 36 |
| Windows to browser | about 0.58 MB/s | about 0.33 MB/s | about 0.49 MB/s | about 0.53 MB/s |
| Browser CPU, all processes | about 1.9 cores | about 1.6 cores | about 1.8 cores | about 1.2 cores |
| Wheel to frame data in the page, median of 16 single notches | 55 ms | 62 ms | 102 ms | 119 ms |
| Wheel to first paint, median of 12 single notches (another run) | 49 ms | 61 ms | 95 ms | 131 ms |
| H.264 decode per picture, median | | 1.8 ms | | 1.6 ms |

- The headless display runs at 60 Hz, which caps the painted count.
- Browser memory was 0.8-1.1 GB at 200% in both modes.
- Decoding and painting add 2-7 ms. The rest of the latency comes before the data reaches the page.

Picture:

- The lossless codecs are pixel-exact.
- H.264, against the lossless picture of the same still screen:
  - PSNR 38.8 dB at 100% and 39.8 dB at 200%;
  - 0.1-0.2% of colour values off by more than 16;
  - flat greys 1-3 levels off, with a faint magenta cast;
  - at 200%, faint block patterns on flat areas, visible when zoomed.
- To tell encoder loss from a client error, the page read the decoder's own values at one flat point: Y 249, U 129, V 129.
  - MS-RDPEGFX's conversion of those gives exactly the colour painted, 251, 248, 251.
  - The true colour there is 251, 251, 251, so the loss comes from Windows' encoder.
- Windows sent every H.264 picture as the main view only: LC = 1 on every AVC444 record, so 4:2:0 colour and no second view.
  - The 4:4:4 combination of the two views is therefore not built. On this server it would never run.

Before the settings change and a restart of Windows, the lossless path on the
same page measured:

- 32 frames a second at both scales;
- 0.5 and 0.87 MB/s;
- 0.7 and 1.4 cores;
- 30 and 56 ms of latency.

After the restart, every number for both modes was slower, and Windows showed
pending updates. The table above therefore compares only runs made together.

Also seen: three connections at 200%, each made seconds after the previous one
ended, stalled in the connection sequence. Windows sent about 1 KB and then
nothing, and the page stayed black with no error. A product client needs a
connect timeout with a clear message.

Reading:

- With H.264, the browser paints every display frame at 100%: 62 against 37 for the lossless codecs. It does so at a little over half the bandwidth and with less browser CPU.
- At 200%, it paints 36 against 24.
- The Keybash host does none of this work. The proxy stays at about 1% of a core.
- Each mode has a cost:
  - H.264 costs picture accuracy, and some latency on a server that encodes on its CPU: 7 ms at 100% and 17 ms at 200% to the arrival time.
  - The lossless codecs cost frame rate.
- So D can give both, with Windows deciding per server: the lossless codecs by default, and H.264 where an administrator turns it on.
- A server with a GPU encoder should cut H.264's latency cost. This was not measured.
- Against today's graphics-pipeline path through guacd, about 10 frames a second at 200% on another counter (see Context):
  - 2.4 times the frame rate with the lossless codecs;
  - 3.6 times with H.264.

For the choice, beyond D's model changes listed above:

- the browser also hands server-chosen H.264 to its own video decoder. Browsers treat web video as untrusted and decode it in a sandboxed process, so this is the exposure of any web video;
- the Windows-side settings are the administrator's, and Keybash cannot change them from the page.

What D still needs before users:

- the IronRDP changes, upstream or carried by Keybash;
- a Keybash proxy in place of the lab proxy;
- resize, clipboard and the page rebuilt around the new client;
- a connect timeout;
- the 4:4:4 combination, for servers that send the second view.

The choice between B and D stays with the maintainer.

## Decision (17 November 2026)

The maintainer chose D. B is not built.

- The desktop runs in the browser:
  - IronRDP is compiled to WebAssembly;
  - the graphics pipeline is drawn on the GPU;
  - H.264 is decoded by WebCodecs.
- Keybash's RDP worker becomes a credential-injecting proxy.
  - It keeps today's boundary: the manager hands it the guarded TCP connection, the pinned certificate and the credential.
  - It completes TLS and NLA with Windows itself. The browser never receives the password or the Windows-side TLS keys.
  - It is written in Rust on IronRDP's connector and sspi, as the lab proxy was, and runs in the existing sandbox.
- The proxy relays RDP between the two sides and enforces policy itself:
  - only the channels Keybash allows are joined or opened: graphics, display control, input, and the clipboard when it is allowed;
  - drives, printers, smart cards, audio input, USB and every other channel are refused;
  - every message it forwards has a bounded length;
  - the session ends on revocation, the idle limit or sign-out, as today.
- The rule from ADR 0007 that the browser parses only pictures Keybash made is replaced:
  - the browser parses Windows' RDP and graphics data in IronRDP's memory-safe WebAssembly;
  - it decodes H.264 in its own sandboxed video decoder.
  - `SECURITY-INVARIANTS.md` changes in the first pull request that ships this.
- No change on Windows is required.
  - Windows' default is the lossless codecs. In step 2 that gave 32 whole frames a second at both scales, pixel-exact.
  - H.264 and 60 frames a second are each server administrator's choice (`AVC444ModePreferred`, `DWMFRAMEINTERVAL`).
  - Keybash shows which codec a desktop uses and explains the two settings. It does not change Windows itself, which would need administrator rights on the server and widen what stored credentials are used for.
  - Update, 22 November: the test server is back on Windows' defaults, and Keybash's numbers are the ones a default server gives.
    - Measured: an Explorer list scrolled at 30 notches a second.
    - Smooth (1092 × 680) painted 29 frames a second and Sharp (2184 × 1362) 21 to 27. Both run at Windows' 30-frame cadence, with no H.264 and text sharp while it moves.
    - With the two settings, H.264 is faster but moving text is softer. At the bitrate Windows chooses (about 4 to 16 KB a frame), trails follow moving text and icons and clear once the picture stops. The page drew every picture in order, 2 to 5 ms after it arrived, so the trails come from Windows' encoder.
- On scaled screens the user chooses the picture, and the choice is kept with the account:
  - "Smooth" asks Windows for the desktop in CSS pixels at 100% and lets the browser enlarge it on the GPU. The desktop is the same size on screen, with softer text and a quarter of the pixels at 200%. In step 2 that meant the 100% numbers at 200%: 62 instead of 36 frames a second with H.264, 37 instead of 24 lossless (both with `DWMFRAMEINTERVAL`), and about half the latency. On Windows' defaults it is 29 against 21 to 27 (see the update above).
  - "Sharp" asks for the screen's own pixels and scale, as since PR 76.
  - With no choice made, Smooth at 175% and 200%, where the saving is largest, and Sharp below.
- Keybash carries the IronRDP changes as a pinned commit plus its own patch, as it does for guacd and FreeRDP. Offering them upstream is the maintainer's choice.
- guacd and FreeRDP leave the runtime once D covers what they do today.
  - Update, 18 November: Keybash has no users yet; it is given to people only once everything is finished. So D replaces guacd and FreeRDP outright, with no per-server choice and no release where both run. They leave as soon as the IronRDP page passes the maintainer's test on the Windows VM.

Order of work. Each step is one or more pull requests with its own evidence.

0. Smooth and Sharp on today's desktop page. The choice carries over to D.
1. The toolchain:
   - a pinned Rust toolchain and wasm-bindgen;
   - IronRDP's pinned commit with Keybash's patch, built in CI and in the stage build;
   - the dependency, licence and freshness checks covering all of them.
2. The proxy worker:
   - TLS with the pinned certificate, NLA with the stored credential, and the security-protocol rewrite;
   - the channel policy, the bounds and revocation;
   - fuzzed parsers, and native CI tests against the FreeRDP sample server the native lab already uses.
   - Done 18 November (PRs 85, 86, 87, 89), with the browser's Client Info written again (2e).
3. The desktop page on IronRDP (`docs/BROWSER-RDP-PAGE.md`):
   - the GPU renderer;
   - the session bar: the clipboard with today's limits and review, Ctrl+Alt+Del, resize, fullscreen, Smooth and Sharp;
   - the end reasons, and a connect timeout with a clear message.
4. The switch, folded into step 3 (the update above):
   - the IronRDP page replaces today's desktop page directly;
   - after the maintainer's test on the Windows VM, guacd, FreeRDP and everything only they use leave.
   - Done 20 November in steps 3d to 3e3 of `BROWSER-RDP-PAGE.md`: the IronRDP page is the only desktop page, and guacd, FreeRDP and everything only they used have left the repository.
5. Then:
   - the 4:4:4 combination, for servers that send the second view;
   - the codec shown on the page;
   - a guide for H.264 and 60 frames a second on the Servers page.

## References

- ADR 0007 (H.264 to the browser), `BROWSER-RDP-LAB.md` (graphics pipeline).
- IronRDP: https://github.com/Devolutions/IronRDP (`crates/ironrdp-egfx`, `crates/ironrdp-client/src/h264.rs`, `crates/ironrdp-web/src/session.rs`).
- MS-RDPEGFX: 2.2.4.5 (AVC444 records and their LC field), 3.3.8.3.1 (colour conversion for H.264).
- WebCodecs `VideoDecoder`: https://www.w3.org/TR/webcodecs/
- Devolutions Gateway, proxy-based credential injection:
  https://docs.devolutions.net/gateway/knowledge-base/how-to-articles/configure-proxy-based-credential-injection
