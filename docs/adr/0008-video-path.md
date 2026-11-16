# 0008 — Which path video takes: guacd's output, or a browser RDP client behind a proxy

Date: 2026-11-16. Status: proposed. The maintainer chooses after the
prototype below.

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

## References

- ADR 0007 (H.264 to the browser), `BROWSER-RDP-LAB.md` (graphics pipeline).
- IronRDP: https://github.com/Devolutions/IronRDP (`crates/ironrdp-egfx`, `crates/ironrdp-client/src/h264.rs`, `crates/ironrdp-web/src/session.rs`).
- Devolutions Gateway, proxy-based credential injection:
  https://docs.devolutions.net/gateway/knowledge-base/how-to-articles/configure-proxy-based-credential-injection
