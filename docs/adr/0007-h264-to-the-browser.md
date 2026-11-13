# 0007 — H.264 to the browser from Keybash's own encoder

Date: 2026-11-13. Status: proposed. It is built only after the measurements
below, each step its own pull request.

## Context

A desktop reaches the browser today as lossless PNG pictures. Windows sends
bitmaps over the classic path (`disable-gfx`). guacd and FreeRDP decode them
inside the sandboxed worker. guacd sends PNG pictures of the changed regions.
The gateway decodes every picture in memory-safe Go, checks it, and writes a
new PNG (`fastpng.go`), so the browser never decodes bytes that the remote
server or a compromised worker made.

On the test VM the gateway is no longer the bottleneck (PR 64, PR 70). The
remaining limits are:

- Windows' legacy bitmap path;
- PNG's size in motion: scrolling, video, and dragged windows;
- four times the pixels on a 200% screen since PR 76.

Windows' own client and Hyper-V's console decode H.264 on the GPU. Browsers
can do the same through WebCodecs.

Upstream guacamole-server does not send video to the browser. Its open pull
request apache/guacamole-server#733 only lets guacd receive H.264 from the
server, and decode it, before making pictures again.

The maintainer decided (13 November 2026):

- Keybash is AGPL-3.0, so OpenH264, FFmpeg and x264 are all allowed.
- Where the work stays on Keybash's side, choose the fastest and best tool.
  Add no second layer where the first already holds.
- Use the newest version of everything.

## Decision (proposed)

1. **Windows to guacd: the graphics pipeline without H.264.** guacd asks
   Windows for the RDP Graphics Pipeline with RemoteFX Progressive and the
   lossless codecs. FreeRDP keeps `WITH_OPENH264=OFF` and `WITH_FFMPEG=OFF`,
   so no third-party video decoder reads bytes from the server. FreeRDP 3.33.1
   carries the Progressive codec fixes (PR 72). This step comes first, measured
   on its own (roadmap step 5).
2. **guacd to the gateway: unchanged.** The gateway reads guacd's bounded
   drawing instructions and PNG pictures, decodes them in Go and checks them,
   as today.
3. **The gateway keeps the desktop's picture.** It applies guacd's checked
   drawing (pictures, copies, layers) to its own frame of the display. The
   viewer's existing bounds and budgets limit that frame. This is the one new
   piece of parsing-free code. It works only on pixels that are already
   decoded and checked.
4. **Keybash's own encoder writes H.264.** A separate helper,
   `keybash-video-encoder`, links **x264** and reads only raw frames that the
   gateway sends it. It runs under the worker's kind of sandbox: no network,
   no files, seccomp, fixed resource limits. Its output goes to the browser as
   a new viewer instruction.
   - The encoder never reads a compressed stream from the server or from guacd.
   - The browser's decoder reads only Keybash's own bitstream: constrained
     settings, one slice per frame, no B-frames, low latency.
5. **Sharp still text.** Video carries motion. Once a region stops changing,
   the gateway sends it again as a lossless PNG over the video, so text stays
   exact. Windows' own client does the same with AVC444 and refinement.
6. **Fallback.** Without WebCodecs H.264 (some browsers on some systems), or
   if the encoder helper is missing, the desktop stays on today's PNG path. The
   page says which path it uses.

## Why x264

The encoder reads only pixels that Keybash decoded and checked, never a
crafted stream. Its attack surface is the frame size and the settings, both
fixed by Keybash. Under the maintainer's rule, it should be the fastest and
best encoder available.

- **x264:** the reference H.264 software encoder.
  - It gives the best quality per bit, with presets fast enough for real-time
    full HD on one core (`ultrafast`/`superfast` with `zerolatency`).
  - Its licence is GPL-2.0-or-later, which can be combined into AGPL-3.0 code.
  - It is mature and slow-moving: the stable branch was last changed in June
    2025. It is built from a pinned commit.
- **OpenH264 2.7.0** (22 October 2026): built for video calls; small and
  BSD-licensed.
  - Its encoder has a screen-content mode, but only the Baseline profile, so it
    needs more bits for the same quality.
  - It is measured against x264 with the same frames, and kept if it wins.
- **FFmpeg 9.0.2:** has no H.264 encoder of its own. It would wrap x264 or
  OpenH264 and add a large codebase, so it is not used.

Hardware encoders (VA-API, NVENC) are a later option where a host has a GPU.
AV1 is not chosen: real-time software AV1 at these sizes needs far more CPU,
and Windows does not send it.

## Alternatives rejected

- **Pass Windows' own H.264 (AVC420/AVC444) to the browser:** fastest in
  theory. But the browser's decoder, often the GPU driver's, would read
  bitstreams the server chose. Checking such a stream thoroughly is decoding
  it.
- **Encode inside guacd:** guacd has the composed picture, but its output
  comes from a process a hostile server may control. The gateway could not
  check that video without decoding it.
- **A faster lossless format (the set-aside ADR 0006 draft):** helps neither
  motion nor bandwidth, now that the gateway is no longer the bottleneck.

## Measurements before building

On the test VM, against Windows Server 2025, at full HD and at 200%:

- frames a second in motion;
- gateway and guacd CPU;
- bandwidth;
- latency of a key press to the picture;
- memory per desktop.

Three cases are compared: today's path, the graphics pipeline (step 1), and a
VM-only encoder prototype, with x264 and OpenH264. A change is kept only if
the numbers improve.

## Limits and open gates

- **Patents.** H.264 is covered by a patent pool (Via LA). The project's
  licences do not settle patent licensing, and this is not legal advice.
  Before a release ships the encoder, the maintainer decides how: built by the
  operator, off by default, or licensed. Until then the PNG path is the
  default.
- **New security invariants.** The encoder helper's sandbox, its frame
  bounds, and the browser instruction get their own invariants and tests
  before the feature is enabled:
  - the helper never sees network, files or compressed input;
  - a broken or slow encoder falls back to PNG and never ends the session;
  - the browser accepts video only for a desktop's own display layer.
- **Freshness.** The weekly check (`STAYING-CURRENT.md`) gains the x264 commit
  and, if used, OpenH264, once they are pinned.
