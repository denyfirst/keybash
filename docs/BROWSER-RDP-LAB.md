# Browser RDP laboratory

14 October 2026. Synthetic viewer laboratory; each change requires native/browser
CI and the documented adversarial self-review. No production account or public
listener, product login/vault, installer, deployment or release.

The loopback HTTPS boundary uses the existing TLS 1.3, exact peer/Host/Origin,
one-use owner grant, restricted cookie, active-session slot and revocation
checks. A separate fixed desktop asset profile serves only local files. Its
CSP allows validated PNG Blob images, self-only scripts and the reviewed inline
style allowance required by the renderer. External image/network URLs, iframe,
object, forms, arbitrary assets and remotely supplied application HTML are not
available. No target, credential or native parameter comes from the browser.

Apache guacamole-common-js 1.6.0 is bundled directly from the official release
archive, not an npm wrapper or hosted service. SHA-256:
`81f9fd5a7b4377fb0ee295d0d4fec92e9667f2aafaa3d0ed8937f535deabdee4`.
The release signature verified against the public Apache KEYS file using an
isolated temporary keyring: Michael Jumper signing fingerprint
`F467E54ACC52F1D2778826865B2977AEE5E4518F`. This is an upstream release check,
not an independently certified OpenPGP identity or product security audit.

The bundler concatenates 35 unmodified modules in deterministic order, adding
only separators and the module export. The manifest records every module and
bundled file hash; CI recreates the exact bytes from the pinned archive.
Apache LICENSE/NOTICE remain bundled. The package defines additional tunnel,
audio/video and stream helpers; the app constructs its own restricted tunnel
and enables none of those auxiliary protocols. No Maven/Java webapp, runtime
CDN, new npm package or Go module version is adopted. Upstream release/security
reports were checked on 14 October; version selection is not a CVE-free claim.

## Viewer boundary

Only the reviewed fixed-viewport drawing subset passes the private server
adapter. Arity, canonical numeric syntax, coordinates, masks, stream/layer IDs
and operation state are checked before the browser receives them.
Unsupported transforms, remote names, URLs, file/pipe/audio/video/clipboard,
argument changes and credential prompts are refused or discarded as specified.
The application uses the upstream renderer rather than implementing RDP.

- Fixed 1024x768 viewport; local display scaling/fullscreen does not negotiate
  another remote size or enable dynamic display/touch.
- The drawing taken is exactly what guacd 1.6 sends for RDP: size, img/blob/end,
  copy, rect, cfill, cursor, dispose, mouse and sync (2026-11-16). transfer,
  start, line, clip, close, push, pop, identity and reset come only from guacd's
  terminal surfaces and are refused rather than priced: transfer makes the
  browser run JavaScript for every pixel, and a path built from many shapes
  makes every fill rasterize them all. One path holds at most 64 rects before
  its fill (guacd sends one; display workers drawing on one small buffer at
  once may each add one).
- At most 1024 tracked layers/buffers and 16 Mi rounded canvas pixels times
  the desktop's area ratio (the renderer allocates multiples of 64). A visible
  layer the browser creates the first time it is named is counted at the
  session's largest display from then on, as the browser may create it before
  a pending resize; guacd draws RDP on the default layer and buffers only.
- A pointer image may be up to 384 by 384, FreeRDP's largest, which Windows
  sends on a scaled desktop or with a large pointer setting. The page makes it
  the browser's own CSS cursor (a `blob:` image, the only image source the
  page's policy allows, at the desktop's scale through `image-set`), so it
  moves with the hand; drawn inside the desktop it trailed the browser's arrow
  by a frame or more, and two pointers showed.
- At most 32 open PNG streams (guacd streams one per display worker at once).
  Each may hold what a PNG of its own size can be, read from its header:
  every row stored unfiltered at four bytes a pixel, plus 1/64 and 4 KiB for
  zlib and chunks. Open images hold at most 8 MiB together, and images waiting
  to be rebuilt another 8 MiB, both times the area ratio; past the second the
  reader waits for them. The fixed 256 KiB per image, 1 MiB together and eight
  streams this replaced ended a desktop showing a photograph at 100% (a
  512 by 512 tile is over 400 KiB) and on hosts with nine or more processors
  (`TestViewerImagesTakeWhatGuacdSends`). The header must give a size within
  the desktop, no 16-bit samples and no interlacing, which guacd never writes.
  Canonical base64, dimension bounds and complete PNG decoding precede forwarding.
  Decoded pixels are re-encoded as a static PNG (at most the same size); remote
  metadata, APNG control/frames and trailing/polyglot data are not forwarded.
  Keybash's own minimal encoder writes it: IHDR, one IDAT and IEND, 8-bit RGB
  or RGBA, every row Sub-filtered, a large image compressed in bands at once
  that join into one zlib stream. It is about three times faster than the
  standard encoder on a desktop-like 1080p frame (`BenchmarkNormalizeDesktop`,
  `BenchmarkFastNormalizeDesktop`). guacd sends every tile of at most 256
  colours as a palette PNG; those are written again by a second minimal
  encoder as IHDR, a PLTE rebuilt from the decoded colours, one IDAT and IEND,
  rows filtered None, one pooled compressor. The standard encoder had taken a
  fresh compressor of about a megabyte for each: a 64 by 64 palette tile went
  from 462 to 82 microseconds and from 904 to 70 KB decoded and written again
  (`BenchmarkNormalizePaletteTile`). Other layouts, a palette with
  transparency or an index outside the palette fall back to the standard
  encoder, which now reuses its buffers too.
  Image starts, ends and drawing operations retain their original order;
  normalized blob bodies are inserted immediately before their image end.
  Groups wait until all active images complete, with a 2 MiB staging ceiling.
  The checks and work budgets run on the reader; decoding and writing an image
  again run off it, while the images after it are read, at most one per
  processor across every desktop and 16 waiting per desktop, with 2 MiB held
  behind them besides the staging. The output waits for an image only at the
  frame's sync or when guacd has nothing more already read ahead (64 KiB), so
  a quiet desktop's image goes at once. An image that fails still ends the desktop,
  and nothing after it is forwarded. A 64-tile frame took 150 ms on the reader
  alone and takes 50 ms on seven processors (`BenchmarkViewerFrameOfTiles`).
- Continuous work budgets: 32 million decoded image pixels and 64 million
  rendering pixels per second (bursts of 64M/128M), charged conservatively for
  image/copy/transfer/fill/resize operations. A fill is charged for the bounds
  of the path it paints, cut at the layer's canvas (rounded up to 64), as the
  browser's canvas keeps that path: a fill, clip or close closes it without
  clearing it, the next shape begins a new one and reset clears it. It used to
  be charged for the whole layer, and scrolling a 200% Windows desktop then
  spent nine tenths of each second paused for pixels never drawn
  (`TestViewerFillIsChargedForThePathItPaints`). A fill, copy or image whose
  channel mask makes the canvas change pixels outside the drawing too
  (destination-in, source-in, source-out, destination-atop, copy), or whose
  mask the client does not map and so keeps the previous operation, costs the
  destination's whole canvas; guacd draws with source-over and
  destination-out, which cost what they draw
  (`TestViewerUnboundedMasksCostTheWholeCanvas`). Work beyond the rate pauses the
  reader and backpressures guacd instead of ending the session; revocation ends
  a pause. These are not throughput promises or exact process memory bounds;
  transient canvas copies/decoders also use memory.
- Native output is paced at 16 MiB and 16384 instructions per second, and the
  WSS relay keeps at most 32 frames unacknowledged. Byte-chunk credit bounds
  transport queues; upstream display-sync responses separately wait for
  image/render work. They are different credits. No lifetime total remains.
- Native PNG blob acknowledgements permit validation staging to finish; bounded
  browser image acknowledgements are consumed exactly once and not forwarded
  twice. A sync reply to one of the 128 newest unanswered native timestamps
  is forwarded once; a reply to an older or already answered one is dropped,
  and one to a timestamp never sent closes the session.
- guacd ends a user it hears nothing from for 15 seconds. On the managed path
  the gateway sends its own nop every 5 seconds while the browser has been
  heard from within 2 minutes, so a hidden page, whose timers run as rarely as
  once a minute, keeps its desktop; idle accounting still counts only input.
- Browser input is one complete <=1 KiB instruction: bounded mouse/buttons,
  supported X11/Unicode keysyms, tracked press/release, matched ack/sync or exact
  nop. Unknown/combined commands and auxiliary streams close the session.
  The ISO group keys 0xfe01-0xfe0f are supported: the browser's keyboard sends
  0xfe03 for AltGr and for every Mac Option key, and guacd reads it as AltGr;
  refusing it ended the desktop at the first AltGr. A pointer position is
  checked against the session's largest display and moved inside the current
  one, as the browser applies a new size only when its frame arrives: a pointer
  over a desktop that has just shrunk used to end it
  (`TestViewerInputSurvivesAShrinkAndTakesAltGr`).

Keyboard forwarding requires desktop focus; blur resets held keys. Mouse moves
are coalesced per animation frame. Ctrl+Alt+Del is sent by an explicit button;
the app does not inject that shortcut into the workstation OS. Logout, socket
closure and expiry cancel the stream/worker and remove the browser display.
An owned session's page is then told why in one fixed word with its own text:
Keybash's idle limit, the sign-in's 8-hour life, signing out, a changed server,
connection or access, or guacd's status code (credentials, account, taken
over, ended by the remote side, unreachable, not responding), never its
message; a desktop that sent what the viewer refuses says so too.
Remote text is not reflected into application HTML. Browser storage and local
clipboard APIs are unused. RAM erasure is not guaranteed.

## Scaled screens (2026-11-13)

A desktop on a screen scaled to 200% used to be drawn at half the screen's
pixels and stretched, so its text was softer than Windows' own client. The
page now picks the Windows scale nearest the screen's (100, 125, 150, 175 or
200%), asks for the desktop in device pixels at the matching DPI (96, 120,
144, 168, 192), and shows it at 1/scale: one remote pixel per screen pixel,
and Windows draws text and controls at the size a person expects. The start
size reads `2880x1800@192`; plain `1600x900` is 96. Windows keeps its DPI for
a session, so the scale is chosen when the desktop opens and later resizes
stay at it. guacd hears the same DPI in its handshake as in its
parameters: it turns each resize from the page into remote pixels by the
session's DPI over the handshake's, so any other value would scale every
resize (the first test on a 200% screen asked for 2880 by 1800 and guacd
made 5760 by 3600, which the viewer refused).

Windows draws at that scale only when the client says so: in the core data
when it connects and in every display-control layout after it. guacd 1.6 uses
its `dpi` argument for sizes alone and says neither, so the first 200% desktop
was drawn at 100% in twice the pixels and everything on the page looked half
size. The native build now tells Windows the session's scale in both
(`native/scale.c`, included by `native/prepare.py`): 100, 125, 150, 175 or
200%; a device scale of 100, which is what FreeRDP's own SDL client sends and
one of the three values without which Windows ignores the desktop scale; and
the physical size in millimetres that a monitor of that DPI reports. Any other
DPI is told as 100%.

Bounds and budgets grow with the scale and with nothing else
(`identity.DesktopBounds`, `areaScale`):

- the largest desktop is full HD times the scale (3840 by 2160 at 200%);
  another DPI, `@96` spelled out, or a size past the bound opens nothing;
- every per-desktop budget sized for full HD (live canvas pixels, decode and
  draw rates, staged and rebuilt image bytes, held output, guacd's byte rate)
  is multiplied by the area's ratio rounded up: 2 at 125%, 3 at 150%, 4 at
  175% and 200%;
- a 100% desktop keeps every bound and budget exactly as before.

A 200% desktop has about four times the pixels of a 100% one. It needs about
that much more memory per session on the gateway host, which the operator's
aggregate memory limit (`--memory-mib`, 1 GiB by default) still bounds, and
more network bandwidth for lossless pictures. Evidence:
`TestOwnedRemoteDesktopStartsAtThePageSize`,
`TestDesktopStartsAtThePageSize`, `TestScaledDesktopHoldsItsPixelsAndNoMore`,
`TestNativeRDPScaledDesktopTellsWindowsItsScale`, `native/scale_test.c` and
`web/desktop-workspace.test.mjs`.

### Smooth or Sharp (2026-11-17)

Four times the pixels cost speed as well. In ADR 0008's step 2 a 200% desktop
moved at 36 frames a second where a 100% one moved at 62. On a scaled screen
the person therefore chooses the picture in the Screen menu:

- Sharp: the screen's own pixels and scale, as above;
- Smooth: the desktop at 100% in CSS pixels, which the browser enlarges. It is
  the same size on screen, with softer text and a quarter of the pixels at 200%.

With no choice made, the page picks Smooth at 175% and 200%, where the saving
is largest, and Sharp below. A 100% screen has nothing to choose, so the menu
shows no choice.

Windows keeps a session's scale, so a new choice is saved and the desktop opens
again with it. It is kept with the account on the server, like the look, as
one of three fixed words (`auto`, `smooth`, `sharp`). It only picks a size the
bounds above already allow. Evidence:
`TestDesktopPictureIsKeptWithTheAccountAndArrivesWithTheDesktop` and
`web/desktop-workspace.test.mjs`.

## Graphics pipeline (2026-11-16)

A managed desktop now connects with the RDP graphics pipeline (MS-RDPEGFX,
`disable-gfx` false); the lab's fixed viewport keeps the classic path. On the
classic bitmap path Windows sends every step of a scroll in a
composited window (Settings, Explorer, Edge) as a new bitmap of the whole
area, with no frame boundaries, so guacd showed half-drawn frames: text
appeared twice while scrolling, and areas a resize left black stayed until
something repainted them. With the pipeline Windows sends whole frames with
their boundaries and moves scrolled areas itself. On the test VM at 200%
(2880x1442), scrolling the same windows:

| | classic path | graphics pipeline |
|---|---|---|
| frames a second, average | 11.6 | 9.5 |
| picture delivered a second | 1.4 Mpx | 5.1 Mpx |
| guacd and FreeRDP memory peak | 329 MiB | 694 MiB |

Fewer but complete frames carry 3.7 times the picture; the repeated text and
the black areas are gone. The cost is memory: FreeRDP keeps the pipeline's
surfaces and caches, so a new install's memory limit is half the machine's
memory (`INSTALL.md`).

The pipeline's codecs (Progressive, ClearCodec, planar) parse what the server
sends inside FreeRDP 3.33.1, whose release fixed the Progressive heap
corruption advisory, in the sandboxed worker; FreeRDP is built without H.264,
so Windows uses those lossless and progressive codecs. Every picture still
passes the viewer's checks and is re-encoded, and guacd still sends lossless
PNG only. Guacamole turns on the legacy RemoteFX surface-bits codec with the
pipeline, which FreeRDP 3's pipeline does not need; `native/prepare.py` leaves
it off, so a server without the pipeline, such as the synthetic peer in CI,
gets the NSCodec classic path CI keeps exercising (with RemoteFX on, that peer
ended the connection after its first picture). The pipeline itself is verified
against Windows Server 2025 on the test VM, not in CI. H.264 to the
browser (ADR 0007) is the next step.

## Evidence and remaining gates

Unit tests cover valid concurrent PNG groups preserving pixels and drawing order,
static normalization of ancillary/animation metadata and trailing content,
malformed/truncated images, SVG, numeric/geometry/memory/stack/work limits, unsafe/replayed
input, cancellation and late operations. Local Edge measures pixels, focused
keys/mouse, held-key release on blur, local requests, untouched clipboard/storage
and display removal. Its source is synthetic; it proves no native RDP by itself.

Required Linux CI additionally connects the isolated actual NLA worker to
Chromium, checks peer authentication separately from Guacamole ready/sync,
observes the actual 'a' key and mouse at the peer, verifies changed desktop pixels
and native worker/broker revocation. Source builds retain actual certificate
mutation gates. The native Go controller/launcher suite runs with the race
detector; the third-party native libraries are not thereby C race-sanitized.

The visible viewer status means the viewer transport is available, not product
authorization or standalone proof of NLA. A production worker needs an explicit
trusted authentication/lifecycle interface. Native/browser text clipboard,
remote resize, layouts, reconnect and real Windows interoperability remain the
next protocol gates. Product login/MFA, ownership/vault, minimal worker packaging,
aggregate isolation/quotas, independent review and installation remain separate.

References: [official release/checksums](https://guacamole.apache.org/releases/1.6.0/),
[security reports](https://guacamole.apache.org/security/),
[JS integration API](https://guacamole.apache.org/doc/gug/guacamole-common-js.html),
[protocol reference](https://guacamole.apache.org/doc/gug/protocol-reference.html).
