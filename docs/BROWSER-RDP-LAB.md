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
adapter. Arity, canonical numeric syntax, coordinates, masks, stream/layer IDs,
stack depth and operation state are checked before the browser receives them.
Unsupported transforms, remote names, URLs, file/pipe/audio/video/clipboard,
argument changes and credential prompts are refused or discarded as specified.
The application uses the upstream renderer rather than implementing RDP.

- Fixed 1024x768 viewport; local display scaling/fullscreen does not negotiate
  another remote size or enable dynamic display/touch.
- At most 32 tracked layers/buffers, eight stack entries per layer and four
  million rounded canvas pixels (the renderer allocates multiples of 64).
- Eight active PNG streams, 256 KiB each and 1 MiB aggregate compressed data.
  Canonical base64, dimension bounds and complete PNG decoding precede forwarding.
  Decoded pixels are re-encoded as a static PNG (also at most 256 KiB); remote
  metadata, APNG control/frames and trailing/polyglot data are not forwarded.
  Image starts, ends and drawing operations retain their original order;
  normalized blob bodies are inserted immediately before their image end.
  Groups wait until all active images complete, with a 2 MiB staging ceiling.
- Lifetime work caps: 64 million decoded image pixels and 128 million rendering
  pixels charged conservatively for image/copy/transfer/fill/resize operations.
  These finite lab quotas are not production throughput/capacity promises or
  exact process memory bounds; transient canvas copies/decoders also use memory.
- Existing 8 MiB/8192 native output ceilings and bounded WSS queues/rate still
  apply. Byte-chunk credit bounds transport queues; upstream display-sync
  responses separately wait for image/render work. They are different credits.
- Native PNG blob acknowledgements permit validation staging to finish; bounded
  browser image acknowledgements are consumed exactly once and not forwarded
  twice. Sync replies must match outstanding native timestamps.
- Browser input is one complete <=1 KiB instruction: bounded mouse/buttons,
  supported X11/Unicode keysyms, tracked press/release, matched ack/sync or exact
  nop. Unknown/combined commands and auxiliary streams close the session.

Keyboard forwarding requires desktop focus; blur resets held keys. Mouse moves
are coalesced per animation frame. Ctrl+Alt+Del is sent by an explicit button;
the app does not inject that shortcut into the workstation OS. Logout, socket
closure and expiry cancel the stream/worker and remove the browser display.
Remote text is not reflected into application HTML. Browser storage and local
clipboard APIs are unused. RAM erasure is not guaranteed.

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
