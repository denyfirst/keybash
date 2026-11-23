// The desktop page on IronRDP (ADR 0008, docs/BROWSER-RDP-PAGE.md). Windows'
// RDP runs here, through the gateway's desktop endpoint and Keybash's RDP
// proxy, which signs in with the stored credential: this page never holds a
// user name or a password. It acts only on what the person does.
import init, { setup, SessionBuilder, DesktopSize, Extension, InputTransaction, DeviceEvent, ClipboardData, RotationUnit } from './vendor/ironrdp/ironrdp_web.js';
import { createRenderer } from './remote-desktop-gfx.mjs';
import { scanCode, sendsRepeat, modifierChanges, ctrlAltDel, ctrlV, mouseButton, desktopPoint, wheelPixels, wheelStep, pointerPNG, closeReason } from './remote-desktop-input.mjs';
import { pictureScale, scaledSize, nearestScale, pointerCursor, pastePacer, windowsLines, pasteWait, pasteNotice } from './desktop-workspace.mjs';
import { inspectPaste } from './paste.mjs';
import { remoteProof, savePicture, remoteErrorMessage, identityChangedMessage, endingMessage, enterFullscreen, watchFullscreen, nameSession, sessionChrome } from './remote.mjs';

const $ = id => document.getElementById(id);
const chrome = sessionChrome();
const canvas = $('screen-canvas'), desktop = $('desktop');
const endpoint = `${location.origin.replace(/^https:/, 'wss:')}/api/remote/desktop`;
// Open to a drawn desktop at most this long, then the page says so.
const startLimit = 20000;
// The proxy reads the browser's RDP as a byte stream; no message is larger
// than this, well under the gateway's 64 KiB.
const messageLimit = 16384;
// What the desktop looks like: ClearType text and the window theme, as
// Windows' own client shows them; wallpaper, menu animations and live window
// dragging off, as guacd had them (MS-RDPBCGR 2.2.1.11.1.1.1).
const lookFlags = 0x01 | 0x02 | 0x04 | 0x80;

// IronRDP opens the page's one WebSocket itself and does not pass its close
// on, yet the gateway says in that close why the desktop ended. So the page's
// WebSocket opens only to the desktop endpoint, and its close is kept.
const sockets = new Set();
let ending = null, closeSeen = () => {};
const closeArrived = new Promise(resolve => { closeSeen = resolve; });
const BrowserSocket = globalThis.WebSocket;
class DesktopSocket extends BrowserSocket {
  constructor(url, protocols) {
    if (url !== endpoint || protocols !== undefined) throw new DOMException('Only the desktop endpoint', 'SecurityError');
    super(url);
    sockets.add(this);
    this.addEventListener('close', event => { sockets.delete(this); ending ??= { code: event.code, reason: event.reason }; closeSeen(); });
  }
}
Object.defineProperty(globalThis, 'WebSocket', { value: DesktopSocket, writable: false, configurable: false });

// Windows' graphics pipeline is drawn by the page (remote-desktop-gfx.mjs).
const renderer = createRenderer();
Object.defineProperty(globalThis, '__keybashGfx', {
  value: Object.freeze({ apply(target, bytes) { if (target !== canvas) throw new Error('not this desktop'); return renderer.apply(target, bytes); } }),
  writable: false, configurable: false
});

let session = null, live = false, stopped = false, retired = false, userEnded = false;
let scale = 1, screen = 'fit', lastAsked = '', sizeTimer = 0;
let picture = ['smooth', 'sharp'].includes(document.body.dataset.picture) ? document.body.dataset.picture : '';

function send(...events) {
  if (!live || !session) return;
  const transaction = new InputTransaction();
  for (const event of events) transaction.addEvent(event);
  try { session.applyInputs(transaction); } catch { void finish('The desktop stopped answering, so it was closed.'); }
}

// Keys. Windows gets each key's scan code; a held modifier or lock key once.
const down = new Set();
let lockSync = true;
function syncLocks(event) {
  if (!lockSync || !live) return;
  lockSync = false;
  try { session.synchronizeLockKeys(event.getModifierState('ScrollLock'), event.getModifierState('NumLock'), event.getModifierState('CapsLock'), event.getModifierState('KanaMode')); } catch {}
}
function releaseAll() {
  down.clear();
  if (live) try { session.releaseAllInputs(); } catch {}
}
// Windows' modifiers brought in line with the event's own (modifierChanges).
function matched(event) {
  const { press, release } = modifierChanges(event, down), events = [];
  for (const code of release) { down.delete(code); events.push(DeviceEvent.keyReleased(scanCode(code))); }
  for (const code of press) { down.add(code); events.push(DeviceEvent.keyPressed(scanCode(code))); }
  return events;
}
desktop.addEventListener('focus', () => { lockSync = true; });
desktop.addEventListener('blur', releaseAll);
let copyAsked = 0;
desktop.addEventListener('keydown', event => {
  if (!live || event.target !== desktop) return;
  syncLocks(event);
  const code = event.code, ctrl = event.ctrlKey && !event.altKey;
  // Ctrl+Shift+C copies what the remote copied, here.
  if (ctrl && event.shiftKey && code === 'KeyC') { event.preventDefault(); void copy(); return; }
  // Ctrl+V: the browser's paste event brings the text, which goes to the
  // remote with the remote's own Ctrl+V.
  if (ctrl && !event.shiftKey && code === 'KeyV') return;
  // Ctrl+C still goes to the remote; it also lets the next copy, within five
  // seconds, come to this computer.
  if (ctrl && code === 'KeyC') copyAsked = Date.now();
  event.preventDefault();
  const scan = scanCode(code), before = matched(event);
  if (scan === null || (event.repeat && !sendsRepeat(code))) { if (before.length) send(...before); return; }
  down.add(code);
  send(...before, DeviceEvent.keyPressed(scan));
});
desktop.addEventListener('keyup', event => {
  if (!live) return;
  const before = matched(event);
  if (!down.has(event.code)) { if (before.length) send(...before); return; }
  event.preventDefault();
  down.delete(event.code);
  send(...before, DeviceEvent.keyReleased(scanCode(event.code)));
});

// The pointer: moves at most once a display frame, the wheel likewise.
let pendingMove = null, moveFrame = 0, wheel = { x: 0, y: 0 }, wheelFrame = 0;
const where = event => desktopPoint(event.clientX, event.clientY, canvas.getBoundingClientRect(), canvas.width, canvas.height);
function flushMove() {
  moveFrame = 0;
  const p = pendingMove;
  pendingMove = null;
  if (p) send(DeviceEvent.mouseMove(p.x, p.y));
}
canvas.addEventListener('pointermove', event => {
  if (!live) return;
  pendingMove = where(event) ?? pendingMove;
  if (pendingMove && !moveFrame) moveFrame = requestAnimationFrame(flushMove);
});
function button(event, pressed) {
  const id = mouseButton(event.button);
  if (!live || id === null) return;
  event.preventDefault();
  cancelAnimationFrame(moveFrame); moveFrame = 0; pendingMove = null;
  const p = where(event), before = matched(event);
  const press = pressed ? DeviceEvent.mouseButtonPressed(id) : DeviceEvent.mouseButtonReleased(id);
  send(...before, ...(p ? [DeviceEvent.mouseMove(p.x, p.y)] : []), press);
}
canvas.addEventListener('pointerdown', event => {
  if (!live) return;
  desktop.focus({ preventScroll: true });
  syncLocks(event);
  try { canvas.setPointerCapture(event.pointerId); } catch {}
  button(event, true);
});
canvas.addEventListener('pointerup', event => button(event, false));
canvas.addEventListener('pointercancel', releaseAll);
canvas.addEventListener('contextmenu', event => event.preventDefault());
function flushWheel() {
  wheelFrame = 0;
  if (!live) { wheel = { x: 0, y: 0 }; return; }
  const v = wheelStep(wheel.y), h = wheelStep(wheel.x), events = [];
  if (v.step) events.push(DeviceEvent.wheelRotations(true, v.step, RotationUnit.Pixel));
  if (h.step) events.push(DeviceEvent.wheelRotations(false, h.step, RotationUnit.Pixel));
  wheel = { x: h.rest, y: v.rest };
  if (events.length) send(...events);
  if (wheel.x || wheel.y) wheelFrame = requestAnimationFrame(flushWheel);
}
canvas.addEventListener('wheel', event => {
  if (!live) return;
  event.preventDefault();
  const d = wheelPixels(event);
  wheel = { x: wheel.x + d.x, y: wheel.y + d.y };
  if (!wheelFrame) wheelFrame = requestAnimationFrame(flushWheel);
}, { passive: false });

// Windows' pointer is the browser's own pointer, a CSS cursor from a blob:
// URL (the only image source the page's policy allows), so it moves with the
// hand at once.
let pointer = null;
function showPointer() {
  if (!pointer) return;
  const shown = canvas.getBoundingClientRect().width / Math.max(1, canvas.width);
  canvas.style.cursor = `url("${pointer.url}") ${Math.round(pointer.x)} ${Math.round(pointer.y)}, default`;
  canvas.style.cursor = pointerCursor(pointer.url, pointer.x, pointer.y, shown);
}
function dropPointer(style) {
  if (pointer) URL.revokeObjectURL(pointer.url);
  pointer = null;
  canvas.style.cursor = style;
}
function cursor(kind, data, x, y) {
  if (stopped) return;
  if (kind === 'hidden') { dropPointer('none'); return; }
  const png = kind === 'url' ? pointerPNG(data) : null;
  if (!png || !Number.isFinite(x) || !Number.isFinite(y)) { dropPointer('default'); return; }
  const old = pointer;
  pointer = { url: URL.createObjectURL(new Blob([png], { type: 'image/png' })), x: Math.max(0, x), y: Math.max(0, y) };
  showPointer();
  if (old) URL.revokeObjectURL(old.url);
}

// The picture fits the space the desktop has, at most one remote pixel to a
// screen pixel on a scaled screen, and starts on a whole screen pixel.
function fit() {
  if (!canvas.width || !canvas.height) return;
  const factor = Math.min(1 / scale, desktop.clientWidth / canvas.width, desktop.clientHeight / canvas.height);
  canvas.style.width = `${canvas.width * factor}px`;
  canvas.style.height = `${canvas.height * factor}px`;
  canvas.style.translate = '';
  const box = canvas.getBoundingClientRect(), ratio = window.devicePixelRatio || 1;
  const snap = edge => (Math.round(edge * ratio) - edge * ratio) / ratio;
  canvas.style.translate = `${snap(box.left)}px ${snap(box.top)}px`;
  $('size').textContent = `${canvas.width} × ${canvas.height}`;
  showPointer();
}
// Fit asks Windows for exactly the space the desktop has; a fixed size is in
// the screen's own units, like Fit, so it looks the same size at any scale.
function requestSize() {
  if (!live) return;
  const [w, h] = scaledSize(...(screen === 'fit' ? [desktop.clientWidth, desktop.clientHeight] : screen.split('x').map(Number)), scale);
  if (!Number.isInteger(w) || !Number.isInteger(h) || `${w}x${h}` === lastAsked) return;
  lastAsked = `${w}x${h}`;
  try { session.resize(w, h, Math.round(scale * 100)); } catch {}
}
function askSize() { clearTimeout(sizeTimer); if (live) sizeTimer = setTimeout(requestSize, 350); }
new ResizeObserver(() => { fit(); askSize(); }).observe(desktop);
new MutationObserver(fit).observe(canvas, { attributes: true, attributeFilter: ['width', 'height'] });

// Copy: what Windows copies waits here, and reaches this computer's clipboard
// only on the person's own Copy, or their Ctrl+C on the desktop. No timer
// reads or writes the clipboard.
let remoteText = '', generation = 0;
const valid = text => typeof text === 'string' && text.isWellFormed() && !text.includes('\0') && inspectPaste(text).allowed;
const closeDialog = id => { if ($(id).open) $(id).close(); };
function remoteCopied(data) {
  try {
    if (!live) return;
    let text = null;
    for (const item of data.items()) {
      try { if (text === null && item.mimeType() === 'text/plain' && typeof item.value() === 'string') text = item.value(); } finally { item.free(); }
    }
    if (text === null) return;
    if (!valid(text)) { $('notice').textContent = 'Text copied on the remote is over 32 KiB, so it was not passed here.'; return; }
    remoteText = text;
    $('copy').disabled = !remoteText;
    if (remoteText) $('copy').dataset.new = ''; else delete $('copy').dataset.new;
    if (remoteText && Date.now() - copyAsked < 5000) { copyAsked = 0; void copy(true); }
  } finally {
    data.free();
  }
}
// asked: the person's own Ctrl+C on the desktop, not a click. If the browser
// does not let that write the clipboard, the dot on Copy says the text waits.
async function copy(asked = false) {
  if (!live || !remoteText) return;
  const epoch = generation, text = remoteText;
  try {
    await navigator.clipboard.writeText(text);
    if (live && epoch === generation) { delete $('copy').dataset.new; $('notice').textContent = asked ? 'Copied to this computer too.' : 'Copied from the remote.'; }
  } catch {
    if (asked || !live || epoch !== generation) return;
    delete $('copy').dataset.new;
    $('remote-text').value = text; $('copy-panel').showModal(); $('remote-text').focus(); $('remote-text').select();
    $('notice').textContent = 'No clipboard permission. Select the text and press Ctrl+C.';
  }
}

// Paste: the person's own text. One line goes at once; several lines, or
// hidden characters, are shown first. It reaches Windows' clipboard, then the
// remote's own Ctrl+V pastes it; no Enter is added. Pastes are paced.
const pastes = pastePacer();
let answered = null;
function formatListAnswered(ok) { answered?.(ok === true ? 'taken' : 'refused'); answered = null; }
async function deliver(text) {
  if (!live) return;
  text = windowsLines(text);
  if (!valid(text)) { $('notice').textContent = 'The text was not sent: too large or not valid Unicode.'; return; }
  if (!pastes()) { $('notice').textContent = 'Paste skipped: one at a time, please.'; return; }
  releaseAll();
  const epoch = generation;
  const accepted = new Promise(resolve => { answered = resolve; setTimeout(() => resolve('silent'), pasteWait); });
  const data = new ClipboardData();
  try {
    data.addText('text/plain', text);
    await session.onClipboardPaste(data);
  } catch {
    answered = null;
    if (live) $('notice').textContent = 'The text could not be pasted.';
    return;
  } finally {
    data.free();
  }
  // Windows has to take the text before its Ctrl+V asks for it.
  const answer = await accepted;
  if (answer !== 'taken') { if (live && epoch === generation) $('notice').textContent = pasteNotice(answer); return; }
  if (!live || epoch !== generation) return;
  send(...ctrlV.map(DeviceEvent.keyPressed), ...[...ctrlV].reverse().map(DeviceEvent.keyReleased));
  desktop.focus({ preventScroll: true });
}
function review(text) {
  if (!live) return;
  $('paste-text').value = text;
  $('paste-preview').textContent = text ? inspectPaste(text).preview : '';
  if (!$('paste-review').open) $('paste-review').showModal();
  (text ? $('paste-send') : $('paste-text')).focus();
}
function paste(text) {
  if (!live) return;
  if (!valid(text)) { $('notice').textContent = 'The text must be at most 32 KiB of valid Unicode.'; return; }
  if (inspectPaste(text).review) review(text); else void deliver(text);
}
$('paste').addEventListener('click', async () => {
  if (!live) return;
  const epoch = generation;
  try {
    const text = await navigator.clipboard.readText();
    if (live && epoch === generation) paste(text);
  } catch {
    if (live && epoch === generation) { review(''); $('notice').textContent = 'No clipboard permission. Paste the text into the box with Ctrl+V.'; }
  }
});
$('paste-text').addEventListener('input', () => {
  const check = inspectPaste($('paste-text').value);
  $('paste-preview').textContent = check.allowed ? check.preview : 'The text is over 32 KiB.';
});
$('paste-send').addEventListener('click', () => {
  const text = $('paste-text').value;
  if (!valid(text)) { $('notice').textContent = 'The text was not sent: too large or not valid Unicode.'; return; }
  // Cleared now: the dialog's close event comes later, as a task of its own.
  $('paste-text').value = ''; $('paste-preview').textContent = '';
  closeDialog('paste-review'); void deliver(text);
});
$('paste-review').addEventListener('close', () => { if (!$('paste-review').open) { $('paste-text').value = ''; $('paste-preview').textContent = ''; } });
$('copy-panel').addEventListener('close', () => { if (!$('copy-panel').open) $('remote-text').value = ''; });
$('copy').addEventListener('click', () => void copy());
// Ctrl+V on the desktop.
document.addEventListener('paste', event => {
  if (!live || document.activeElement !== desktop) return;
  event.preventDefault();
  paste(event.clipboardData?.getData('text/plain') ?? '');
});

// Screen size and picture.
const menu = $('screen-menu'), toggle = $('screen');
function closeMenu() { if (!menu.hidden) { menu.hidden = true; toggle.setAttribute('aria-expanded', 'false'); } }
function choose(size) {
  screen = size;
  for (const item of menu.querySelectorAll('[data-size]')) item.setAttribute('aria-checked', String(item.dataset.size === size));
  $('screen-choice').textContent = size === 'fit' ? 'Fit to window' : size.replace('x', ' × ');
  // A fixed size is its own label; Fit shows the size it has now.
  $('size').hidden = size !== 'fit';
  closeMenu(); askSize(); desktop.focus({ preventScroll: true });
}
// Only a scaled screen has a picture choice. Windows keeps a session's scale,
// so a new choice is saved with the account and the desktop opens again.
const ratio = () => window.devicePixelRatio || 1;
const shownPicture = () => pictureScale(picture, ratio()) === 1 ? 'smooth' : 'sharp';
function showPicture() {
  $('picture-group').hidden = nearestScale(ratio()) === 1;
  for (const item of menu.querySelectorAll('[data-picture]')) item.setAttribute('aria-checked', String(item.dataset.picture === shownPicture()));
}
async function choosePicture(next) {
  closeMenu();
  if (next === shownPicture()) { desktop.focus({ preventScroll: true }); return; }
  try { await savePicture(next); } catch { if (live) $('notice').textContent = 'The picture could not be changed. Try again.'; return; }
  picture = next; showPicture();
  location.reload();
}
toggle.addEventListener('click', () => {
  if (!live) return;
  if (!menu.hidden) { closeMenu(); return; }
  showPicture();
  menu.hidden = false; toggle.setAttribute('aria-expanded', 'true');
  (menu.querySelector('[data-size][aria-checked="true"]') ?? menu.querySelector('[data-size]')).focus();
});
menu.addEventListener('click', event => {
  if (!live) return;
  const item = event.target.closest('[data-size]'), look = event.target.closest('[data-picture]');
  if (item) choose(item.dataset.size);
  else if (look) void choosePicture(look.dataset.picture);
});
menu.addEventListener('keydown', event => {
  const items = [...menu.querySelectorAll('[data-size],[data-picture]')].filter(item => !item.closest('[hidden]')), at = items.indexOf(document.activeElement);
  if (event.key === 'Escape') { event.preventDefault(); closeMenu(); toggle.focus(); }
  else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); items[(at + (event.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length].focus(); }
});
document.addEventListener('pointerdown', event => { if (!menu.contains(event.target) && !toggle.contains(event.target)) closeMenu(); });

$('special').addEventListener('click', () => {
  if (!live) return;
  releaseAll();
  send(...ctrlAltDel.map(DeviceEvent.keyPressed), ...[...ctrlAltDel].reverse().map(DeviceEvent.keyReleased));
  desktop.focus({ preventScroll: true });
});
$('fullscreen').addEventListener('click', () => {
  if (document.fullscreenElement) void document.exitFullscreen().catch(() => {});
  else if (live) void enterFullscreen(document.querySelector('.session')).then(() => desktop.focus({ preventScroll: true })).catch(() => {});
});
watchFullscreen($('fullscreen'));
$('disconnect').addEventListener('click', () => {
  userEnded = true;
  try { session?.shutdown(); } catch {}
  // Windows answers a shutdown at once; if it does not, the page ends anyway.
  setTimeout(() => void finish(''), 3000);
});

// The end: why, in the gateway's own words when its close said so.
async function finish(fallback) {
  if (stopped) return;
  stopped = true; live = false; generation++;
  // The gateway's close can come a moment after IronRDP stops reading.
  if (sockets.size) await Promise.race([closeArrived, new Promise(resolve => setTimeout(resolve, 1000))]);
  for (const socket of sockets) socket.close();
  renderer.close();
  // Nothing of the remote screen stays on the page once the session is over.
  canvas.width = 0; canvas.height = 0;
  canvas.style.width = '0'; canvas.style.height = '0';
  const word = ending ? closeReason(ending.code, ending.reason) : null;
  const message = userEnded ? '' : word === 'identity-changed' ? identityChangedMessage : (word && endingMessage(word)) || fallback;
  if (message) $('notice').textContent = message;
  down.clear(); cancelAnimationFrame(moveFrame); cancelAnimationFrame(wheelFrame); clearTimeout(sizeTimer);
  dropPointer('default');
  closeMenu(); closeDialog('paste-review'); closeDialog('copy-panel');
  remoteText = ''; delete $('copy').dataset.new;
  for (const id of ['paste-text', 'remote-text']) $(id).value = '';
  for (const id of ['screen', 'copy', 'paste', 'special', 'fullscreen', 'disconnect']) $(id).disabled = true;
  if (document.fullscreenElement) void document.exitFullscreen().catch(() => {});
  $('status').textContent = 'Session ended'; $('status').classList.remove('connected');
  if (!$('notice').textContent) $('notice').textContent = 'Session ended.';
  chrome.end();
}

// H.264 through the browser's own decoder when it has one, offered as in ADR
// 0008's step 2: Windows chooses 4:4:4 or 4:2:0 for the whole screen, where
// its administrator turned H.264 on, and its lossless codecs otherwise.
// Offered alone, the older 4:2:0 mode was never used by Windows Server 2025.
async function video() {
  try {
    if (typeof VideoDecoder !== 'function') return 'off';
    return (await VideoDecoder.isConfigSupported({ codec: 'avc1.640028', optimizeForLatency: true })).supported ? 'avc444' : 'off';
  } catch {
    return 'off';
  }
}

async function begin() {
  const timer = setTimeout(() => void finish('The desktop did not start within 20 seconds. Connect again to try once more.'), startLimit);
  let proof;
  try {
    proof = await remoteProof();
  } catch (error) {
    clearTimeout(timer);
    void finish(remoteErrorMessage(error));
    return;
  }
  try {
    await init();
    setup('warn');
    scale = pictureScale(picture, ratio());
    const [width, height] = scaledSize(desktop.clientWidth, desktop.clientHeight, scale);
    lastAsked = `${width}x${height}`;
    const builder = new SessionBuilder();
    builder.proxyAddress(endpoint);
    // The page's proof travels inside IronRDP's first message, never in the
    // address. The proxy needs no destination, and the page has no account.
    builder.authToken(`${proof.csrf}.${proof.lease}`);
    builder.destination('');
    builder.username('');
    builder.password('');
    builder.renderCanvas(canvas);
    builder.setCursorStyleCallbackContext(null);
    builder.setCursorStyleCallback(cursor);
    builder.remoteClipboardChangedCallback(remoteCopied);
    builder.desktopSize(new DesktopSize(width, height));
    for (const [name, value] of [
      // TLS alone: the proxy makes the sign-in with Windows itself.
      ['enable_credssp', false], ['display_control', true], ['desktop_scale_factor', Math.round(scale * 100)],
      ['color_depth', 32], ['gfx_video', await video()], ['performance_flags', lookFlags],
      ['outbound_message_size_limit', messageLimit], ['format_list_response_callback', formatListAnswered]
    ]) builder.extension(new Extension(name, value));
    if (stopped) return;
    session = await builder.connect();
  } catch {
    clearTimeout(timer);
    void finish('The desktop could not be opened. Connect again to try once more.');
    return;
  }
  clearTimeout(timer);
  if (stopped) { try { session.shutdown(); } catch {} return; }
  live = true;
  $('status').textContent = 'Connected'; $('status').classList.add('connected');
  for (const id of ['screen', 'paste', 'special', 'fullscreen', 'disconnect']) $(id).disabled = false;
  fit(); desktop.focus({ preventScroll: true });
  askSize();
  session.run().then(
    () => void finish(endingMessage('remote-ended')),
    () => void finish('The connection to the desktop was lost.')
  );
}

window.addEventListener('pagehide', () => {
  retired = true; userEnded = true;
  try { session?.shutdown(); } catch {}
  for (const socket of sockets) socket.close();
  void finish('');
});
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
void nameSession('Keybash');
if (!retired) void begin();
