// The person's keys and pointer as Windows hears them over RDP, for the
// desktop page on IronRDP (ADR 0008, docs/BROWSER-RDP-PAGE.md). Pure
// functions, so node tests cover every rule here.

// KeyboardEvent.code to the scan code Windows' keyboard driver reports: set 1,
// with 0xE0 in the high byte for an extended key, as Windows' own client sends
// it. Physical keys, so the remote's own layout gives the character. A key
// missing here is never sent; nothing is guessed from the character.
const codes = (() => {
  const map = {};
  const run = (names, first) => names.forEach((name, i) => { if (name) map[name] = first + i; });
  run(['Escape', 'Digit1', 'Digit2', 'Digit3', 'Digit4', 'Digit5', 'Digit6', 'Digit7', 'Digit8', 'Digit9', 'Digit0', 'Minus', 'Equal', 'Backspace', 'Tab'], 0x01);
  run(['KeyQ', 'KeyW', 'KeyE', 'KeyR', 'KeyT', 'KeyY', 'KeyU', 'KeyI', 'KeyO', 'KeyP', 'BracketLeft', 'BracketRight', 'Enter', 'ControlLeft'], 0x10);
  run(['KeyA', 'KeyS', 'KeyD', 'KeyF', 'KeyG', 'KeyH', 'KeyJ', 'KeyK', 'KeyL', 'Semicolon', 'Quote', 'Backquote', 'ShiftLeft', 'Backslash'], 0x1e);
  run(['KeyZ', 'KeyX', 'KeyC', 'KeyV', 'KeyB', 'KeyN', 'KeyM', 'Comma', 'Period', 'Slash', 'ShiftRight', 'NumpadMultiply', 'AltLeft', 'Space', 'CapsLock'], 0x2c);
  run(['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10'], 0x3b);
  run(['ScrollLock', 'Numpad7', 'Numpad8', 'Numpad9', 'NumpadSubtract', 'Numpad4', 'Numpad5', 'Numpad6', 'NumpadAdd', 'Numpad1', 'Numpad2', 'Numpad3', 'Numpad0', 'NumpadDecimal'], 0x46);
  run(['IntlBackslash', 'F11', 'F12', 'NumpadEqual'], 0x56);
  run(['F13', 'F14', 'F15', 'F16', 'F17', 'F18', 'F19', 'F20', 'F21', 'F22', 'F23'], 0x64);
  Object.assign(map, {
    KanaMode: 0x70, Lang2: 0x71, Lang1: 0x72, IntlRo: 0x73, F24: 0x76, Lang4: 0x77, Lang3: 0x78,
    Convert: 0x79, NonConvert: 0x7b, IntlYen: 0x7d, NumpadComma: 0x7e,
    // Extended keys.
    MediaTrackPrevious: 0xe010, MediaTrackNext: 0xe019, NumpadEnter: 0xe01c, ControlRight: 0xe01d,
    AudioVolumeMute: 0xe020, VolumeMute: 0xe020, LaunchApp2: 0xe021, MediaPlayPause: 0xe022, MediaStop: 0xe024,
    AudioVolumeDown: 0xe02e, VolumeDown: 0xe02e, AudioVolumeUp: 0xe030, VolumeUp: 0xe030, BrowserHome: 0xe032,
    NumpadDivide: 0xe035, PrintScreen: 0xe037, AltRight: 0xe038,
    // NumLock is extended in what Windows reports; Pause has no single scan
    // code (E1 1D 45), so it goes as Ctrl+Break's, as IronRDP's own client does.
    NumLock: 0xe045, Pause: 0xe046,
    Home: 0xe047, ArrowUp: 0xe048, PageUp: 0xe049, ArrowLeft: 0xe04b, ArrowRight: 0xe04d, End: 0xe04f,
    ArrowDown: 0xe050, PageDown: 0xe051, Insert: 0xe052, Delete: 0xe053,
    MetaLeft: 0xe05b, OSLeft: 0xe05b, MetaRight: 0xe05c, OSRight: 0xe05c, ContextMenu: 0xe05d,
    Power: 0xe05e, Sleep: 0xe05f, WakeUp: 0xe063,
    BrowserSearch: 0xe065, BrowserFavorites: 0xe066, BrowserRefresh: 0xe067, BrowserStop: 0xe068,
    BrowserForward: 0xe069, BrowserBack: 0xe06a, LaunchApp1: 0xe06b, LaunchMail: 0xe06c, MediaSelect: 0xe06d
  });
  return Object.freeze(map);
})();

export function scanCode(code) {
  return typeof code === 'string' && Object.hasOwn(codes, code) ? codes[code] : null;
}

// Keys whose state the browser keeps: a held one repeats, but Windows needs
// only the first press. Lock keys are also told to Windows as their state.
const held = new Set(['ShiftLeft', 'ShiftRight', 'ControlLeft', 'ControlRight', 'AltLeft', 'AltRight', 'MetaLeft', 'MetaRight', 'OSLeft', 'OSRight', 'CapsLock', 'NumLock', 'ScrollLock', 'KanaMode']);
export function sendsRepeat(code) {
  return !held.has(code);
}

// Ctrl+Alt+Del and Ctrl+V, as Windows' own client sends them.
export const ctrlAltDel = [0x1d, 0x38, 0xe053];
export const ctrlV = [0x1d, 0x2f];

// The mouse buttons IronRDP knows, by the browser's number: left, middle,
// right, back, forward. Any other is not sent: IronRDP would take it as left.
export function mouseButton(button) {
  return Number.isInteger(button) && button >= 0 && button <= 4 ? button : null;
}

// Where the pointer is on the desktop, in its own pixels: the canvas is shown
// at a CSS size of its own, and the edges are clamped.
export function desktopPoint(clientX, clientY, rect, width, height) {
  if (!(rect?.width > 0 && rect?.height > 0 && width > 0 && height > 0)) return null;
  const clamp = (v, most) => Math.max(0, Math.min(most, Math.floor(v)));
  return {
    x: clamp((clientX - rect.left) * width / rect.width, width - 1),
    y: clamp((clientY - rect.top) * height / rect.height, height - 1)
  };
}

// A wheel event in IronRDP's pixel unit (it counts a line as 50 and a page as
// 1900), with Windows' signs: up and right are positive, as FreeRDP sends them.
export function wheelPixels(event) {
  const scale = event.deltaMode === 1 ? 50 : event.deltaMode === 2 ? 1900 : 1;
  const finite = v => Number.isFinite(v) ? v : 0;
  return { x: finite(event.deltaX) * scale, y: -finite(event.deltaY) * scale };
}

// What one message says of the wheel: RDP carries at most 255 units (120 is
// one notch). The rest waits for the next frame, at most four messages'
// worth, so a fling does not scroll on long after the hand stopped.
export function wheelStep(amount) {
  const step = Math.trunc(Math.max(-255, Math.min(255, Number.isFinite(amount) ? amount : 0)));
  return { step, rest: Math.max(-1020, Math.min(1020, (Number.isFinite(amount) ? amount : 0) - step)) };
}

// Windows' pointer image arrives as a data: URL of a PNG. The page's policy
// allows images from blob: URLs only, so the bytes are taken out here, and
// nothing but a PNG of a pointer's size is accepted.
export const maxPointerBytes = 512 * 1024;
export function pointerPNG(url) {
  const prefix = 'data:image/png;base64,';
  if (typeof url !== 'string' || !url.startsWith(prefix) || url.length > prefix.length + Math.ceil(maxPointerBytes / 3) * 4) return null;
  let binary;
  try { binary = atob(url.slice(prefix.length)); } catch { return null; }
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  return bytes.length > signature.length && signature.every((b, i) => bytes[i] === b) ? bytes : null;
}

// Why the gateway ended a desktop: its close code names the reason, and the
// close text must be that reason's own word. Anything else says nothing.
const reasons = new Map([
  [4001, 'idle'], [4002, 'expired'], [4003, 'signed-out'], [4004, 'access-changed'], [4005, 'credentials'],
  [4006, 'account'], [4007, 'taken-over'], [4008, 'remote-ended'], [4009, 'unreachable'], [4010, 'not-responding'],
  [4011, 'refused'], [4020, 'identity-changed']
]);
export function closeReason(code, text) {
  const word = reasons.get(code);
  return word && text === word ? word : null;
}
