import test from 'node:test';
import assert from 'node:assert/strict';
import { scanCode, sendsRepeat, modifierChanges, ctrlAltDel, ctrlV, mouseButton, desktopPoint, wheelPixels, wheelStep, pointerPNG, maxPointerBytes, closeReason } from './remote-desktop-input.mjs';

test('keys go as the scan codes Windows knows, and unknown keys not at all', () => {
  for (const [code, scan] of [['Escape', 0x01], ['Digit1', 0x02], ['Digit0', 0x0b], ['KeyQ', 0x10], ['KeyA', 0x1e], ['KeyZ', 0x2c], ['KeyM', 0x32],
    ['Space', 0x39], ['F1', 0x3b], ['F10', 0x44], ['F11', 0x57], ['F12', 0x58], ['F13', 0x64], ['F24', 0x76], ['Numpad0', 0x52], ['NumpadDecimal', 0x53],
    ['ControlLeft', 0x1d], ['ControlRight', 0xe01d], ['AltRight', 0xe038], ['NumpadEnter', 0xe01c], ['NumpadDivide', 0xe035], ['ArrowLeft', 0xe04b],
    ['Delete', 0xe053], ['MetaLeft', 0xe05b], ['OSLeft', 0xe05b], ['ContextMenu', 0xe05d], ['IntlBackslash', 0x56], ['Backquote', 0x29]]) {
    assert.equal(scanCode(code), scan, code);
  }
  for (const code of ['', 'Unidentified', 'Fn', 'a', 'KEYA', '__proto__', 'toString', 'constructor', undefined, null, 30]) {
    assert.equal(scanCode(code), null, String(code));
  }
});

test('no two keys share a scan code but the browsers\' own aliases', () => {
  const aliases = new Set(['OSLeft', 'OSRight', 'VolumeMute', 'VolumeDown', 'VolumeUp']);
  const seen = new Map();
  for (const code of ['Escape', 'Digit1', 'Digit2', 'Digit3', 'Digit4', 'Digit5', 'Digit6', 'Digit7', 'Digit8', 'Digit9', 'Digit0', 'Minus', 'Equal', 'Backspace', 'Tab',
    'KeyQ', 'KeyW', 'KeyE', 'KeyR', 'KeyT', 'KeyY', 'KeyU', 'KeyI', 'KeyO', 'KeyP', 'BracketLeft', 'BracketRight', 'Enter', 'ControlLeft',
    'KeyA', 'KeyS', 'KeyD', 'KeyF', 'KeyG', 'KeyH', 'KeyJ', 'KeyK', 'KeyL', 'Semicolon', 'Quote', 'Backquote', 'ShiftLeft', 'Backslash',
    'KeyZ', 'KeyX', 'KeyC', 'KeyV', 'KeyB', 'KeyN', 'KeyM', 'Comma', 'Period', 'Slash', 'ShiftRight', 'NumpadMultiply', 'AltLeft', 'Space', 'CapsLock',
    'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12', 'NumLock', 'ScrollLock', 'Pause',
    'Home', 'End', 'PageUp', 'PageDown', 'Insert', 'Delete', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'MetaLeft', 'MetaRight', 'OSLeft', 'OSRight',
    'AltRight', 'ControlRight', 'NumpadEnter', 'NumpadDivide', 'PrintScreen', 'VolumeMute', 'AudioVolumeMute', 'VolumeUp', 'AudioVolumeUp', 'VolumeDown', 'AudioVolumeDown']) {
    const scan = scanCode(code);
    assert.notEqual(scan, null, code);
    if (aliases.has(code)) continue;
    assert.ok(!seen.has(scan), `${code} and ${seen.get(scan)} share ${scan.toString(16)}`);
    seen.set(scan, code);
  }
});

test('a held modifier or lock key is pressed once, other keys repeat', () => {
  for (const code of ['ShiftLeft', 'ControlRight', 'AltLeft', 'MetaLeft', 'OSRight', 'CapsLock', 'NumLock', 'ScrollLock', 'KanaMode']) assert.equal(sendsRepeat(code), false, code);
  for (const code of ['KeyA', 'Backspace', 'ArrowDown', 'Space', 'Delete']) assert.equal(sendsRepeat(code), true, code);
  assert.deepEqual(ctrlAltDel, [0x1d, 0x38, 0xe053]);
  assert.deepEqual(ctrlV, [0x1d, 0x2f]);
});

test('Windows\' modifiers follow what each event says', () => {
  const none = { shiftKey: false, ctrlKey: false, altKey: false, metaKey: false };
  // A shifted key with no Shift press of its own (held before focus came).
  assert.deepEqual(modifierChanges({ ...none, code: 'KeyH', shiftKey: true }, new Set()), { press: ['ShiftLeft'], release: [] });
  // Shift already pressed on either side: nothing more.
  assert.deepEqual(modifierChanges({ ...none, code: 'KeyH', shiftKey: true }, new Set(['ShiftRight'])), { press: [], release: [] });
  // Ctrl and Alt let go elsewhere are let go on Windows, both sides.
  assert.deepEqual(modifierChanges({ ...none, code: 'KeyA' }, new Set(['ControlLeft', 'ControlRight', 'AltLeft', 'KeyA'])), { press: [], release: ['ControlLeft', 'ControlRight', 'AltLeft'] });
  // The event's own modifier is the event's: Shift's keyup does not release itself twice.
  assert.deepEqual(modifierChanges({ ...none, code: 'ShiftLeft' }, new Set(['ShiftLeft'])), { press: [], release: [] });
  assert.deepEqual(modifierChanges({ ...none, code: 'ControlLeft', ctrlKey: true, altKey: true }, new Set()), { press: ['AltLeft'], release: [] });
  // The Windows key under either name, and an event without the flags changes nothing.
  assert.deepEqual(modifierChanges({ ...none, code: 'KeyE' }, new Set(['OSLeft'])), { press: [], release: ['OSLeft'] });
  assert.deepEqual(modifierChanges({ code: 'KeyE' }, new Set(['ShiftLeft'])), { press: [], release: [] });
});

test('only the five mouse buttons IronRDP knows are sent', () => {
  for (const b of [0, 1, 2, 3, 4]) assert.equal(mouseButton(b), b);
  for (const b of [-1, 5, 1.5, '0', NaN, undefined]) assert.equal(mouseButton(b), null, String(b));
});

test('the pointer lands on the desktop\'s own pixels, inside its edges', () => {
  const rect = { left: 100, top: 50, width: 640, height: 360 };
  assert.deepEqual(desktopPoint(100, 50, rect, 1280, 720), { x: 0, y: 0 });
  assert.deepEqual(desktopPoint(420, 230, rect, 1280, 720), { x: 640, y: 360 });
  assert.deepEqual(desktopPoint(10000, 10000, rect, 1280, 720), { x: 1279, y: 719 });
  assert.deepEqual(desktopPoint(-5, -5, rect, 1280, 720), { x: 0, y: 0 });
  assert.equal(desktopPoint(1, 1, { left: 0, top: 0, width: 0, height: 10 }, 1280, 720), null);
  assert.equal(desktopPoint(1, 1, rect, 0, 720), null);
});

test('the wheel goes in Windows\' signs and units, a step at a time', () => {
  // A notch, as Chrome and Edge give it, is Windows' 120 units; a touchpad's
  // small steps add up the same way, with nothing lost.
  assert.deepEqual(wheelPixels({ deltaMode: 0, deltaX: 0, deltaY: 100 }), { x: 0, y: -120 });
  assert.deepEqual(wheelPixels({ deltaMode: 0, deltaX: 25, deltaY: 0 }), { x: 30, y: -0 });
  const swipe = [4, 7.5, 12, 16.5, 10, 50].reduce((sum, d) => sum + wheelPixels({ deltaMode: 0, deltaX: 0, deltaY: d }).y, 0);
  assert.ok(Math.abs(swipe + 120) < 1e-9, 'a touchpad notch is not one Windows notch');
  // Three lines, as Firefox gives a notch, are a notch too.
  assert.deepEqual(wheelPixels({ deltaMode: 1, deltaX: 0, deltaY: -3 }), { x: 0, y: 120 });
  assert.deepEqual(wheelPixels({ deltaMode: 2, deltaX: 0, deltaY: 1 }), { x: 0, y: -1520 });
  assert.deepEqual(wheelPixels({ deltaMode: 0, deltaX: NaN, deltaY: Infinity }), { x: 0, y: -0 });
  assert.deepEqual(wheelStep(100), { step: 100, rest: 0 });
  assert.deepEqual(wheelStep(-400.7), { step: -255, rest: -145.7 });
  assert.deepEqual(wheelStep(1e9), { step: 255, rest: 1020 });
  assert.deepEqual(wheelStep(NaN), { step: 0, rest: 0 });
});

test('a pointer image is taken only as a PNG of a pointer\'s size', () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);
  const url = 'data:image/png;base64,' + png.toString('base64');
  assert.deepEqual([...pointerPNG(url)], [...png]);
  assert.equal(pointerPNG('data:image/svg+xml;base64,' + png.toString('base64')), null);
  assert.equal(pointerPNG('data:image/png;base64,' + Buffer.from('GIF89a....').toString('base64')), null);
  assert.equal(pointerPNG('data:image/png;base64,***'), null);
  assert.equal(pointerPNG('data:image/png;base64,' + Buffer.concat([png, Buffer.alloc(maxPointerBytes)]).toString('base64')), null);
  assert.equal(pointerPNG(undefined), null);
});

test('an ending says why only when its code and word agree', () => {
  assert.equal(closeReason(4005, 'credentials'), 'credentials');
  assert.equal(closeReason(4001, 'idle'), 'idle');
  assert.equal(closeReason(4011, 'refused'), 'refused');
  assert.equal(closeReason(4020, 'identity-changed'), 'identity-changed');
  assert.equal(closeReason(4005, 'idle'), null);
  assert.equal(closeReason(4012, 'refused'), null);
  assert.equal(closeReason(1000, ''), null);
  assert.equal(closeReason(1006, 'credentials'), null);
});
