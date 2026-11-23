import test from 'node:test';
import assert from 'node:assert/strict';
import { desktopScales, nearestScale, pictureScale, scaledSize, rateLimiter, pastePacer, windowsLines, pointerCursor, pasteWait, pasteNotice } from './desktop-workspace.mjs';

test('the picture: sharp is the screen\'s scale, smooth is 100%, and with no choice smooth from 175% up', () => {
  for (const [ratio, sharp] of [[1, 1], [1.25, 1.25], [1.5, 1.5], [1.75, 1.75], [2, 2], [2.625, 2], [NaN, 1]]) {
    assert.equal(pictureScale('sharp', ratio), sharp, `sharp at ${ratio}`);
    assert.equal(pictureScale('smooth', ratio), 1, `smooth at ${ratio}`);
    assert.equal(pictureScale('', ratio), sharp >= 1.75 ? 1 : sharp, `no choice at ${ratio}`);
    // Only the two words choose; anything else is no choice.
    assert.equal(pictureScale('Sharp', ratio), pictureScale('', ratio), `other words at ${ratio}`);
  }
  // A 4K screen at 200% with no choice opens at 100%: a quarter of the pixels.
  assert.deepEqual(scaledSize(1920, 1040, pictureScale('', 2)), [1920, 1040]);
  assert.deepEqual(scaledSize(1920, 1040, pictureScale('sharp', 2)), [3840, 2080]);
});

test("Windows' pointer becomes the browser's own at the desktop's scale", () => {
  // At 200% the desktop is shown at half size: the image is a 2x image and
  // the hotspot is in CSS pixels.
  assert.equal(pointerCursor('blob:x', 10, 6, 0.5), 'image-set(url("blob:x") 2x) 5 3, default');
  assert.equal(pointerCursor('blob:x', 10, 6, 1), 'image-set(url("blob:x") 1x) 10 6, default');
  assert.equal(pointerCursor('blob:x', 9, 9, 0.8), 'image-set(url("blob:x") 1.25x) 7 7, default');
  // A desktop fitted into a smaller window is shown smaller still.
  assert.equal(pointerCursor('blob:x', 64, 64, 0.25), 'image-set(url("blob:x") 4x) 16 16, default');
});

test('a screen gets the nearest Windows scale, 100% for anything unusable', () => {
  for (const [ratio, want] of [[1, 1], [0.9, 1], [1.1, 1], [1.2, 1.25], [1.25, 1.25], [1.4, 1.5], [1.5, 1.5],
    [1.7, 1.75], [1.8, 1.75], [1.9, 2], [2, 2], [2.625, 2], [3, 2], [0, 1], [-2, 1], [NaN, 1], [Infinity, 1]]) {
    assert.equal(nearestScale(ratio), want, `ratio ${ratio}`);
  }
});

test('device pixels: width a multiple of 4, height even, at least 200, within full HD times the scale', () => {
  assert.deepEqual(scaledSize(1440, 900, 2), [2880, 1800]);
  assert.deepEqual(scaledSize(1400, 1000, 1), [1400, 1000]);
  assert.deepEqual(scaledSize(1401, 901, 1), [1400, 900]);
  assert.deepEqual(scaledSize(1403, 901, 1), [1400, 900]);
  // The width comes down to a multiple of 4.
  assert.deepEqual(scaledSize(1366, 768, 1.25), [1704, 960]);
  assert.deepEqual(scaledSize(50, 50, 2), [200, 200]);
  for (const scale of desktopScales) {
    const [w, h] = scaledSize(100000, 100000, scale);
    assert.deepEqual([w, h], [1920 * scale, 1080 * scale], `largest at ${scale}`);
    assert.ok(w % 4 === 0 && h % 2 === 0, `width by 4, height even at ${scale}`);
    for (let css = 160; css < 2000; css += 37) {
      const [sw, sh] = scaledSize(css, css, scale);
      assert.ok(sw % 4 === 0 && sh % 2 === 0 && sw >= 200 && sh >= 200, `${css} at ${scale}`);
    }
  }
});

test('a rate limiter gives its burst, then its rate', () => {
  let t = 0;
  const allow = rateLimiter(100, 10, () => t);
  for (let i = 0; i < 10; i++) assert.ok(allow(), `burst ${i}`);
  assert.ok(!allow(), 'past the burst');
  t += 10; // 10 ms at 100 a second is one more
  assert.ok(allow());
  assert.ok(!allow());
  t += 1000; // never more than the burst saved up
  for (let i = 0; i < 10; i++) assert.ok(allow(), `refilled ${i}`);
  assert.ok(!allow());
});

test('the first paste goes at once, later ones are paced', () => {
  let t = 100; // a page open for a tenth of a second
  const allow = pastePacer(() => t);
  assert.ok(allow(), 'first paste');
  t = 400;
  assert.ok(!allow(), 'under half a second after the first');
  // Held Ctrl+V, a paste every half second: the burst of 8 lasts 15 pastes
  // (half a token back between each), then about one a second.
  for (let i = 0; i < 14; i++) { t += 500; assert.ok(allow(), `held ${i}`); }
  t += 500;
  assert.ok(!allow(), 'past the burst');
  t += 500;
  assert.ok(allow(), 'a second later');
});

test('pasted text reaches Windows with CRLF line ends', () => {
  assert.equal(windowsLines('a\nb\r\nc\rd'), 'a\r\nb\r\nc\r\nd');
  assert.equal(windowsLines('one line'), 'one line');
  assert.equal(windowsLines('\r\n\r\n'), '\r\n\r\n');
});


test('a paste Windows never answered says what helps; a refused one says it plainly', () => {
  assert.match(pasteNotice('silent'), /sign out of Windows/);
  for (const answer of ['refused', 'taken', '', undefined]) {
    assert.equal(pasteNotice(answer), 'The text could not be pasted.', String(answer));
  }
  assert.ok(pasteWait >= 1000 && pasteWait <= 5000);
});
