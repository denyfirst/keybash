import test from 'node:test';
import assert from 'node:assert/strict';
import { desktopScales, nearestScale, scaledSize, startSizeField } from './desktop-workspace.mjs';

test('a screen gets the nearest Windows scale, 100% for anything unusable', () => {
  for (const [ratio, want] of [[1, 1], [0.9, 1], [1.1, 1], [1.2, 1.25], [1.25, 1.25], [1.4, 1.5], [1.5, 1.5],
    [1.7, 1.75], [1.8, 1.75], [1.9, 2], [2, 2], [2.625, 2], [3, 2], [0, 1], [-2, 1], [NaN, 1], [Infinity, 1]]) {
    assert.equal(nearestScale(ratio), want, `ratio ${ratio}`);
  }
});

test('device pixels stay even, at least 200, within full HD times the scale', () => {
  assert.deepEqual(scaledSize(1440, 900, 2), [2880, 1800]);
  assert.deepEqual(scaledSize(1400, 1000, 1), [1400, 1000]);
  assert.deepEqual(scaledSize(1401, 901, 1), [1400, 900]);
  assert.deepEqual(scaledSize(1366, 768, 1.25), [1706, 960]);
  assert.deepEqual(scaledSize(50, 50, 2), [200, 200]);
  for (const scale of desktopScales) {
    const [w, h] = scaledSize(100000, 100000, scale);
    assert.deepEqual([w, h], [1920 * scale, 1080 * scale], `largest at ${scale}`);
    assert.ok(w % 2 === 0 && h % 2 === 0, `even at ${scale}`);
  }
});

test('the start size names the DPI only on a scaled screen', () => {
  assert.equal(startSizeField(1600, 900, 1), '1600x900');
  assert.equal(startSizeField(2880, 1800, 2), '2880x1800@192');
  assert.equal(startSizeField(2400, 1350, 1.25), '2400x1350@120');
  assert.equal(startSizeField(2880, 1620, 1.5), '2880x1620@144');
  assert.equal(startSizeField(3360, 1890, 1.75), '3360x1890@168');
});
