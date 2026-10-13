import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectPaste, decodeOutput } from './paste.mjs';

test('single-line Unicode may paste; multiline/control text always needs review', () => {
  assert.equal(inspectPaste('Azərbaycan əıöüçşğ').review, false);
  for (const value of ['one\ntwo', 'one\rtwo', '\t', '\x03', '\x1b[201~', '\x7f', '\u0085', '\u2028', '\u202e', '\ufeff']) {
    const result = inspectPaste(value);
    assert.equal(result.allowed, true);
    assert.equal(result.review, true);
  }
  assert.equal(inspectPaste('\x1b[201~').preview, '\\u001b[201~');
});
test('byte limits apply to Unicode as well as ASCII', () => {
  assert.equal(inspectPaste('a'.repeat(32768)).allowed, true);
  for (const value of ['a'.repeat(32769), 'ə'.repeat(16385), null]) assert.equal(inspectPaste(value).allowed, false);
});
test('bounded ordered output frames preserve partial Unicode bytes', () => {
  const buffer = new Uint8Array([0, 0, 0, 1, 0xc9]).buffer;
  assert.deepEqual([...decodeOutput(buffer, 1).bytes], [0xc9]);
  for (const [buffer, expected] of [[new ArrayBuffer(4), 1], [new ArrayBuffer(8197), 1], [new Uint8Array([0, 0, 0, 2, 65]).buffer, 1]]) {
    assert.throws(() => decodeOutput(buffer, expected));
  }
});
