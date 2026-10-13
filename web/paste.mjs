export const MAX_INPUT = 32768;
const encoder = new TextEncoder();

export function inspectPaste(text) {
  if (typeof text !== 'string' || text.length > MAX_INPUT || encoder.encode(text).length > MAX_INPUT) {
    return { allowed: false, review: false, preview: '' };
  }
  const review = /[\x00-\x1f\x7f\u0080-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/u.test(text);
  // Show invisible controls instead of letting them disguise the review text.
  const preview = text.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u0080-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/gu,
    c => `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`);
  return { allowed: true, review, preview };
}

export function decodeOutput(buffer, expected) {
  if (!(buffer instanceof ArrayBuffer) || buffer.byteLength <= 4 || buffer.byteLength > 8196) throw new Error('invalid output');
  const sequence = new DataView(buffer).getUint32(0);
  if (sequence !== expected) throw new Error('unexpected output sequence');
  return { sequence, bytes: new Uint8Array(buffer, 4) };
}
