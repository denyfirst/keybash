import test from 'node:test';
import assert from 'node:assert/strict';

// The canvases the renderer draws on, as plain recorders.
class Context {
  constructor(log) { this.log = log; this.fillStyle = ''; }
  drawImage(...a) { this.log.push(['drawImage', a.length]); }
  putImageData(image, x, y) { this.log.push(['putImageData', image.width, image.height, x, y]); }
  fillRect(...a) { this.log.push(['fillRect', ...a]); }
  clearRect() {} save() {} restore() {} beginPath() {} rect() {} clip() {}
}
const log = [];
globalThis.HTMLCanvasElement = class { constructor() { this.width = 0; this.height = 0; this.ctx = new Context(log); } getContext() { return this.ctx; } };
globalThis.OffscreenCanvas = class { constructor(w, h) { this.width = w; this.height = h; this.ctx = new Context(log); } getContext() { return this.ctx; } };
globalThis.ImageData = class { constructor(data, width, height) { Object.assign(this, { data, width, height }); } };
const { createRenderer, limits, nalUnits, avcCodec } = await import('./remote-desktop-gfx.mjs');

// Records as Keybash's patch writes them (gfx.rs), little endian.
class Records {
  constructor() { this.b = []; }
  u8(v) { this.b.push(v & 0xff); return this; }
  u16(v) { return this.u8(v).u8(v >> 8); }
  u32(v) { return this.u16(v & 0xffff).u16(v >>> 16); }
  rect(l, t, r, b) { return this.u16(l).u16(t).u16(r).u16(b); }
  bytes(data) { this.u32(data.length); for (const x of data) this.u8(x); return this; }
  reset(w, h) { return this.u8(1).u32(w).u32(h); }
  create(id, w, h) { return this.u8(2).u16(id).u16(w).u16(h).u8(0); }
  remove(id) { return this.u8(3).u16(id); }
  map(id) { return this.u8(4).u16(id).u32(0).u32(0); }
  fill(id, rects) { this.u8(5).u16(id).u8(1).u8(2).u8(3).u8(255).u16(rects.length); for (const r of rects) this.rect(...r); return this; }
  toCache(id, slot, rect) { return this.u8(7).u16(id).u16(slot).rect(...rect); }
  evict(slot) { return this.u8(9).u16(slot); }
  bitmap(id, rect, data) { return this.u8(10).u16(id).rect(...rect).bytes(data); }
  end(id) { return this.u8(13).u32(id); }
  get array() { return Uint8Array.from(this.b); }
}
const fresh = () => ({ renderer: createRenderer(), canvas: new HTMLCanvasElement() });

test('a frame is drawn on the page\'s canvas', async () => {
  const { renderer, canvas } = fresh();
  log.length = 0;
  const pixels = new Array(2 * 2 * 4).fill(7);
  assert.equal(renderer.apply(canvas, new Records().reset(64, 32).create(1, 64, 32).map(1).fill(1, [[0, 0, 8, 8]]).bitmap(1, [4, 4, 6, 6], pixels).end(1).array), undefined);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(canvas.width, 64);
  assert.equal(canvas.height, 32);
  assert.ok(log.some(([name, w, h]) => name === 'putImageData' && w === 2 && h === 2));
  assert.ok(log.some(([name]) => name === 'drawImage'), 'the surface reached the canvas');
  assert.equal(renderer.stats.frames, 1);
});

test('records outside the bounds end the desktop', () => {
  const cases = {
    'a desktop past full HD at 200%': new Records().reset(limits.width + 1, 100),
    'an empty desktop': new Records().reset(0, 100),
    'a surface past the bounds': new Records().reset(64, 64).create(1, 100, limits.height + 1),
    'a record cut short': new Records().reset(64, 64).u8(2).u16(1),
    'a length past the batch': new Records().reset(64, 64).create(1, 8, 8).u8(10).u16(1).rect(0, 0, 1, 1).u32(4),
    'an unknown record': new Records().u8(99),
    'a bitmap of the wrong size': new Records().reset(64, 64).create(1, 8, 8).bitmap(1, [0, 0, 2, 2], [1, 2, 3]),
    'too many rectangles': (() => { const r = new Records().reset(64, 64).create(1, 8, 8).u8(5).u16(1).u32(0).u16(limits.items + 1); for (let i = 0; i <= limits.items; i++) r.rect(0, 0, 1, 1); return r; })()
  };
  for (const [name, records] of Object.entries(cases)) {
    const { renderer, canvas } = fresh();
    assert.throws(() => renderer.apply(canvas, records.array), Error, name);
  }
});

test('surfaces and the cache stay within their memory', () => {
  let { renderer, canvas } = fresh();
  const many = new Records().reset(64, 64);
  for (let id = 0; id < limits.surfaces; id++) many.create(id, 8, 8);
  renderer.apply(canvas, many.array);
  assert.throws(() => renderer.apply(canvas, new Records().create(limits.surfaces, 8, 8).array), /too many surfaces/);
  ({ renderer, canvas } = fresh());
  renderer.apply(canvas, new Records().reset(64, 64).create(1, limits.width, limits.height).create(2, limits.width, limits.height).array);
  assert.throws(() => renderer.apply(canvas, new Records().create(3, 8, 8).array), /too many surfaces/);
  // Replacing or deleting a surface gives its memory back, and a reset all of it.
  ({ renderer, canvas } = fresh());
  for (let i = 0; i < 50; i++) renderer.apply(canvas, new Records().reset(64, 64).create(1, limits.width, limits.height).create(1, limits.width, limits.height).create(2, limits.width, limits.height).remove(2).array);
  ({ renderer, canvas } = fresh());
  renderer.apply(canvas, new Records().reset(64, 64).create(1, 2048, 2048).toCache(1, 0, [0, 0, 2048, 2048]).array);
  assert.throws(() => renderer.apply(canvas, new Records().toCache(1, 1, [0, 0, 1, 1]).array), /cache overflow/);
  renderer.apply(canvas, new Records().evict(0).toCache(1, 1, [0, 0, 2048, 2048]).array);
  assert.throws(() => renderer.apply(canvas, new Records().toCache(1, limits.cacheSlots, [0, 0, 1, 1]).array), /cache overflow/);
});

test('an ended desktop takes no more records, nor another canvas', () => {
  const { renderer, canvas } = fresh();
  assert.throws(() => renderer.apply({}, new Records().reset(64, 64).array), /refused/);
  assert.throws(() => renderer.apply(canvas, [1, 2, 3]), /refused/);
  renderer.close();
  assert.throws(() => renderer.apply(canvas, new Records().reset(64, 64).array), /ended/);
});

test('H.264 is read as Annex B, its codec from its own SPS', () => {
  const data = Uint8Array.from([0, 0, 0, 1, 0x67, 0x64, 0x00, 0x28, 0xaa, 0, 0, 1, 0x68, 0xbb, 0, 0, 1, 0x65, 0x88, 0, 0, 1, 0x41]);
  const units = nalUnits(data);
  assert.deepEqual(units.map(([type]) => type), [7, 8, 5]);
  assert.equal(avcCodec(data, units), 'avc1.640028');
  assert.equal(avcCodec(Uint8Array.from([0, 0, 1, 0x41]), nalUnits(Uint8Array.from([0, 0, 1, 0x41]))), 'avc1.640033');
  assert.deepEqual(nalUnits(Uint8Array.from([0, 0, 1])), []);
});
