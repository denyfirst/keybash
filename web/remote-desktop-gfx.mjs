// Windows' graphics pipeline (MS-RDPEGFX), drawn by the desktop page. Keybash's
// IronRDP patch (ironrdp/graphics-pipeline.diff, gfx.rs) parses the channel
// and decodes the bitmap codecs; after each frame it hands the page one batch
// of records, in order, through globalThis.__keybashGfx.apply. Bitmaps arrive
// as RGBA. H.264 goes to the browser's own decoder (WebCodecs) and is drawn
// straight from the decoded frame.
//
// Everything here comes from Windows through the proxy, so every count, size
// and length is checked before it is used, and memory is bounded: a record
// outside these limits ends the desktop.

const RESET = 1, CREATE = 2, DELETE = 3, MAP = 4, FILL = 5, COPY = 6, TO_CACHE = 7, FROM_CACHE = 8;
const EVICT = 9, BITMAP = 10, AVC420 = 11, AVC444 = 12, END_FRAME = 13, MAP_SCALED = 14, NOTE = 15;
const CLOSE = 16, ALPHA = 17;

export const limits = Object.freeze({
  // The largest desktop Keybash opens: full HD at 200% (identity.DesktopSize).
  width: 3840, height: 2160,
  surfaces: 16, surfacePixels: 2 * 3840 * 2160,
  // The small cache Keybash's patch asks for: 16 MiB (MS-RDPEGFX 2.2.3.1).
  cacheSlots: 4096, cachePixels: 4 * 1024 * 1024,
  items: 4096, decoders: 4, bytes: 64 * 1024 * 1024,
  // Frames drawn behind the session before it waits, and the longest wait.
  framesAhead: 3, waitMs: 250
});

class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.o = 0;
  }
  more() { return this.o < this.b.length; }
  need(n) { if (this.o + n > this.b.length) throw new Error('graphics record cut short'); }
  u8() { this.need(1); return this.v.getUint8(this.o++); }
  u16() { this.need(2); const x = this.v.getUint16(this.o, true); this.o += 2; return x; }
  u32() { this.need(4); const x = this.v.getUint32(this.o, true); this.o += 4; return x; }
  count() { const n = this.u16(); if (n > limits.items) throw new Error('graphics record too long'); return n; }
  rect() { const l = this.u16(), t = this.u16(), r = this.u16(), b = this.u16(); return { l, t, r, b }; }
  rects() { const n = this.count(), a = []; for (let i = 0; i < n; i++) a.push(this.rect()); return a; }
  points() { const n = this.count(), a = []; for (let i = 0; i < n; i++) a.push({ x: this.u16(), y: this.u16() }); return a; }
  bytes() { const n = this.u32(); this.need(n); const s = this.b.subarray(this.o, this.o + n); this.o += n; return s; }
}

// Annex B: each NAL unit's type and the offset of its header, up to the first slice.
export function nalUnits(data) {
  const units = [];
  for (let i = 0; i + 3 < data.length; i++) {
    if (data[i] !== 0 || data[i + 1] !== 0) continue;
    let start = -1;
    if (data[i + 2] === 1) start = i + 3;
    else if (data[i + 2] === 0 && data[i + 3] === 1) start = i + 4;
    if (start < 0 || start >= data.length) continue;
    const type = data[start] & 0x1f;
    units.push([type, start]);
    if (type === 1 || type === 5) break;
    i = start;
  }
  return units;
}

// avc1.PPCCLL from the stream's own profile, constraints and level.
export function avcCodec(data, units) {
  const sps = units.find(([type]) => type === 7);
  const hex = n => n.toString(16).padStart(2, '0');
  return sps && sps[1] + 3 < data.length ? `avc1.${hex(data[sps[1] + 1])}${hex(data[sps[1] + 2])}${hex(data[sps[1] + 3])}` : 'avc1.640033';
}

function clip(rect, w, h) {
  const l = Math.min(rect.l, w), t = Math.min(rect.t, h);
  const right = Math.min(rect.r, w), bottom = Math.min(rect.b, h);
  return right > l && bottom > t ? { l, t, r: right, b: bottom } : null;
}

export function createRenderer() {
  const surfaces = new Map(), cache = new Map(), decoders = new Map(), queue = [];
  let output = null, octx = null, pumping = false, framesQueued = 0, waiters = [], closed = false;
  const stats = { codec: '', frames: 0, decoded: 0, skipped: 0, errors: 0, stalls: 0, notes: 0 };

  function retire(id) {
    const d = decoders.get(id);
    if (!d) return;
    decoders.delete(id);
    // Pictures already sent still come out before the decoder closes.
    d.dec.flush().then(() => d.dec.close(), () => {}).catch(() => {});
  }
  function retireAll() { for (const id of [...decoders.keys()]) retire(id); }

  function decoderFor(id, data, units) {
    const live = decoders.get(id);
    if (live && live.dec.state !== 'closed') return live;
    // A stream starts at a key picture; anything before one cannot be decoded.
    if (!units.some(([type]) => type === 5) || typeof VideoDecoder !== 'function') return null;
    if (decoders.size >= limits.decoders) throw new Error('too many video streams');
    const d = { pending: [], ts: 0, dec: null };
    d.dec = new VideoDecoder({
      output: frame => {
        const entry = d.pending.shift();
        stats.decoded++;
        if (!entry || closed) { frame.close(); entry?.resolve(null); return; }
        entry.resolve(frame);
      },
      error: () => {
        stats.errors++;
        for (const entry of d.pending.splice(0)) entry.resolve(null);
        if (decoders.get(id) === d) decoders.delete(id);
      }
    });
    const codec = avcCodec(data, units);
    // MS-RDPEGFX 3.3.8.3.1: AVC420 pictures are full-range BT.709, whatever the stream says.
    d.dec.configure({
      codec, hardwareAcceleration: 'prefer-hardware', optimizeForLatency: true,
      colorSpace: { primaries: 'bt709', transfer: 'bt709', matrix: 'bt709', fullRange: true }
    });
    stats.codec = codec;
    decoders.set(id, d);
    return d;
  }

  // Sends one picture to the surface's decoder now; the promise gives the frame, or null.
  function submit(id, data) {
    const units = nalUnits(data);
    const key = units.some(([type]) => type === 5);
    const d = decoderFor(id, data, units);
    if (!d) { stats.skipped++; return Promise.resolve(null); }
    return new Promise(resolve => {
      d.pending.push({ resolve });
      try {
        d.dec.decode(new EncodedVideoChunk({ type: key ? 'key' : 'delta', timestamp: d.ts++ * 16667, data }));
      } catch {
        stats.errors++;
        d.pending.pop();
        resolve(null);
      }
    });
  }

  function push(op, waitFor) {
    if (waitFor) op.wait = Promise.all(waitFor).then(frames => { op.frames = frames; });
    queue.push(op);
  }

  // What the records will hold once drawn, counted as they are read, in
  // order: a record that would pass a limit ends the desktop before anything
  // is allocated for it.
  const planned = { surfaces: new Map(), pixels: 0, cache: new Map(), cachePixels: 0 };
  function planSurface(id, w, h) {
    planDropSurface(id);
    if (planned.surfaces.size >= limits.surfaces || planned.pixels + w * h > limits.surfacePixels) throw new Error('too many surfaces');
    planned.surfaces.set(id, { w, h });
    planned.pixels += w * h;
  }
  function planDropSurface(id) {
    const s = planned.surfaces.get(id);
    if (s) { planned.pixels -= s.w * s.h; planned.surfaces.delete(id); }
  }
  function planTile(id, slot, rect) {
    const s = planned.surfaces.get(id), r = s && clip(rect, s.w, s.h);
    planDropTile(slot);
    if (!r) return;
    const area = (r.r - r.l) * (r.b - r.t);
    if (slot >= limits.cacheSlots || planned.cachePixels + area > limits.cachePixels) throw new Error('graphics cache overflow');
    planned.cache.set(slot, area);
    planned.cachePixels += area;
  }
  function planDropTile(slot) {
    planned.cachePixels -= planned.cache.get(slot) ?? 0;
    planned.cache.delete(slot);
  }

  function parse(bytes) {
    const r = new Reader(bytes);
    while (r.more()) {
      const op = r.u8();
      switch (op) {
        case RESET: {
          const w = r.u32(), h = r.u32();
          if (w < 1 || h < 1 || w > limits.width || h > limits.height) throw new Error('desktop outside the bounds');
          // A reset ends every surface, and with it every H.264 stream.
          retireAll();
          planned.surfaces.clear(); planned.pixels = 0;
          push({ op, w, h });
          break;
        }
        case CREATE: {
          const id = r.u16(), w = r.u16(), h = r.u16(), alpha = r.u8() === 1;
          if (w < 1 || h < 1 || w > limits.width || h > limits.height) throw new Error('surface outside the bounds');
          planSurface(id, w, h);
          retire(id);
          push({ op, id, w, h, alpha });
          break;
        }
        case DELETE: { const id = r.u16(); planDropSurface(id); retire(id); push({ op, id }); break; }
        case MAP: push({ op, id: r.u16(), x: r.u32(), y: r.u32() }); break;
        case MAP_SCALED: push({ op, id: r.u16(), x: r.u32(), y: r.u32(), tw: r.u32(), th: r.u32() }); break;
        case FILL: push({ op, id: r.u16(), rgba: [r.u8(), r.u8(), r.u8(), r.u8()], rects: r.rects() }); break;
        case COPY: push({ op, src: r.u16(), dst: r.u16(), rect: r.rect(), points: r.points() }); break;
        case TO_CACHE: {
          const id = r.u16(), slot = r.u16(), rect = r.rect();
          planTile(id, slot, rect);
          push({ op, id, slot, rect });
          break;
        }
        case FROM_CACHE: push({ op, slot: r.u16(), id: r.u16(), points: r.points() }); break;
        case EVICT: { const slot = r.u16(); planDropTile(slot); push({ op, slot }); break; }
        case BITMAP: {
          const id = r.u16(), rect = r.rect(), data = r.bytes();
          const w = rect.r - rect.l, h = rect.b - rect.t;
          if (w < 1 || h < 1 || data.length !== w * h * 4) throw new Error('bitmap of the wrong size');
          push({ op, id, rect, data });
          break;
        }
        case AVC420: {
          const id = r.u16(), dest = r.rect(), rects = r.rects(), data = r.bytes();
          push({ op, id, dest, rects }, [submit(id, data)]);
          break;
        }
        case AVC444: {
          const id = r.u16(); r.u8(); const encoding = r.u8(), dest = r.rect();
          const first = { rects: r.rects(), data: r.bytes() };
          const second = r.u8() === 1 ? { rects: r.rects(), data: r.bytes() } : null;
          // Encoding 1 is luma only, 2 chroma only, 0 both (MS-RDPEGFX 2.2.4.5).
          const main = encoding === 2 ? null : first;
          const aux = encoding === 2 ? first : encoding === 0 ? second : null;
          // Both views are pictures of one H.264 stream: both are decoded, in order.
          const frames = [];
          if (main) frames.push(submit(id, main.data));
          if (aux) frames.push(submit(id, aux.data));
          push({ op, id, dest, main }, frames);
          break;
        }
        case END_FRAME: framesQueued++; push({ op, id: r.u32() }); break;
        case NOTE: r.bytes(); stats.notes++; break;
        case CLOSE:
          retireAll();
          planned.surfaces.clear(); planned.pixels = 0; planned.cache.clear(); planned.cachePixels = 0;
          push({ op });
          break;
        // Surfaces with alpha are drawn opaque; their alpha codec is not used.
        case ALPHA: r.u16(); r.rect(); r.bytes(); break;
        default: throw new Error('unknown graphics record');
      }
    }
  }

  function dirty(s, l, t, w, h) {
    if (w > 0 && h > 0) s.dirty.push({ l, t, r: l + w, b: t + h });
  }

  function makeSurface(w, h, alpha) {
    const canvas = new OffscreenCanvas(w, h);
    return { canvas, ctx: canvas.getContext('2d', { alpha }), w, h, alpha, x: 0, y: 0, tw: w, th: h, mapped: false, dirty: [] };
  }
  const dropSurface = id => surfaces.delete(id);
  const dropSurfaces = () => surfaces.clear();
  const dropCache = slot => cache.delete(slot);

  // A decoded picture on its surface inside the given rectangles: picture
  // (x, y) is surface (x, y), as FreeRDP draws it. Without rectangles, the
  // destination gets it all.
  function drawPicture(s, frame, rects, dest) {
    if (!rects.length) {
      const r = clip(dest, Math.min(s.w, frame.displayWidth), Math.min(s.h, frame.displayHeight));
      if (!r) return;
      s.ctx.drawImage(frame, r.l, r.t, r.r - r.l, r.b - r.t, r.l, r.t, r.r - r.l, r.b - r.t);
      dirty(s, r.l, r.t, r.r - r.l, r.b - r.t);
      return;
    }
    s.ctx.save();
    s.ctx.beginPath();
    for (const rect of rects) {
      const r = clip(rect, Math.min(s.w, frame.displayWidth), Math.min(s.h, frame.displayHeight));
      if (!r) continue;
      s.ctx.rect(r.l, r.t, r.r - r.l, r.b - r.t);
      dirty(s, r.l, r.t, r.r - r.l, r.b - r.t);
    }
    s.ctx.clip();
    s.ctx.drawImage(frame, 0, 0);
    s.ctx.restore();
  }

  function composite() {
    for (const s of surfaces.values()) {
      if (!s.mapped || !s.dirty.length) continue;
      let rects = s.dirty;
      if (rects.length > 48) {
        const b = { l: Infinity, t: Infinity, r: 0, b: 0 };
        for (const r of rects) { b.l = Math.min(b.l, r.l); b.t = Math.min(b.t, r.t); b.r = Math.max(b.r, r.r); b.b = Math.max(b.b, r.b); }
        rects = [b];
      }
      const sx = s.tw / s.w, sy = s.th / s.h;
      for (const r of rects) {
        const w = r.r - r.l, h = r.b - r.t;
        octx.drawImage(s.canvas, r.l, r.t, w, h, s.x + r.l * sx, s.y + r.t * sy, w * sx, h * sy);
      }
      s.dirty = [];
    }
  }

  function run(op) {
    switch (op.op) {
      case RESET:
        dropSurfaces();
        if (output.width !== op.w || output.height !== op.h) { output.width = op.w; output.height = op.h; }
        octx.fillStyle = '#000';
        octx.fillRect(0, 0, op.w, op.h);
        break;
      case CREATE: dropSurface(op.id); surfaces.set(op.id, makeSurface(op.w, op.h, op.alpha)); break;
      case DELETE: dropSurface(op.id); break;
      case MAP:
      case MAP_SCALED: {
        const s = surfaces.get(op.id);
        if (!s) break;
        const tw = op.tw ?? s.w, th = op.th ?? s.h;
        if (tw < 1 || th < 1 || tw > limits.width || th > limits.height) break;
        Object.assign(s, { x: op.x, y: op.y, mapped: true, tw, th });
        dirty(s, 0, 0, s.w, s.h);
        break;
      }
      case FILL: {
        const s = surfaces.get(op.id);
        if (!s) break;
        const [red, green, blue, a] = op.rgba;
        s.ctx.fillStyle = `rgba(${red},${green},${blue},${s.alpha ? a / 255 : 1})`;
        for (const rect of op.rects) {
          const r = clip(rect, s.w, s.h);
          if (!r) continue;
          if (s.alpha) s.ctx.clearRect(r.l, r.t, r.r - r.l, r.b - r.t);
          s.ctx.fillRect(r.l, r.t, r.r - r.l, r.b - r.t);
          dirty(s, r.l, r.t, r.r - r.l, r.b - r.t);
        }
        break;
      }
      case COPY: {
        const src = surfaces.get(op.src), dst = surfaces.get(op.dst);
        if (!src || !dst) break;
        const r = clip(op.rect, src.w, src.h);
        if (!r) break;
        const w = r.r - r.l, h = r.b - r.t;
        let from = src.canvas, fx = r.l, fy = r.t;
        // A copy within one surface reads what was there before it.
        if (src === dst && op.points.length > 0) {
          from = new OffscreenCanvas(w, h);
          from.getContext('2d', { alpha: src.alpha }).drawImage(src.canvas, r.l, r.t, w, h, 0, 0, w, h);
          fx = 0; fy = 0;
        }
        for (const p of op.points) {
          if (dst.alpha) dst.ctx.clearRect(p.x, p.y, w, h);
          dst.ctx.drawImage(from, fx, fy, w, h, p.x, p.y, w, h);
          dirty(dst, p.x, p.y, Math.min(w, dst.w - p.x), Math.min(h, dst.h - p.y));
        }
        break;
      }
      case TO_CACHE: {
        const s = surfaces.get(op.id);
        const r = s && clip(op.rect, s.w, s.h);
        if (!r) break;
        const w = r.r - r.l, h = r.b - r.t;
        const tile = new OffscreenCanvas(w, h);
        tile.getContext('2d', { alpha: s.alpha }).drawImage(s.canvas, r.l, r.t, w, h, 0, 0, w, h);
        cache.set(op.slot, tile);
        break;
      }
      case FROM_CACHE: {
        const s = surfaces.get(op.id), tile = cache.get(op.slot);
        if (!s || !tile) break;
        for (const p of op.points) {
          if (s.alpha) s.ctx.clearRect(p.x, p.y, tile.width, tile.height);
          s.ctx.drawImage(tile, p.x, p.y);
          dirty(s, p.x, p.y, Math.min(tile.width, s.w - p.x), Math.min(tile.height, s.h - p.y));
        }
        break;
      }
      case EVICT: dropCache(op.slot); break;
      case BITMAP: {
        const s = surfaces.get(op.id);
        if (!s) break;
        const w = op.rect.r - op.rect.l, h = op.rect.b - op.rect.t;
        const pixels = new Uint8ClampedArray(op.data.buffer, op.data.byteOffset, op.data.length);
        s.ctx.putImageData(new ImageData(pixels, w, h), op.rect.l, op.rect.t);
        dirty(s, op.rect.l, op.rect.t, w, h);
        break;
      }
      case AVC420: {
        const s = surfaces.get(op.id), [frame] = op.frames;
        try { if (s && frame) drawPicture(s, frame, op.rects, op.dest); } finally { frame?.close(); }
        break;
      }
      case AVC444: {
        // The main view only: a whole 4:2:0 picture. The auxiliary view, the
        // rest of the colour, is decoded to keep the stream whole, then dropped.
        const s = surfaces.get(op.id), frames = op.frames;
        const main = op.main ? frames[0] : null;
        try { if (s && main) drawPicture(s, main, op.main.rects, op.dest); } finally { for (const f of frames) f?.close(); }
        break;
      }
      case END_FRAME:
        composite();
        framesQueued--;
        stats.frames++;
        if (framesQueued <= 1) for (const resolve of waiters.splice(0)) resolve();
        break;
      case CLOSE: dropSurfaces(); break;
    }
  }

  async function pump() {
    if (pumping) return;
    pumping = true;
    try {
      while (queue.length && !closed) {
        const op = queue[0];
        if (op.wait) await op.wait;
        queue.shift();
        if (closed) { for (const f of op.frames ?? []) f?.close(); break; }
        try { run(op); } catch { stats.errors++; for (const f of op.frames ?? []) f?.close(); }
      }
    } finally {
      pumping = false;
    }
  }

  return {
    stats,
    apply(canvas, bytes) {
      if (closed) throw new Error('the desktop has ended');
      if (!(canvas instanceof HTMLCanvasElement) || !(bytes instanceof Uint8Array) || bytes.length > limits.bytes) throw new Error('graphics batch refused');
      if (canvas !== output) { output = canvas; octx = canvas.getContext('2d'); }
      parse(bytes);
      void pump();
      // Frames behind: the session waits, and reads nothing from Windows
      // meanwhile, so Windows slows down. A decoder holding a picture back
      // must not stop the desktop, hence the time limit.
      if (framesQueued > limits.framesAhead) {
        return new Promise(resolve => {
          waiters.push(resolve);
          setTimeout(() => { stats.stalls++; resolve(); }, limits.waitMs);
        });
      }
      return undefined;
    },
    close() {
      closed = true;
      retireAll();
      for (const op of queue.splice(0)) op.wait?.then(() => { for (const f of op.frames ?? []) f?.close(); });
      dropSurfaces();
      cache.clear();
      for (const resolve of waiters.splice(0)) resolve();
    }
  };
}
