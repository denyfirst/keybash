// The Files page's one way to the server (ADR 0011): a one-use lease from
// /api/remote/files, then the Files socket. Operations go one at a time;
// opening a folder goes ahead of transfers that are still waiting. Every
// reply is checked before the page sees it.

import { endingMessage, remoteErrorMessage } from './remote.mjs';

const CHUNK = 32 * 1024;
const MAX_FILE = 2 * 1024 ** 3;
const MAX_ENTRIES = 10000;
// Upload bytes the socket may hold before the page waits for it to drain.
const QUEUED = 1024 * 1024;
const kinds = new Set(['dir', 'file', 'link', 'other']);
const reasons = new Set(['exists', 'missing', 'denied', 'not-empty', 'too-large', 'not-allowed', 'failed', 'cancelled']);

async function api(path, method = 'GET', body = undefined, csrf = '') {
  const response = await fetch(path, { method, headers: { 'Content-Type': 'application/json', 'X-Keybash-Request': '1', 'X-Keybash-CSRF': csrf }, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (response.status === 503 && response.headers.get('X-Keybash-Capacity') === 'full') throw Object.assign(new Error('capacity'), { code: 'capacity' });
  if (response.status === 429) throw Object.assign(new Error('rate'), { code: 'rate' });
  if (!response.ok || response.headers.get('Content-Type') !== 'application/json; charset=utf-8') throw new Error('refused');
  const text = await response.text();
  if (text.length > 8192) throw new Error('response limit');
  return JSON.parse(text);
}

const fail = reason => Object.assign(new Error(reason), { reason });
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

function entryOK(entry) {
  return entry && typeof entry === 'object' && typeof entry.readable === 'boolean' && typeof entry.name === 'string' &&
    (entry.readable ? entry.name.length > 0 && entry.name.length <= 255 : entry.name === '') &&
    kinds.has(entry.kind) && (entry.target === undefined || (entry.kind === 'link' && (entry.target === 'dir' || entry.target === 'file'))) &&
    Number.isSafeInteger(entry.size) && entry.size >= 0 && Number.isSafeInteger(entry.time) && entry.time >= 0;
}

export async function openFiles(account, { ended }) {
  if (!/^[a-f0-9]{32}$/.test(account)) throw new Error('This page does not name an account.');
  let csrf, lease;
  try {
    const session = await api('/api/session');
    if (session.stage !== 'ready' || !/^[A-Za-z0-9_-]{43}$/.test(session.csrf ?? '')) throw new Error('session refused');
    csrf = session.csrf;
    const granted = await api('/api/remote/files', 'POST', { account }, csrf);
    if (!/^[A-Za-z0-9_-]{43}$/.test(granted.lease ?? '')) throw new Error('lease refused');
    lease = granted.lease;
  } catch (error) {
    throw new Error(remoteErrorMessage(error));
  }

  const socket = new WebSocket(`${location.origin.replace('https:', 'wss:')}/api/remote/files-socket`);
  socket.binaryType = 'arraybuffer';
  let nextID = 1;
  let expected = 1; // the next download frame's sequence
  let current = null; // the operation in flight
  const waiting = [];
  let closed = false;
  let why = null;

  const finish = (operation, error, value) => {
    if (current === operation) current = null;
    if (error) operation.reject(error); else operation.resolve(value);
    pump();
  };
  function pump() {
    if (current || closed || !waiting.length) return;
    const at = waiting.findIndex(operation => operation.message.type === 'list');
    current = waiting.splice(at >= 0 ? at : 0, 1)[0];
    current.start();
  }
  function run(message, extra = {}) {
    return new Promise((resolve, reject) => {
      if (closed) { reject(fail('failed')); return; }
      const operation = { message: { ...message, id: nextID++ }, resolve, reject, entries: [], parts: [], received: 0, ...extra };
      operation.start = () => {
        if (operation.signal?.aborted) { finish(operation, fail('cancelled')); return; }
        socket.send(JSON.stringify(operation.message));
        operation.signal?.addEventListener('abort', () => {
          if (current === operation && !closed) socket.send(JSON.stringify({ type: 'cancel', id: operation.message.id }));
        }, { once: true });
      };
      waiting.push(operation);
      pump();
    });
  }

  async function sendFile(operation) {
    const { file } = operation;
    let sent = 0;
    while (sent < file.size) {
      if (closed || current !== operation || operation.failed) return;
      if (operation.signal?.aborted) return; // the cancel is already on its way
      while (socket.bufferedAmount > QUEUED) { await wait(15); if (closed) return; }
      const piece = await file.slice(sent, Math.min(sent + CHUNK, file.size)).arrayBuffer();
      if (closed || current !== operation || operation.failed || operation.signal?.aborted) return;
      socket.send(piece);
      sent += piece.byteLength;
      operation.progress?.(sent);
    }
  }

  function message(data) {
    if (data.type === 'ended') { why = endingMessage(data.reason); socket.close(); return; }
    const operation = current;
    if (!operation || data.id !== operation.message.id) { socket.close(); return; }
    switch (data.type) {
      case 'entries':
        if (operation.message.type !== 'list' || !Array.isArray(data.entries) || !data.entries.every(entryOK) || operation.entries.length + data.entries.length > MAX_ENTRIES) { socket.close(); return; }
        operation.entries.push(...data.entries);
        return;
      case 'file':
        if (operation.message.type !== 'get' || operation.accepted || !Number.isSafeInteger(data.size) || data.size < 0 || data.size > MAX_FILE) { socket.close(); return; }
        operation.accepted = true;
        operation.size = data.size;
        return;
      case 'accept':
        if (!['put', 'replace'].includes(operation.message.type) || operation.accepted) { socket.close(); return; }
        operation.accepted = true;
        sendFile(operation);
        return;
      case 'done':
        if (operation.message.type === 'list') {
          if (typeof data.path !== 'string' || !data.path.startsWith('/') || data.path.length > 4096) { socket.close(); return; }
          finish(operation, null, { path: data.path, entries: operation.entries });
        } else if (operation.message.type === 'get') {
          if (!operation.accepted || data.size !== operation.received) { socket.close(); return; }
          finish(operation, null, new Blob(operation.parts));
        } else finish(operation, null);
        return;
      case 'failed':
        if (!reasons.has(data.reason)) { socket.close(); return; }
        operation.failed = true;
        finish(operation, fail(data.reason));
        return;
    }
    socket.close();
  }

  function chunk(buffer) {
    // Every frame is acknowledged in order, even one for a download that was
    // just cancelled, so the window stays honest.
    if (buffer.byteLength <= 4 || buffer.byteLength > 4 + CHUNK) { socket.close(); return; }
    const sequence = new DataView(buffer).getUint32(0);
    if (sequence !== expected) { socket.close(); return; }
    expected += 1;
    socket.send(JSON.stringify({ type: 'ack', sequence }));
    const operation = current;
    if (!operation || operation.message.type !== 'get' || !operation.accepted) return;
    operation.received += buffer.byteLength - 4;
    if (operation.received > MAX_FILE) { socket.close(); return; }
    operation.parts.push(new Uint8Array(buffer, 4));
    operation.progress?.(operation.received);
  }

  return new Promise((resolve, reject) => {
    let ready = false;
    const timer = setTimeout(() => socket.close(), 15000);
    socket.onopen = () => socket.send(JSON.stringify({ csrf, lease }));
    socket.onmessage = event => {
      if (typeof event.data !== 'string') {
        if (!ready) { socket.close(); return; }
        chunk(event.data);
        return;
      }
      let data;
      try { data = event.data.length <= 1024 * 1024 ? JSON.parse(event.data) : null; } catch { data = null; }
      if (!data || typeof data !== 'object' || typeof data.type !== 'string') { socket.close(); return; }
      if (ready) { message(data); return; }
      if (data.type === 'ended') { why = endingMessage(data.reason); socket.close(); return; }
      if (data.type !== 'ready' || !['download', 'both'].includes(data.mode) || typeof data.server !== 'string' || typeof data.account !== 'string' || typeof data.host !== 'string' ||
          data.server.length > 160 || data.account.length > 128 || data.host.length > 253) { socket.close(); return; }
      ready = true;
      clearTimeout(timer);
      resolve({
        server: { name: data.server, address: data.host },
        account: data.account,
        mode: data.mode,
        list: path => run({ type: 'list', path }),
        mkdir: path => run({ type: 'mkdir', path }),
        rename: (path, to) => run({ type: 'rename', path, to }),
        remove: path => run({ type: 'remove', path }),
        rmdir: path => run({ type: 'rmdir', path }),
        download: (path, { signal, progress } = {}) => run({ type: 'get', path }, { signal, progress }),
        upload: (path, file, { replace = false, signal, progress } = {}) => {
          if (file.size > MAX_FILE) return Promise.reject(fail('too-large'));
          return run({ type: replace ? 'replace' : 'put', path, size: file.size }, { file, signal, progress });
        },
      });
    };
    socket.onclose = () => {
      clearTimeout(timer);
      closed = true;
      const message = why ?? 'The connection to the server closed.';
      for (const operation of [current, ...waiting.splice(0)]) if (operation) operation.reject(fail('failed'));
      current = null;
      if (ready) ended(message); else reject(new Error(message));
    };
  });
}
