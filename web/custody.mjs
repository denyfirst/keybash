import { systems } from '/systems.mjs';
const $ = id => document.getElementById(id);
let csrf = '', busy = false, secretTimer, pendingDelete = null, remoteEnabled = false, setupRequired = false, role = 'user', pendingPerson = null, pendingServer = null;
let scanned = null, catalog = new Map(), selectedTarget = null, targetGeneration = 0, reviewing = null, reviewGeneration = 0, owned = new Map();
// The page's answer goes where the person is looking: into the open sheet
// that asked, or under the page.
const notice = text => {
  const sheet = [...document.querySelectorAll('dialog[open] .dialog-notice')].at(-1);
  if (sheet) { sheet.textContent = text; $('notice').textContent = ''; } else $('notice').textContent = text;
};
const dialogNotice = text => document.querySelectorAll('.dialog-notice').forEach(el => { el.textContent = text; });
const sections = ['enroll', 'challenge', 'recovery', 'vault'];
const idOK = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
function hideSecret() {
  clearTimeout(secretTimer);
  for (const id of ['revealed-secret', 'revealed-passphrase']) if ($(id)) $(id).value = '';
  if ($('secret-dialog')?.open) $('secret-dialog').close();
}
function clearInputs() {
  document.querySelectorAll('input[type=password], input[autocomplete=one-time-code]').forEach(el => { el.value = ''; });
  for (const id of ['credential-key', 'key-file']) if ($(id)) $(id).value = '';
  document.querySelectorAll('.code-boxes').forEach(box => { box.dataset.filled = '0'; });
}
// The six boxes follow the one field: digits only, the next box lit.
$('enrollment-code')?.addEventListener('input', event => {
  const field = event.target, digits = field.value.replace(/[^0-9]/g, '').slice(0, 6);
  if (field.value !== digits) field.value = digits;
  field.parentElement.dataset.filled = String(digits.length);
});
// The MFA seed, as a QR code and as text, is on screen only while it is
// needed and the page is in view.
const qrOK = rows => Array.isArray(rows) && rows.length >= 21 && rows.length <= 57 && (rows.length - 17) % 4 === 0 && rows.every(row => typeof row === 'string' && row.length === rows.length && /^[01]+$/.test(row));
function hideSeed() {
  if (!$('seed-panel')) return;
  $('seed').replaceChildren(); $('seed-qr').replaceChildren(); $('seed-qr').removeAttribute('viewBox');
  $('seed-panel').hidden = true; $('qr-start').hidden = false; $('seed-panel').querySelector('details').open = false;
}
function showSeed(secret, rows) {
  // One path of dark runs, drawn by DOM calls; four modules of white margin.
  let d = '';
  rows.forEach((row, y) => { for (const run of row.matchAll(/1+/g)) d += `M${run.index} ${y}h${run[0].length}v1h-${run[0].length}z`; });
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', d);
  $('seed-qr').setAttribute('viewBox', `-4 -4 ${rows.length + 8} ${rows.length + 8}`); $('seed-qr').replaceChildren(path);
  $('seed').replaceChildren(...secret.match(/.{4}/g).map(group => { const span = document.createElement('span'); span.textContent = group; return span; }));
  $('qr-start').hidden = true; $('seed-panel').hidden = false;
}
function clearAll() {
  hideSecret(); clearInputs(); closeReview(); hideSeed(); csrf = ''; catalog.clear(); selectedTarget = null; ++targetGeneration; pendingPerson = null; pendingServer = null; scanned = null;
  for (const id of ['account', 'account-name', 'focus-account', 'records', 'connections', 'connection-server', 'people', 'person-code', 'servers', 'server-networks']) if ($(id)) $(id).textContent = '';
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  if ($('recovery-codes')) $('recovery-codes').value = '';
  for (const id of sections) if ($(id)) $(id).hidden = true;
  delete document.body.dataset.stage; delete document.body.dataset.loaded;
}
async function request(path, method = 'GET', value, retried = false) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const headers = { 'X-Keybash-Request': '1' };
    if (method !== 'GET') { headers['Content-Type'] = 'application/json'; headers['X-Keybash-CSRF'] = csrf; }
    const response = await fetch(path, { method, headers, body: value === undefined ? undefined : JSON.stringify(value), credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal });
    // 428: this action needs a factor proved in the last ten minutes. Ask for
    // the code once, then send the same request again.
    if (response.status === 428 && !retried) { clearTimeout(timer); await stepUp(); return request(path, method, value, true); }
    if (!response.ok) throw Object.assign(new Error('request refused'), { status: response.status });
    if (response.status === 204) return null;
    if (response.headers.get('Content-Type') !== 'application/json; charset=utf-8') throw new Error('invalid response');
    const reader = response.body.getReader(); const chunks = []; let size = 0;
    while (true) {
      const { value: part, done } = await reader.read(); if (done) break;
      size += part.byteLength; if (size > 192 * 1024) { await reader.cancel(); throw new Error('response too large'); }
      chunks.push(part);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally { clearTimeout(timer); }
}
// The step-up dialog: the second factor alone renews the fresh window. It
// settles the waiting action's request: resolved after the server accepts a
// code, rejected on cancel or when the session has ended (five wrong codes
// end it, and the person signs in again).
let stepping = null;
function stepUp() {
  if (stepping) return stepping;
  stepping = new Promise((resolve, reject) => {
    const dialog = $('stepup-dialog'), input = $('stepup-code'), submit = $('stepup-submit');
    let sending = false;
    const finish = error => {
      $('stepup-form').removeEventListener('submit', send); $('stepup-cancel').removeEventListener('click', cancel); dialog.removeEventListener('cancel', cancel);
      input.value = ''; $('stepup-error').textContent = ''; if (dialog.open) dialog.close(); stepping = null;
      if (error) reject(error); else resolve();
    };
    async function send(event) {
      event.preventDefault();
      const code = input.value.trim(); input.value = '';
      if (sending || !code) return;
      sending = true; submit.disabled = true; $('stepup-error').textContent = '';
      try { await request('/api/reauth', 'POST', { code }); finish(); return; }
      catch (error) {
        if (error.status === 401) {
          try { await request('/api/session'); }
          catch { finish(Object.assign(new Error('session ended'), { status: 'ended' })); clearAll(); location.replace('/login'); return; }
          $('stepup-error').textContent = 'That code was not accepted. Enter the current code from the app: a code works only once.';
        } else $('stepup-error').textContent = error.status === 429 ? 'Too many attempts. Wait a minute and try again.' : 'The code could not be checked. Check your connection and try again.';
      } finally { sending = false; submit.disabled = false; }
      input.focus();
    }
    function cancel(event) { event?.preventDefault(); finish(Object.assign(new Error('cancelled'), { status: 'cancelled' })); }
    $('stepup-form').addEventListener('submit', send); $('stepup-cancel').addEventListener('click', cancel); dialog.addEventListener('cancel', cancel);
    input.value = ''; $('stepup-error').textContent = ''; submit.disabled = false; dialog.showModal(); input.focus();
  });
  return stepping;
}
function errorMessage(error) {
  hideSecret();
  if (error.status === 'cancelled') return 'Confirmation cancelled. Nothing changed.';
  if (error.status === 'ended') return 'Too many wrong codes: this session was closed. Sign in again.';
  if (error.status === 'code-shape') return 'That code is incomplete: it has 43 letters, digits, - and _. Paste the whole code again.';
  if (error.status === 'setup') return 'The setup code was not accepted. Use the newest one-time code from your administrator: a new code replaces the old one, and a code expires after 72 hours.';
  if (error.status === 'reset') return 'That did not match. Check your username, the newest code from your administrator and the current code on your phone (or a recovery code). A code works once and expires after 72 hours.';
  if (error.status === 'no-phone') return 'They have no phone to confirm a new password with, or they are blocked. Choose “Their phone” or “Both: start over”, or unblock them first.';
  if (error.status === 'invite') return 'The username or code was not accepted. Check both, and use the newest code: a new code replaces the old one, a code works once and expires after 72 hours. If you already chose your password with it, sign in instead.';
  if (error.status === 'taken') return 'That username is already taken. Choose another.';
  if (error.status === 'server-input') return 'Check the address and port: an IP address such as 192.168.1.20, and a port from 1 to 65535.';
  if (error.status === 'outside') return 'That address is outside the networks this Keybash may reach. To allow it, run upgrade.sh with --target-networks on the Keybash server.';
  if (error.status === 'listed') return 'A server at that address and port is already listed.';
  if (error.status === 'changed') return 'The server shows another identity than the one you compared, or it is already listed. Read it again and compare.';
  if (error.status === 'unreachable') return 'No SSH server with an Ed25519 key answered there. Check the address and port, and that the server is on.';
  if (error.status === 'rdp-unreachable') return 'No RDP server answered there. Check the address and port, that the server is on, and that its firewall lets this Keybash in.';
  if (error.status === 'rdp-unfit') return 'An RDP server answered, but Keybash cannot use it: it must require Network Level Authentication and show a current certificate fit for a server.';
  if (error.status === 'print-differs') return 'That is not what the server shows, so nothing changed. Check that you ran the command on this server and copied the whole line. If it still differs, someone may be between Keybash and the server: do not connect.';
  if (error.status === 'print-shape') return 'Paste the whole line the command printed: it starts with SHA256: and has 64 more letters and digits.';
  if (error.status === 'last-admin') return 'At least one administrator must remain.';
  if (error.status === 403) return 'That is not allowed. Reload the page and try again.';
  if (error.status === 428) return 'This needs confirmation with your phone. Try again.';
  if (error.status === 409) return 'The server details changed meanwhile. Reload the page and check again.';
  if (error.status === 429) return 'Too many attempts. Wait a moment.';
  if (error.status === 401) return 'Not accepted, or your session ended. Check the code, and sign in again if needed.';
  if (error.status === 400) return 'That input was not accepted. Check the password, code or key format.';
  return 'That did not go through. Check your connection and reload the page.';
}
async function run(action) {
  if (busy) return;
  busy = true; notice('');
  // The step-up dialog stays usable while the action that opened it waits.
  const buttons = [...document.querySelectorAll('button')].filter(el => !el.closest('#stepup-dialog')); buttons.forEach(el => { el.disabled = true; });
  document.body.dataset.busy = '';
  try { await action(); } catch (error) { notice(errorMessage(error)); }
  finally { busy = false; delete document.body.dataset.busy; buttons.forEach(el => { el.disabled = false; }); updateTrustButtons(); }
}
function bind(id, action) {
  $(id)?.addEventListener('submit', event => { event.preventDefault(); void run(action); });
}
function click(id, action) { $(id)?.addEventListener('click', () => { void run(action); }); }
async function copy(id) {
  const element = $(id), value = element.value ?? element.textContent;
  if (!value) return;
  try { await navigator.clipboard.writeText(value); notice('Copied.'); }
  catch { if (element.select) element.select(); notice('The browser did not allow copying. Select the text and copy it yourself.'); }
}
function showCodes(data) {
  if (!Array.isArray(data?.codes) || data.codes.length !== 10 || !data.codes.every(code => typeof code === 'string' && /^[A-Za-z0-9_-]{22}$/.test(code))) throw new Error('invalid codes');
  clearInputs(); hideSecret(); hideSeed();
  sections.forEach(id => { $(id).hidden = id !== 'recovery'; });
  $('heading').textContent = 'Your recovery codes are ready';
  $('recovery-codes').value = data.codes.join('\n');
}
// A key or password as a row: what it is, who it signs in as, and what can be
// done with it. The secret itself is never part of the row.
function recordRow(record) {
  const row = document.createElement('article'); row.className = 'record'; row.dataset.kind = record.generated ? 'generated' : record.kind;
  const tile = document.createElement('span'); tile.className = 'record-icon'; tile.append(glyph(record.generated ? 'made' : record.kind, 'server-glyph'));
  const titles = document.createElement('div'); titles.className = 'record-titles';
  const name = document.createElement('h3'); name.className = 'record-name'; name.textContent = record.name;
  const meta = document.createElement('p'); meta.className = 'record-meta';
  meta.textContent = `${record.kind === 'ssh-key' ? 'SSH key' : 'Password'} · ${record.username ? `user ${record.username}` : 'no user'}`;
  titles.append(name, meta);
  if (record.generated) { const badge = document.createElement('span'); badge.className = 'record-badge'; badge.textContent = 'Made in Keybash'; titles.append(badge); }
  if (record.fingerprint) {
    const line = document.createElement('p'); line.className = 'record-print';
    const print = document.createElement('code'); print.className = 'fingerprint'; print.textContent = record.fingerprint; print.title = 'Key fingerprint';
    line.append(print); titles.append(line);
  }
  row.append(tile, titles);
  const actions = document.createElement('div'); actions.className = 'record-actions'; row.append(actions);
  return { row, actions };
}
// One sheet asks before anything is deleted or taken away: a key or password,
// a connection, or a person's account or access.
const confirmKinds = {
  credential: { title: 'Delete this key or password?', hint: 'Connections that sign in with it stop working. This cannot be undone.', path: id => `/api/credentials/${id}` },
  connection: { title: 'Delete this connection?', hint: 'The key or password it signs in with stays under Keys & passwords. This cannot be undone.', path: id => `/api/connections/${id}` },
  person: { title: 'Delete this person?', hint: 'Their account goes, with their keys, passwords and connections, and they are signed out at once. This cannot be undone.', path: id => `/api/users/${id}` },
  block: { title: 'Block this person?', hint: 'They are signed out at once and cannot sign in until you unblock them. Their keys and passwords stay.', path: id => `/api/users/${id}/block`, method: 'POST', word: 'Block' },
  newcode: { title: 'Make a new invite code?', hint: 'The earlier code stops working at once. You get a new one to give them.', path: id => `/api/users/${id}/reset`, method: 'POST', word: 'Make new code' },
  server: { title: 'Remove this server?', hint: 'Open sessions to it end at once, and connections to it stop working. People’s keys and passwords stay. This cannot be undone.', path: id => `/api/servers/${id}`, word: 'Remove' },
};
function askConfirm(kind, record) {
  pendingDelete = { kind, id: record.id, name: record.name };
  $('delete-title').textContent = confirmKinds[kind].title; $('delete-hint').textContent = confirmKinds[kind].hint; $('delete-name').textContent = record.name;
  $('confirm-delete').textContent = confirmKinds[kind].word ?? 'Delete';
  $('delete-dialog').showModal();
}
async function loadRecords() {
  const records = await request('/api/credentials');
  if (!Array.isArray(records) || records.length > 256) throw new Error('invalid records');
  $('records').replaceChildren();
  for (const record of records) {
    if (!idOK(record.id) || typeof record.name !== 'string' || !['password', 'ssh-key'].includes(record.kind) || typeof record.username !== 'string' || typeof record.fingerprint !== 'string' || record.generated !== undefined && (record.generated !== true || !publicOK(record.public))) throw new Error('invalid record');
    const { row, actions } = recordRow(record);
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'ghost destructive'; remove.textContent = 'Delete';
    remove.addEventListener('click', () => askConfirm('credential', record));
    // A key made here is never shown; its row offers the install command instead.
    if (record.generated) {
      const install = document.createElement('button'); install.type = 'button'; install.className = 'secondary'; install.textContent = 'Add to server';
      install.addEventListener('click', () => showInstall(record.public));
      actions.append(install, remove); $('records').append(row); continue;
    }
    const reveal = document.createElement('button'); reveal.type = 'button'; reveal.className = 'secondary'; reveal.textContent = 'Show';
    reveal.addEventListener('click', () => { void run(async () => {
      hideSecret();
      const item = await request(`/api/credentials/${record.id}/reveal`, 'POST', {});
      if (item?.id !== record.id || typeof item.secret !== 'string' || item.secret.length > 65536 || typeof item.passphrase !== 'string' || item.passphrase.length > 1024 || typeof item.name !== 'string') throw new Error('invalid secret');
      if (document.visibilityState !== 'visible') return;
      $('secret-title').textContent = item.name; $('revealed-secret').value = item.secret; $('revealed-passphrase').value = item.passphrase;
      $('copy-passphrase').hidden = !item.passphrase; $('revealed-passphrase').hidden = !item.passphrase;
      $('secret-dialog').showModal(); secretTimer = setTimeout(hideSecret, 60000);
    }); });
    actions.append(reveal, remove); $('records').append(row);
  }
  if (!records.length) {
    const start = document.createElement('button'); start.type = 'button'; start.textContent = 'Add your first key or password'; start.addEventListener('click', () => openRecordDialog('password'));
    $('records').append(emptyState('No keys or passwords yet', 'Save a server user’s password or SSH key, or let Keybash make a new SSH key for you.', 'key', start));
  }
  owned = new Map(records.map(record => [record.id, record]));
  if(remoteEnabled){$('connection-credential').replaceChildren();for(const record of records){const option=document.createElement('option');option.value=record.id;option.textContent=`${record.name} · ${record.kind === 'ssh-key' ? 'SSH key' : 'Password'}`;$('connection-credential').append(option);}await loadConnections();}
}
const fingerprintOK = value => typeof value === 'string' && (/^SHA256:[A-Za-z0-9+/]{43}$/.test(value) || /^SHA256:[a-f0-9]{64}$/.test(value));
function updateTrustButtons() {
  if ($('connection-save')) $('connection-save').disabled = busy || !selectedTarget?.available || selectedTarget.id !== $('connection-target').value;
  if ($('trust-save')) $('trust-save').disabled = busy || !reviewing?.target.available;
}
function validateTarget(data, id) {
  if (data?.id !== id || typeof data.name !== 'string' || data.name.length > 160 || !['ssh', 'rdp'].includes(data.protocol) || typeof data.hostname !== 'string' || !/^[a-z0-9.:-]{1,253}$/.test(data.hostname) || !Number.isInteger(data.port) || data.port < 1 || data.port > 65535 || !Array.isArray(data.addresses) || !data.addresses.length || data.addresses.length > 16 || !data.addresses.every(ip => typeof ip === 'string' && /^[a-f0-9:.]{1,45}$/.test(ip)) || typeof data.algorithm !== 'string' || data.algorithm.length > 80 || !fingerprintOK(data.fingerprint) || typeof data.approval !== 'string' || !/^[a-f0-9]{64}$/.test(data.approval) || typeof data.available !== 'boolean') throw new Error('invalid server identity');
  if (catalog.get(id)?.protocol !== data.protocol || data.protocol === 'ssh' && !/^SHA256:[A-Za-z0-9+/]{43}$/.test(data.fingerprint) || data.protocol === 'rdp' && !/^SHA256:[a-f0-9]{64}$/.test(data.fingerprint) ||
    data.unchecked !== undefined && (data.unchecked !== true || data.protocol !== 'rdp')) throw new Error('inconsistent server identity');
  return data;
}
// An IPv6 address is written in brackets before its port.
const hostPort = (host, port) => `${host.includes(':') ? `[${host}]` : host}:${port}`;
function serverText(data) {
  return `Address: ${hostPort(data.hostname, data.port)} · ${data.protocol.toUpperCase()}\nIP: ${data.addresses.join(', ')}\nIdentity (fingerprint): ${data.fingerprint}${data.unchecked ? '\nNot checked: your administrator added this identity without comparing it on the server’s own screen.' : ''}${data.available ? '' : '\nThis server identity cannot be used right now.'}`;
}
async function chooseTarget() {
  const id = $('connection-target').value, generation = ++targetGeneration;
  selectedTarget = null; $('connection-server').textContent = 'Checking the server…'; updateTrustButtons();
  if (!idOK(id)) { $('connection-server').textContent = 'No server is open to you yet. Ask your administrator to let you use one.'; return; }
  try {
    const target = validateTarget(await request(`/api/targets/${id}`), id);
    if (generation !== targetGeneration || $('connection-target').value !== id) return;
    selectedTarget = target; $('connection-server').textContent = serverText(target);
  } finally { updateTrustButtons(); }
}
function closeReview() {
  ++reviewGeneration; reviewing = null;
  if ($('trust-dialog')?.open) $('trust-dialog').close();
  updateTrustButtons();
}
async function openReview(record) {
  closeReview(); const generation = ++reviewGeneration;
  $('trust-title').textContent = record.name; $('trust-server').textContent = 'Checking the server…';
  $('trust-previous').textContent = record.fingerprint ? `Identity you accepted before: ${record.fingerprint}` : 'This connection has no accepted identity yet.';
  $('trust-dialog').showModal(); updateTrustButtons();
  const target = validateTarget(await request(`/api/targets/${record.target}`), record.target);
  if (generation !== reviewGeneration || !$('trust-dialog').open) return;
  reviewing = {record, target}; $('trust-server').textContent = serverText(target); updateTrustButtons();
}
// Icons are drawn with DOM calls, like everything else the page builds.
const svgNS = 'http://www.w3.org/2000/svg';
const icons = {
  ssh: ['M4 5.5h16v13H4z', 'M7.5 10l2.5 2-2.5 2', 'M12 14h4'],
  rdp: ['M3.5 5h17v11h-17z', 'M9 19.5h6', 'M12 16v3.5'],
  play: ['M8.5 6.5v11l9-5.5z'],
  password: ['M5.5 7.5h13a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2z', 'M8 12h.01', 'M12 12h.01', 'M16 12h.01'],
  'ssh-key': ['M4.5 12a3.5 3.5 0 1 0 7 0a3.5 3.5 0 1 0-7 0', 'M11.5 12h9', 'M17 12v3', 'M20 12v2'],
  made: ['M3.5 14a3.5 3.5 0 1 0 7 0a3.5 3.5 0 1 0-7 0', 'M10.5 14h8', 'M15.5 14v2.5', 'M18.5 14v2', 'M17.5 3.5v4', 'M15.5 5.5h4'],
  key: ['M4.5 12a3.5 3.5 0 1 0 7 0a3.5 3.5 0 1 0-7 0', 'M11.5 12h9', 'M17 12v3', 'M20 12v2'],
};
function glyph(name, className) {
  const svg = document.createElementNS(svgNS, 'svg');
  for (const [key, value] of [['viewBox', '0 0 24 24'], ['aria-hidden', 'true'], ['focusable', 'false'], ['class', className]]) svg.setAttribute(key, value);
  for (const d of icons[name]) { const path = document.createElementNS(svgNS, 'path'); path.setAttribute('d', d); svg.append(path); }
  return svg;
}
// A system's mark: its own path in its own colour, or one of ours in line art.
function systemMark(name) {
  const mark = systems[name];
  const svg = document.createElementNS(svgNS, 'svg');
  for (const [key, value] of [['viewBox', '0 0 24 24'], ['aria-hidden', 'true'], ['focusable', 'false'], ['class', mark.path ? 'system-mark' : 'system-mark system-own']]) svg.setAttribute(key, value);
  for (const d of mark.path ? [mark.path] : mark.own) { const path = document.createElementNS(svgNS, 'path'); path.setAttribute('d', d); svg.append(path); }
  return svg;
}
// The tile takes the mark's colour; one too dark or too light for a scheme is
// drawn in ink there instead, so every mark stays visible.
function paintTile(tile, name) {
  const color = systems[name]?.color; tile.dataset.system = name;
  if (!/^#[0-9A-F]{6}$/.test(color ?? '')) return;
  tile.style.setProperty('--mark', color);
  const channel = i => { const c = parseInt(color.slice(i, i + 2), 16) / 255; return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
  const tone = 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
  if (tone < 0.05) tile.dataset.tone = 'dark'; else if (tone < 0.12) tile.dataset.tone = 'dim'; else if (tone > 0.45) tile.dataset.tone = 'light';
}
let pickedSystem = '';
function systemGrid(container, chosen, choose) {
  container.replaceChildren();
  for (const name of Object.keys(systems)) {
    const option = document.createElement('button'); option.type = 'button'; option.className = 'system-option';
    option.setAttribute('aria-pressed', String(name === chosen)); option.title = systems[name].title;
    const tile = document.createElement('span'); tile.className = 'server-icon'; paintTile(tile, name); tile.append(systemMark(name));
    const label = document.createElement('span'); label.className = 'system-label'; label.textContent = systems[name].title;
    option.append(tile, label); option.addEventListener('click', () => choose(name)); container.append(option);
  }
}
function openSystemPicker(record) {
  if (busy) return;
  $('system-title').textContent = `What runs on ${record.name}?`;
  systemGrid($('system-grid'), record.system, name => { void run(async () => {
    await request(`/api/connections/${record.id}/system`, 'POST', { system: name });
    $('system-dialog').close(); await loadConnections();
  }); });
  $('system-dialog').showModal();
}
// An empty page shows what will live there: a small waiting terminal, or a key.
function emptyState(title, text, picture = 'terminal', action) {
  const box = document.createElement('div'); box.className = 'empty-state';
  const art = document.createElement('span'); art.setAttribute('aria-hidden', 'true');
  if (picture === 'terminal') {
    const cursor = document.createElement('span'); cursor.className = 'empty-cursor'; cursor.textContent = '▍';
    art.className = 'empty-art'; art.append('$ ', cursor);
  } else { art.className = 'empty-key'; art.append(glyph('key', 'server-glyph')); }
  box.append(art);
  const heading = document.createElement('p'); heading.className = 'empty-title'; heading.textContent = title;
  const body = document.createElement('p'); body.className = 'hint'; body.textContent = text;
  box.append(heading, body); if (action) box.append(action); return box;
}
const trustWords = { verified: 'Ready', changed: 'Identity changed', stopped: 'Server changed', unverified: 'Needs approval', unavailable: 'Unavailable' };
const trustHelp = { changed: 'The administrator changed this server’s identity. Review it before connecting.', stopped: 'This server now shows a different certificate, so Keybash will not connect and sends it no password. Your administrator can see this and has to check it.', unverified: 'Review and accept this server’s identity before connecting.', unavailable: 'This server is not open to you right now: it was removed, you were taken off it, or its certificate has ended.' };
// A connection as a card: what it is, who it signs in as, whether it is
// ready, and the one action that matters most.
function serverCard(record, target) {
  const card = document.createElement('article'); card.className = 'server-card'; card.dataset.connection = record.id; card.dataset.trust = record.trust;
  const head = document.createElement('div'); head.className = 'server-card-head';
  // The tile shows the system's mark once one is chosen, the protocol until
  // then; it is also the way to choose.
  const tile = document.createElement('button'); tile.type = 'button'; tile.className = 'server-icon';
  tile.title = record.system ? `${systems[record.system]?.title ?? 'System'} · change` : 'Choose the system';
  tile.setAttribute('aria-label', tile.title);
  if (systems[record.system]) { paintTile(tile, record.system); tile.append(systemMark(record.system)); }
  else tile.append(glyph(target?.protocol === 'rdp' ? 'rdp' : 'ssh', 'server-glyph'));
  tile.addEventListener('click', () => openSystemPicker(record));
  const titles = document.createElement('div'); titles.className = 'server-titles';
  const name = document.createElement('h3'); name.className = 'server-name'; name.textContent = record.name;
  const login = owned.get(record.credential);
  const meta = document.createElement('p'); meta.className = 'server-meta'; meta.textContent = `${login ? login.username : 'removed key'} @ ${target ? target.name : 'removed server'}`;
  titles.append(name, meta);
  const state = document.createElement('span'); state.className = 'trust-state pill'; state.dataset.trust = record.trust; state.textContent = trustWords[record.trust];
  head.append(tile, titles, state); card.append(head);
  if (trustHelp[record.trust]) { const help = document.createElement('p'); help.className = 'server-help'; help.textContent = trustHelp[record.trust]; card.append(help); }
  const actions = document.createElement('div'); actions.className = 'server-actions';
  if (target && record.trust === 'verified') {
    const link = document.createElement('a'); link.className = 'connect'; link.href = `/remote/${target.protocol}/${record.id}`; link.target = '_blank'; link.rel = 'noopener'; /* each session in its own tab */
    link.append(glyph('play', 'button-glyph'), 'Connect'); actions.append(link);
  }
  if (target && record.trust !== 'stopped') { const review = document.createElement('button'); review.type = 'button'; review.className = 'secondary'; review.textContent = 'Server identity'; review.addEventListener('click', () => { void run(() => openReview(record)); }); actions.append(review); }
  const remove = document.createElement('button'); remove.textContent = 'Delete'; remove.type = 'button'; remove.className = 'ghost destructive'; remove.addEventListener('click', () => askConfirm('connection', record));
  actions.append(remove); card.append(actions);
  return card;
}
async function loadConnections() {
  const previous = $('connection-target').value;
  selectedTarget = null; ++targetGeneration; updateTrustButtons(); $('connections').replaceChildren();
  const targets = await request('/api/targets'), connections = await request('/api/connections');
  if (!Array.isArray(targets) || targets.length > 256 || !Array.isArray(connections) || connections.length > 128) throw new Error('invalid connections');
  const approved = new Map(), options = document.createDocumentFragment(), rows = document.createDocumentFragment();
  for (const target of targets) {
    if (!idOK(target.id) || approved.has(target.id) || typeof target.name !== 'string' || target.name.length > 160 || !['ssh', 'rdp'].includes(target.protocol)) throw new Error('invalid target');
    approved.set(target.id, target); const option = document.createElement('option'); option.value = target.id; option.textContent = `${target.name} · ${target.protocol.toUpperCase()}`; options.append(option);
  }
  for (const record of connections) {
    if (!idOK(record.id) || typeof record.name !== 'string' || record.name.length > 160 || !idOK(record.target) || !idOK(record.credential) || typeof record.revision !== 'string' || !/^[1-9][0-9]{0,9}$/.test(record.revision) || !['verified', 'changed', 'stopped', 'unverified', 'unavailable'].includes(record.trust) || record.fingerprint !== '' && !fingerprintOK(record.fingerprint) || record.trust === 'verified' && !fingerprintOK(record.fingerprint)) throw new Error('invalid connection');
    rows.append(serverCard(record, approved.get(record.target)));
  }
  catalog = approved; $('connection-target').replaceChildren(options); if (approved.has(previous)) $('connection-target').value = previous; $('connections').replaceChildren(rows);
  // With no connection yet, the first steps say what to do, and which is done.
  const hasRecords = $('connection-credential').options.length > 0;
  $('first-steps').hidden = connections.length > 0; $('first-step-key').dataset.done = String(hasRecords);
  if (!connections.length) {
    let start;
    if (hasRecords) { start = document.createElement('button'); start.type = 'button'; start.textContent = 'Create your first connection'; start.addEventListener('click', () => $('new-connection').click()); }
    $('connections').append(emptyState('No connections yet', hasRecords ? 'Create one to open a terminal on your server.' : 'Add a key or password first, then create a connection.', 'terminal', start));
  }
  await chooseTarget();
}
// One document, four pages: the path picks what a ready session sees. Without
// an operator catalog there is nothing to connect to, so "/" shows the keys.
const pages = {
  connections: { path: '/', panel: 'connections-panel', title: 'Connections', lead: 'Your servers, one click from a terminal.' },
  keys: { path: '/keys', panel: 'records-panel', title: 'Keys & passwords', lead: 'What you sign in to servers with, encrypted on this server.' },
  account: { path: '/account', panel: 'account-panel', title: 'Account', lead: 'Your password, your phone authenticator and your recovery codes.' },
  installation: { path: '/installation', panel: 'installation-panel', title: 'Installation', lead: 'What this copy of Keybash runs, and how to update it.' },
  servers: { path: '/servers', panel: 'servers-panel', title: 'Servers', lead: 'Where people here connect, and who may use each server.' },
  users: { path: '/users', panel: 'users-panel', title: 'Users', lead: 'Who signs in here, and what each person may do.' },
};
// Which pages each role sees, in rail order; the first is where a role lands.
// The server refuses the rest whatever the page shows.
const access = { user: ['connections', 'keys', 'account'], admin: ['connections', 'keys', 'servers', 'users', 'installation', 'account'], auditor: ['servers', 'account'] };
const roleWords = { user: 'User', admin: 'Administrator', auditor: 'Auditor' };
const stateWords = { active: 'Active', setup: 'Setting up phone', invited: 'Invited', expired: 'Code expired', blocked: 'Blocked' };
const codeOK = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
// A one-time code from an administrator or the operator, as pasted: spaces
// around it are dropped, and a code of the wrong shape is refused here, before
// it costs an attempt. Only its field is cleared then, so the passwords typed
// beside it need not be typed again.
function pastedCode(id) {
  const code = $(id).value.trim();
  if (codeOK(code)) return code;
  $(id).value = ''; throw Object.assign(new Error('code shape'), { status: 'code-shape' });
}
// The one-time code for an invite or a reset, shown once to give to the person.
// With the steps that person takes: an invite is accepted with "I have an
// invite"; after a reset they sign in as usual and the phone setup asks for
// the code. Each step is text, with the words they click in bold.
const codeSteps = {
  invite: [['Give them the code apart from their username, for example by phone.'], ['On the Keybash sign-in page they choose ', 'I have an invite', ', enter both and choose their own password.'], ['Then they set up their phone. The code works once and expires in 72 hours.']],
  reset: [['Give them the code by another channel, for example by phone.'], ['They sign in as usual with their own username and password, not with ', 'I have an invite', '.'], ['Keybash then asks for this code and shows a new QR code for their phone. The code works once and expires in 72 hours.']],
  password: [['Give them the code by another channel, for example by phone.'], ['On the Keybash sign-in page they choose ', 'Forgot password?', ' and enter their username, this code and the current code from their phone.'], ['Then they choose a new password. The code works once and expires in 72 hours.']],
};
const codeDialogs = {
  invite: { title: name => `Invite for ${name}`, lead: name => `This code is shown only now. With it, ${name} chooses their own password: you never learn it.`, steps: codeSteps.invite },
  newcode: { title: name => `New invite code for ${name}`, lead: name => `This code is shown only now and replaces the earlier one. With it, ${name} chooses their own password: you never learn it.`, steps: codeSteps.invite },
  reset: { title: name => `New phone code for ${name}`, lead: name => `This code is shown only now. ${name} signs in with their own password, then enters it to set up a new phone. The code alone opens nothing.`, steps: codeSteps.reset },
  password: { title: name => `Password reset code for ${name}`, lead: name => `This code is shown only now. ${name} needs it with the current code on their phone to choose a new password: the code alone opens nothing.`, steps: codeSteps.password },
  restart: { title: name => `New invite for ${name}`, lead: name => `${name}’s keys, passwords and connections were deleted. This code is shown only now; with it, ${name} chooses a new password and sets up a phone.`, steps: codeSteps.invite },
};
// What a person lost decides the reset: a phone keeps the password, a
// password keeps the phone, and losing both starts the account over.
const resetKinds = {
  phone: { path: 'reset', word: 'Make phone code', dialog: 'reset', done: name => `${name}’s phone was reset.` },
  password: { path: 'password', word: 'Make password code', dialog: 'password', done: name => `${name} has a password reset code.` },
  restart: { path: 'restart', word: 'Start over', dialog: 'restart', done: name => `${name} starts over: their keys, passwords and connections were deleted.` },
};
function chooseReset() {
  const kind = document.querySelector('input[name=reset-kind]:checked')?.value;
  if (!Object.hasOwn(resetKinds, kind)) return;
  $('reset-submit').textContent = resetKinds[kind].word; $('reset-submit').classList.toggle('danger', kind === 'restart');
}
function openReset(person) {
  if (busy) return;
  pendingPerson = person; $('reset-title').textContent = `Reset access for ${person.username}`; dialogNotice('');
  document.querySelectorAll('input[name=reset-kind]').forEach(input => { input.checked = input.value === 'phone'; });
  chooseReset(); $('reset-dialog').showModal();
}
function showCode(code, name, kind) {
  if (!codeOK(code) || !Object.hasOwn(codeDialogs, kind)) throw new Error('invalid code');
  const dialog = codeDialogs[kind];
  $('code-title').textContent = dialog.title(name); $('code-lead').textContent = dialog.lead(name);
  $('code-steps').replaceChildren(...dialog.steps.map(parts => {
    const step = document.createElement('li');
    parts.forEach((part, i) => { if (i % 2) { const strong = document.createElement('strong'); strong.textContent = part; step.append(strong); } else step.append(part); });
    return step;
  }));
  $('person-code').textContent = code; $('code-dialog').showModal();
}
function openRole(person) {
  if (busy) return;
  pendingPerson = person; $('role-title').textContent = `Change role for ${person.username}`; dialogNotice('');
  document.querySelectorAll('input[name=person-role]').forEach(input => { input.checked = input.value === person.role; });
  $('role-dialog').showModal();
}
// A person as a row: who, which role, in what state, and what can be done.
// Nothing about their password, phone or keys is ever part of it.
function personRow(person, self) {
  const row = document.createElement('article'); row.className = 'record person'; row.dataset.person = person.id;
  const tile = document.createElement('span'); tile.className = 'record-icon'; tile.setAttribute('aria-hidden', 'true'); tile.textContent = person.username[0];
  const titles = document.createElement('div'); titles.className = 'record-titles';
  const name = document.createElement('h3'); name.className = 'record-name'; name.textContent = person.username;
  const meta = document.createElement('p'); meta.className = 'record-meta'; meta.textContent = roleWords[person.role];
  titles.append(name, meta);
  if (self) { const badge = document.createElement('span'); badge.className = 'record-badge'; badge.textContent = 'You'; titles.append(badge); }
  const state = document.createElement('span'); state.className = 'pill person-state'; state.dataset.state = person.state; state.textContent = stateWords[person.state];
  const actions = document.createElement('div'); actions.className = 'record-actions';
  row.append(tile, titles, state, actions);
  if (self) return row; // your own password and phone are on Account
  const button = (text, style, act) => { const b = document.createElement('button'); b.type = 'button'; b.className = style; b.textContent = text; b.addEventListener('click', act); actions.append(b); };
  const record = { id: person.id, name: person.username };
  button('Change role', 'secondary', () => openRole(person));
  if (person.state === 'blocked') button('Unblock', 'ghost', () => { void run(async () => { await request(`/api/users/${person.id}/unblock`, 'POST', {}); await loadUsers(); notice(`${person.username} can sign in again.`); }); });
  else button('Block', 'ghost', () => askConfirm('block', record));
  const invited = ['invited', 'expired'].includes(person.state);
  if (invited) button('New code', 'ghost', () => askConfirm('newcode', record));
  else button('Reset access…', 'ghost', () => openReset(person));
  button('Delete', 'ghost destructive', () => askConfirm('person', record));
  return row;
}
// Everyone on this installation, as the Users page lists them.
async function loadPeople() {
  const data = await request('/api/users');
  if (!idOK(data?.self) || !Array.isArray(data.accounts) || data.accounts.length > 256) throw new Error('invalid users');
  for (const person of data.accounts) {
    if (!idOK(person.id) || typeof person.username !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(person.username) || !Object.hasOwn(roleWords, person.role) || !Object.hasOwn(stateWords, person.state)) throw new Error('invalid person');
  }
  return data;
}
async function loadUsers() {
  const data = await loadPeople(), rows = document.createDocumentFragment();
  for (const person of data.accounts) rows.append(personRow(person, person.id === data.self));
  $('people').replaceChildren(rows);
}
// The Servers page: each server, where it is, its pinned identity, and who
// may use it. Administrators change it; auditors read it.
const sshPrintOK = value => typeof value === 'string' && /^SHA256:[A-Za-z0-9+/]{43}$/.test(value);
const serverOK = s => idOK(s?.id) && typeof s.name === 'string' && s.name.length <= 160 && ['ssh', 'rdp'].includes(s.protocol) && typeof s.hostname === 'string' && /^[a-z0-9.:-]{1,253}$/.test(s.hostname) &&
  Number.isInteger(s.port) && s.port >= 1 && s.port <= 65535 && Array.isArray(s.addresses) && s.addresses.length >= 1 && s.addresses.length <= 16 && s.addresses.every(ip => typeof ip === 'string' && /^[a-f0-9:.]{1,45}$/.test(ip)) &&
  fingerprintOK(s.fingerprint) && (s.protocol === 'rdp' || sshPrintOK(s.fingerprint)) && typeof s.available === 'boolean' &&
  (s.certificate === undefined || ['current', 'soon', 'expired', 'changed'].includes(s.certificate)) && (s.expires === undefined || Number.isInteger(s.expires)) &&
  (s.unchecked === undefined || s.unchecked === true && s.protocol === 'rdp') &&
  Array.isArray(s.access) && s.access.length <= 256 && s.access.every(idOK) && (s.added_by === undefined || idOK(s.added_by)) && Number.isInteger(s.added);
const serversOK = data => Array.isArray(data?.networks) && data.networks.length <= 64 && data.networks.every(n => typeof n === 'string' && /^[a-f0-9:.]{2,45}\/[0-9]{1,3}$/.test(n)) && typeof data.adding === 'boolean' && typeof data.ssh === 'boolean' && typeof data.rdp === 'boolean' &&
  Array.isArray(data.servers) && data.servers.length <= 256 && data.servers.every(serverOK) && typeof data.names === 'object' && data.names !== null &&
  Object.entries(data.names).every(([id, name]) => idOK(id) && typeof name === 'string' && /^[a-z0-9._-]{1,64}$/.test(name));
// The command an administrator runs on a Windows server: the fingerprint of the
// certificate Remote Desktop uses now. Fixed text, the same for every server.
const windowsCommand = `$t = (Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'").SSLCertificateSHA1Hash; $c = Get-ChildItem Cert:\\LocalMachine -Recurse | Where-Object Thumbprint -eq $t | Select-Object -First 1; 'SHA256:' + -join ([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData) | ForEach-Object { $_.ToString('x2') })`;
for (const id of ['server-command', 'identity-command']) if ($(id)) $(id).textContent = windowsCommand;
click('server-copy', () => copy('server-command'));
click('identity-copy', () => copy('identity-command'));
// The line that command prints, as pasted: the spaces and breaks a terminal may
// add are dropped. Keybash, not the person, compares it with what the server
// shows, and the page is never told that value.
function pastedPrint(id) {
  const value = $(id).value.replace(/\s+/g, '');
  if (/^SHA256:[A-Fa-f0-9]{64}$/.test(value)) return `SHA256:${value.slice(7).toLowerCase()}`;
  throw Object.assign(new Error('print shape'), { status: 'print-shape' });
}
const dayOf = seconds => new Date(seconds * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
const needsChecking = server => server.certificate === 'changed' || server.certificate === 'expired';
// An administrator is told on every page: a mark on the rail and a line above
// the page. There is no mail yet, so this is seen at the next sign-in.
function paintAttention(servers) {
  const needing = role === 'admin' ? servers.filter(needsChecking) : [];
  $('rail-attention').hidden = $('attention').hidden = !needing.length;
  if (!needing.length) return;
  const count = needing.length;
  $('rail-attention').textContent = String(count); $('rail-attention').setAttribute('aria-label', `${count} ${count === 1 ? 'server needs' : 'servers need'} checking`);
  $('attention-text').textContent = count > 1 ? `${count} servers need checking. Nobody can connect to them until you do.` :
    `${needing[0].name} ${needing[0].certificate === 'changed' ? 'shows a different certificate' : 'has a certificate that ended'}. Nobody can connect to it until you check it.`;
  $('attention-open').hidden = location.pathname === '/servers';
}
// On the other pages the same check runs behind the page; failing it changes nothing there.
async function checkAttention() {
  try { const data = await request('/api/servers'); if (serversOK(data)) paintAttention(data.servers); } catch { /* the Servers page itself reports this */ }
}
let people = new Map(), names = new Map(), serverKinds = { ssh: true, rdp: false }, serverProtocol = 'ssh';
async function loadServers() {
  const data = await request('/api/servers');
  if (!serversOK(data)) throw new Error('invalid servers');
  names = new Map(Object.entries(data.names));
  serverKinds = { ssh: data.ssh, rdp: data.rdp };
  // Only an administrator chooses people, so only they need the full list.
  people = role === 'admin' ? new Map((await loadPeople()).accounts.map(person => [person.id, person])) : new Map();
  paintAttention(data.servers);
  $('add-server').hidden = !data.adding;
  const code = text => { const element = document.createElement('code'); element.textContent = text; return element; };
  const option = code('upgrade.sh --target-networks=…');
  if (data.networks.length) $('server-networks').replaceChildren('Servers can be added inside ', ...data.networks.flatMap((n, i) => i ? [', ', code(n)] : [code(n)]), '. To allow other networks, run ', option, ' on the Keybash server.');
  else $('server-networks').replaceChildren('This installation names no networks for servers, so none can be added here. On the Keybash server, run ', option, ' (see Installation).');
  $('server-networks').hidden = role !== 'admin';
  const rows = document.createDocumentFragment();
  for (const server of data.servers) rows.append(serverRow(server));
  $('servers').replaceChildren(rows);
  if (!data.servers.length) $('servers').append(emptyState('No servers yet', role === 'admin' ? 'Add one, then choose who may use it.' : 'An administrator adds servers here.', 'terminal'));
  return data.servers;
}
function serverRow(server) {
  const row = document.createElement('article'); row.className = 'record server-row'; row.dataset.server = server.id;
  const tile = document.createElement('span'); tile.className = 'record-icon'; tile.append(glyph(server.protocol, 'server-glyph'));
  const titles = document.createElement('div'); titles.className = 'record-titles';
  const name = document.createElement('h3'); name.className = 'record-name'; name.textContent = server.name;
  const where = server.addresses.length === 1 && server.addresses[0] === server.hostname ? '' : ` (${server.addresses.join(', ')})`;
  const meta = document.createElement('p'); meta.className = 'record-meta'; meta.textContent = `${server.protocol.toUpperCase()} · ${hostPort(server.hostname, server.port)}${where}`;
  titles.append(name, meta);
  const print = document.createElement('p'); print.className = 'record-print';
  const code = document.createElement('code'); code.className = 'fingerprint'; code.textContent = server.fingerprint; code.title = 'Identity (fingerprint)'; print.append(code);
  const who = document.createElement('p'); who.className = 'server-access';
  const listed = server.access.map(id => names.get(id)).filter(Boolean).sort();
  who.textContent = listed.length ? `Can use it: ${listed.join(', ')}` : 'Nobody can use it yet.';
  titles.append(print, who);
  if (server.certificate === 'current') { const until = document.createElement('p'); until.className = 'server-access'; until.textContent = `Certificate until ${dayOf(server.expires)}`; titles.append(until); }
  const whoChecks = role === 'admin' ? 'you check it' : 'an administrator checks it';
  const said = {
    changed: `It shows a different certificate, usually because Windows renewed its own. Nobody can connect until ${whoChecks}.`,
    expired: `Its certificate ended on ${dayOf(server.expires ?? 0)}. Nobody can connect until ${whoChecks}.`,
    soon: `Its certificate ends on ${dayOf(server.expires ?? 0)}. Windows renews it by itself; Keybash then asks ${role === 'admin' ? 'you' : 'an administrator'} to check the new one.`,
  }[server.certificate] ?? (server.available ? '' : 'Nobody can connect to it now: it is outside the networks this Keybash may reach, or its identity cannot be used.');
  const unchecked = server.unchecked && !needsChecking(server) ? `Added without comparing it on the server’s own screen, so Keybash cannot be sure it is your server. ${role === 'admin' ? 'Check it now to be sure.' : 'An administrator can check it.'}` : '';
  const stateName = needsChecking(server) ? server.certificate : !server.available ? 'unreachable' : server.unchecked ? 'unchecked' : server.certificate === 'soon' ? 'soon' : 'ready';
  const state = document.createElement('span'); state.className = 'pill server-state'; state.dataset.state = stateName;
  state.textContent = { changed: 'Identity changed', expired: 'Certificate ended', unreachable: 'Not reachable', unchecked: 'Not checked', soon: 'Ending soon', ready: 'Ready' }[stateName];
  const actions = document.createElement('div'); actions.className = 'record-actions';
  row.append(tile, titles, state, actions);
  const note = [said, unchecked].filter(Boolean).join(' ');
  if (note) { const help = document.createElement('p'); help.className = 'server-help server-note'; help.textContent = note; row.append(help); }
  if (role !== 'admin') return row;
  const button = (text, style, act) => { const b = document.createElement('button'); b.type = 'button'; b.className = style; b.textContent = text; b.addEventListener('click', act); actions.append(b); };
  const check = () => { void run(() => openIdentity(server)); };
  // What needs doing comes first, and looks like it.
  if (needsChecking(server)) button('Check identity', '', check);
  else if (server.available && server.unchecked) button('Check now', '', check);
  button('Who can use it', 'secondary', () => openAccess(server));
  button('Rename', 'ghost', () => openRename(server));
  if (server.available && !needsChecking(server) && !server.unchecked) button('Check identity', 'ghost', check);
  button('Remove', 'ghost destructive', () => askConfirm('server', server));
  return row;
}
// Why a server request was refused, in the words of the step that asked.
function serverError(error, adding = false, protocol = 'ssh') {
  const rdp = protocol === 'rdp';
  const words = { 400: 'server-input', 403: 'outside', 409: adding ? (rdp ? 'print-differs' : 'changed') : 'listed', 422: 'rdp-unfit', 502: rdp ? 'rdp-unreachable' : 'unreachable' };
  return Object.hasOwn(words, error.status) ? Object.assign(new Error('server refused'), { status: words[error.status] }) : error;
}
function serverStep(checking) {
  const rdp = serverProtocol === 'rdp';
  $('server-check').hidden = !checking || rdp; $('server-paste').hidden = !checking || !rdp;
  $('server-submit').textContent = checking ? 'Add server' : rdp ? 'Continue' : 'Read identity';
  if (!checking) { scanned = null; $('server-print').textContent = ''; $('server-same').checked = false; $('server-answer').value = ''; }
  else if (rdp) serverVerify();
}
// A desktop is checked on its own screen unless the administrator unticks it:
// then the page says what that risks, and the button says what it does.
function serverVerify() {
  const verify = $('server-verify').checked;
  $('server-steps').hidden = !verify; $('server-unchecked').hidden = verify;
  $('server-submit').textContent = verify ? 'Add server' : 'Add without checking';
}
function identityVerify() {
  const verify = $('identity-verify').checked, same = scanned?.same === true;
  $('identity-steps').hidden = !verify; $('identity-unchecked').hidden = verify;
  $('identity-submit').textContent = same ? 'Compare and mark checked' : verify ? 'Compare and accept' : 'Accept without checking';
}
$('server-verify')?.addEventListener('change', () => { serverVerify(); if ($('server-verify').checked) $('server-answer').focus(); });
$('identity-verify')?.addEventListener('change', () => { identityVerify(); if ($('identity-verify').checked) $('identity-answer').focus(); });
// SSH or a desktop: the words and the usual port follow the choice, and a port
// someone typed themselves stays.
function chooseServerKind(protocol) {
  serverProtocol = protocol; const rdp = protocol === 'rdp';
  document.querySelectorAll('#server-kind .segment').forEach(segment => segment.setAttribute('aria-pressed', String(segment.dataset.protocol === protocol)));
  $('server-lead').textContent = rdp ? 'Keybash compares the server’s certificate with a line you bring from the server’s own screen, so nobody in between can pass for it. Nobody can use the server until you choose who may.' : 'Keybash reads the server’s SSH identity, and you compare it on the server’s own console before it is added. Nobody can use the server until you choose who may.';
  $('server-port-label').textContent = rdp ? 'RDP port' : 'SSH port';
  if (['', '22', '3389'].includes($('server-port').value)) $('server-port').value = rdp ? '3389' : '22';
  serverStep(false);
}
document.querySelectorAll('#server-kind .segment').forEach(segment => segment.addEventListener('click', () => { if (!busy) chooseServerKind(segment.dataset.protocol); }));
function openAccess(server) { if (!busy) showAccess(server); }
function showAccess(server) {
  pendingServer = server; $('access-title').textContent = `Who can use ${server.name}?`; dialogNotice('');
  const legend = document.createElement('legend'); legend.textContent = 'People';
  const choices = [...people.values()].filter(person => person.role !== 'auditor').sort((a, b) => a.username.localeCompare(b.username)).map(person => {
    const label = document.createElement('label'); label.className = 'role-option';
    const input = document.createElement('input'); input.type = 'checkbox'; input.value = person.id; input.checked = server.access.includes(person.id);
    const text = document.createElement('span'); text.className = 'role-text';
    const strong = document.createElement('strong'); strong.textContent = person.username;
    const role = document.createElement('span'); role.textContent = roleWords[person.role];
    text.append(strong, role); label.append(input, text); return label;
  });
  $('access-people').replaceChildren(legend, ...choices);
  $('access-dialog').showModal();
}
function openRename(server) {
  if (busy) return;
  pendingServer = server; $('rename-name').value = server.name; dialogNotice(''); $('rename-dialog').showModal(); $('rename-name').focus();
}
// Checking a server's identity reads it again; a different key is accepted
// only after the administrator compares it on the server's console. For a
// desktop the page never learns the new fingerprint: the administrator brings
// it from the server's own screen, so it cannot be accepted without looking.
async function openIdentity(server) {
  const rdp = server.protocol === 'rdp';
  pendingServer = server; scanned = null;
  $('identity-title').textContent = `Identity of ${server.name}`; $('identity-pinned').textContent = server.fingerprint; $('identity-now').textContent = 'Reading the server…';
  $('identity-change').hidden = true; $('identity-paste').hidden = true; $('identity-submit').hidden = true; $('identity-same').checked = false; $('identity-answer').value = ''; dialogNotice(''); $('identity-dialog').showModal();
  let data;
  try { data = await request(`/api/servers/${server.id}/scan`, 'POST', {}); }
  catch (error) { $('identity-now').textContent = 'It could not be read.'; throw serverError(error, false, server.protocol); }
  if (rdp ? typeof data?.same !== 'boolean' || !Number.isInteger(data.expires) : !sshPrintOK(data?.fingerprint) || data.algorithm !== 'ssh-ed25519') throw new Error('invalid identity');
  if (pendingServer !== server || !$('identity-dialog').open) return;
  if (rdp) {
    // What was just read also settles the mark on the page.
    await loadServers();
    if (data.same && server.certificate === 'expired') { $('identity-now').textContent = 'The same certificate, and it has ended. Restart Remote Desktop Services on the server: Windows then makes a new one.'; return; }
    if (data.same && !server.unchecked) { $('identity-now').textContent = 'The same certificate: nothing to do.'; return; }
    // A different certificate is accepted with the check, or without it if the
    // administrator unticks it; an unchecked one that is the same is only ever
    // marked checked, so there the check cannot be unticked.
    scanned = { id: server.id, rdp: true, same: data.same };
    $('identity-now').textContent = data.same ? 'The same certificate, not checked yet.' : 'A different certificate.';
    $('identity-why').textContent = data.same ? 'Keybash kept this certificate without comparing it on the server’s own screen. Compare it now to be sure it is your server.' : 'Usually this means Windows renewed its own certificate, but someone in between would look the same. So check it on the server.';
    $('identity-after').textContent = data.same ? 'If it matches, the server is marked checked. Nothing else changes for anyone.' : 'If it matches, the new identity is pinned. Open sessions to this server end, and each person accepts it on their connection.';
    $('identity-verify').checked = true; $('identity-verify-choice').hidden = data.same; identityVerify();
    $('identity-paste').hidden = false; $('identity-submit').hidden = false; $('identity-answer').focus();
    return;
  }
  if (data.fingerprint === server.fingerprint) { $('identity-now').textContent = `${data.fingerprint}\nThe same: nothing to do.`; return; }
  scanned = { id: server.id, fingerprint: data.fingerprint };
  $('identity-now').textContent = data.fingerprint; $('identity-change').hidden = false; $('identity-submit').textContent = 'Accept new identity'; $('identity-submit').hidden = false;
}
$('add-server')?.addEventListener('click', () => {
  if (busy) return;
  $('server-form').reset(); dialogNotice('');
  $('server-kind').hidden = !(serverKinds.ssh && serverKinds.rdp); $('server-no-rdp').hidden = serverKinds.rdp;
  chooseServerKind(serverKinds.ssh ? 'ssh' : 'rdp');
  $('server-dialog').showModal(); $('server-name').focus();
});
// Changing where the server is after it was read starts the comparison over.
for (const id of ['server-address', 'server-port']) $(id)?.addEventListener('input', () => { if (scanned) serverStep(false); });
$('server-cancel')?.addEventListener('click', () => $('server-dialog').close());
$('server-dialog')?.addEventListener('close', () => serverStep(false));
bind('server-form', async () => {
  const name = $('server-name').value.trim(), address = $('server-address').value.trim().toLowerCase(), port = $('server-port').value.trim(), protocol = serverProtocol, rdp = protocol === 'rdp';
  if (!scanned || scanned.address !== address || scanned.port !== port) {
    let data;
    try { data = await request('/api/servers/scan', 'POST', { protocol, address, port }); }
    catch (error) { throw serverError(error, false, protocol); }
    if (rdp ? !Number.isInteger(data?.expires) : !sshPrintOK(data?.fingerprint) || data.algorithm !== 'ssh-ed25519') throw new Error('invalid identity');
    serverStep(true); scanned = { address, port, fingerprint: data.fingerprint };
    if (rdp) $('server-answer').focus(); else $('server-print').textContent = data.fingerprint;
    return;
  }
  let fingerprint = scanned.fingerprint;
  const unchecked = rdp && !$('server-verify').checked;
  if (rdp) fingerprint = unchecked ? 'unchecked' : pastedPrint('server-answer');
  else if (!$('server-same').checked) { notice('Compare the fingerprint on the server’s console first, then tick “It is the same”.'); return; }
  let made;
  try { made = await request('/api/servers', 'POST', { protocol, name, address, port, fingerprint }); }
  catch (error) { if (error.status === 409 && !rdp) serverStep(false); throw serverError(error, !unchecked, protocol); }
  if (!idOK(made?.id)) throw new Error('invalid server');
  $('server-dialog').close();
  const added = (await loadServers()).find(server => server.id === made.id);
  notice(`${name} was added${unchecked ? ', not checked' : ''}. Nobody can use it yet: choose who may.`);
  if (added) showAccess(added);
});
$('access-cancel')?.addEventListener('click', () => $('access-dialog').close());
$('access-dialog')?.addEventListener('close', () => { pendingServer = null; });
bind('access-form', async () => {
  const server = pendingServer;
  if (!server) return;
  const chosen = new Set([...document.querySelectorAll('#access-people input:checked')].map(input => input.value).filter(idOK));
  for (const id of chosen) if (!server.access.includes(id)) await request(`/api/servers/${server.id}/grant`, 'POST', { account: id });
  for (const id of server.access) if (!chosen.has(id)) await request(`/api/servers/${server.id}/revoke`, 'POST', { account: id });
  $('access-dialog').close(); await loadServers(); notice(`Saved who can use ${server.name}.`);
});
$('rename-cancel')?.addEventListener('click', () => $('rename-dialog').close());
$('rename-dialog')?.addEventListener('close', () => { pendingServer = null; });
bind('rename-form', async () => {
  const server = pendingServer, name = $('rename-name').value.trim();
  if (!server) return;
  if (name !== server.name) await request(`/api/servers/${server.id}/name`, 'POST', { name });
  $('rename-dialog').close(); await loadServers(); notice('Renamed.');
});
$('identity-cancel')?.addEventListener('click', () => $('identity-dialog').close());
$('identity-dialog')?.addEventListener('close', () => { pendingServer = null; scanned = null; });
bind('identity-form', async () => {
  const server = pendingServer, next = scanned;
  if (!server || next?.id !== server.id) return;
  let fingerprint = next.fingerprint;
  const unchecked = next.rdp && !next.same && !$('identity-verify').checked;
  if (next.rdp) fingerprint = unchecked ? 'unchecked' : pastedPrint('identity-answer');
  else if (!$('identity-same').checked) { notice('Compare the fingerprint on the server’s console first, then tick the box.'); return; }
  try { await request(`/api/servers/${server.id}/key`, 'POST', { fingerprint }); }
  catch (error) { throw serverError(error, true, server.protocol); }
  $('identity-dialog').close(); await loadServers();
  notice(next.same ? `${server.name} is checked now.` : `New identity pinned for ${server.name}${unchecked ? ', not checked' : ''}. Open sessions to it were closed; each person accepts it on their connection.`);
});
// What this copy runs and serves comes from the server; the commands on the
// page are fixed text, the same for every installation.
async function loadInstallation() {
  const data = await request('/api/installation');
  if (typeof data?.revision !== 'string' || !/^(?:[0-9a-f]{40})?$/.test(data.revision) || typeof data.built !== 'string' || data.built !== '' && Number.isNaN(Date.parse(data.built)) ||
    typeof data.modified !== 'boolean' || typeof data.ssh !== 'boolean' || typeof data.rdp !== 'boolean' || !Number.isInteger(data.servers) || data.servers < 0 || data.servers > 256) throw new Error('invalid installation');
  if (data.revision) {
    const link = document.createElement('a'); link.href = `https://github.com/denyfirst/keybash/commit/${data.revision}`; link.target = '_blank'; link.rel = 'noopener noreferrer';
    const code = document.createElement('code'); code.textContent = data.revision.slice(0, 7); link.append(code);
    const notes = [];
    if (data.built) notes.push(`built ${new Date(data.built).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' })}`);
    if (data.modified) notes.push('with local changes');
    $('install-version').replaceChildren(link, notes.length ? ` · ${notes.join(' · ')}` : '');
  } else $('install-version').textContent = 'Not recorded in this build.';
  const kinds = data.ssh && data.rdp ? 'SSH and RDP' : data.ssh ? 'SSH' : data.rdp ? 'RDP' : '';
  $('install-serves').textContent = kinds ? `${kinds}, to ${data.servers} ${data.servers === 1 ? 'server' : 'servers'} on the Servers page.` : 'Keys and passwords only: this copy connects to no server.';
  // An installation with RDP is rebuilt with its runtime.
  if (data.rdp && !$('command-build').textContent.endsWith(' --with-rdp')) $('command-build').textContent += ' --with-rdp';
}
function showPage(ready) {
  // Without an operator catalog there is nothing to connect to or manage.
  const allowed = access[role].filter(key => !['connections', 'servers'].includes(key) || remoteEnabled);
  let name = Object.keys(pages).find(key => pages[key].path === location.pathname) ?? 'connections';
  if (!allowed.includes(name)) name = allowed[0];
  for (const [key, page] of Object.entries(pages)) $(page.panel).hidden = !ready || key !== name;
  document.querySelectorAll('.rail-item').forEach(item => {
    if (item.dataset.page === name) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
    item.hidden = !allowed.includes(item.dataset.page);
  });
  $('new-connection').hidden = !ready || name !== 'connections'; $('add-record').hidden = !ready || name !== 'keys'; $('invite-person').hidden = !ready || name !== 'users'; $('add-server').hidden = true; /* shown once the page knows it can add */
  $('topbar-page').textContent = $('rail-page').textContent = ready ? pages[name].title : 'Sign-in';
  $('lead').textContent = ready ? pages[name].lead : ''; $('lead').hidden = !ready;
  if (ready) { $('heading').textContent = pages[name].title; document.title = `Keybash · ${pages[name].title}`; }
  return name;
}
async function loadAccount() {
  const data = await request('/api/session');
  if (typeof data?.username !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(data.username) || typeof data.csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.csrf) || !['enroll', 'challenge', 'ready'].includes(data.stage) || !Object.hasOwn(access, data.role)) throw new Error('invalid session');
  csrf = data.csrf; role = data.role; for (const id of ['account', 'account-name', 'focus-account']) $(id).textContent = data.username; document.body.dataset.stage = data.stage;
  remoteEnabled = data.remote === true;
  setupRequired = data.stage === 'enroll' && data.setup === true; $('setup-proof').hidden = !setupRequired;
  sections.forEach(id => { $(id).hidden = true; });
  $('heading').textContent = data.stage === 'enroll' ? 'Set up your phone' : 'Confirm it’s you';
  const page = showPage(data.stage === 'ready');
  $(data.stage === 'ready' ? 'vault' : data.stage).hidden = false; document.body.dataset.loaded = '';
  // An auditor holds no key or password, so there is none to load.
  if (data.stage === 'ready' && role !== 'auditor') await loadRecords();
  if (data.stage === 'ready' && page === 'installation') await loadInstallation();
  if (data.stage === 'ready' && page === 'users') await loadUsers();
  if (data.stage === 'ready' && page === 'servers') await loadServers();
  else if (data.stage === 'ready' && role === 'admin' && remoteEnabled) void checkAttention();
}
bind('signin', async () => {
  const username = $('username').value, password = $('password').value; clearInputs();
  await request('/api/session', 'POST', { username, password }); location.replace('/');
});
bind('bootstrap', async () => {
  const code = pastedCode('setup-code'), username = $('setup-user').value.trim(), password = $('setup-password').value; clearInputs();
  await request('/api/bootstrap', 'POST', { code, username, password }); location.replace('/');
});
// An invited person chooses their password with the code, then sets up their phone.
bind('claim', async () => {
  const code = pastedCode('claim-code'), username = $('claim-user').value.trim(), password = $('claim-password').value, confirm = $('claim-confirm').value; clearInputs();
  if (password !== confirm) { notice('The passwords don’t match.'); return; }
  try { await request('/api/invite', 'POST', { username, code, password }); }
  catch (error) { throw error.status === 401 ? Object.assign(new Error('invite'), { status: 'invite' }) : error; }
  location.replace('/');
});
// Someone who forgot their password sets a new one with their administrator's
// code and the code on their phone, which also signs them in.
bind('recover', async () => {
  const code = pastedCode('recover-code'), factor = $('recover-phone-code').value.replace(/\s/g, ''), username = $('recover-user').value.trim(), password = $('recover-password').value, confirm = $('recover-confirm').value; clearInputs();
  if (password !== confirm) { notice('The passwords don’t match.'); return; }
  try { await request('/api/password-reset', 'POST', { username, code, factor, password }); }
  catch (error) { throw error.status === 401 ? Object.assign(new Error('reset'), { status: 'reset' }) : error; }
  location.replace('/');
});
// The sign-in page shows one form at a time: sign in, accept an invite, or
// reset a forgotten password.
const signinForms = { signin: ['Sign in', 'username'], claim: ['Accept your invite', 'claim-user'], recover: ['Reset your password', 'recover-user'] };
function showForm(which) {
  clearInputs(); notice('');
  for (const name of Object.keys(signinForms)) $(name).hidden = name !== which;
  $('show-claim').hidden = $('show-recover').hidden = which !== 'signin'; $('show-signin').hidden = which === 'signin';
  $('signin-title').textContent = signinForms[which][0]; document.title = `Keybash · ${signinForms[which][0]}`;
  $(signinForms[which][1]).focus();
}
// On a phone the menu folds behind one button: it opens when asked, and
// Escape or a tap elsewhere folds it again.
function setMenu(open) {
  const toggle = $('menu-toggle'), rail = toggle?.closest('.rail');
  if (!rail) return;
  toggle.setAttribute('aria-expanded', String(open));
  if (open) rail.dataset.open = ''; else delete rail.dataset.open;
}
$('menu-toggle')?.addEventListener('click', () => setMenu($('menu-toggle').getAttribute('aria-expanded') !== 'true'));
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && $('menu-toggle')?.getAttribute('aria-expanded') === 'true') { setMenu(false); $('menu-toggle').focus(); }
});
document.addEventListener('click', event => { if (!event.target.closest?.('.rail')) setMenu(false); });
$('show-claim')?.addEventListener('click', () => showForm('claim'));
$('show-recover')?.addEventListener('click', () => showForm('recover'));
$('show-signin')?.addEventListener('click', () => showForm('signin'));
document.querySelectorAll('input[name=reset-kind]').forEach(input => input.addEventListener('change', chooseReset));
$('reset-cancel')?.addEventListener('click', () => $('reset-dialog').close());
$('reset-dialog')?.addEventListener('close', () => { pendingPerson = null; });
bind('reset-form', async () => {
  const person = pendingPerson, kind = document.querySelector('input[name=reset-kind]:checked')?.value;
  if (!person || !Object.hasOwn(resetKinds, kind)) return;
  let reply;
  try { reply = await request(`/api/users/${person.id}/${resetKinds[kind].path}`, 'POST', {}); }
  catch (error) { throw error.status === 409 ? Object.assign(new Error('conflict'), { status: kind === 'password' ? 'no-phone' : 'last-admin' }) : error; }
  $('reset-dialog').close(); await loadUsers(); showCode(reply?.code, person.username, resetKinds[kind].dialog); notice(resetKinds[kind].done(person.username));
});
$('invite-person')?.addEventListener('click', () => {
  if (busy) return;
  $('invite-form').reset(); dialogNotice(''); $('invite-dialog').showModal(); $('invite-name').focus();
});
$('invite-cancel')?.addEventListener('click', () => $('invite-dialog').close());
bind('invite-form', async () => {
  const username = $('invite-name').value, chosen = document.querySelector('input[name=invite-role]:checked')?.value;
  if (!Object.hasOwn(roleWords, chosen)) return;
  let made;
  try { made = await request('/api/users', 'POST', { username, role: chosen }); }
  catch (error) { throw error.status === 409 ? Object.assign(new Error('taken'), { status: 'taken' }) : error; }
  if (!idOK(made?.id)) throw new Error('invalid invite');
  $('invite-dialog').close(); await loadUsers(); showCode(made.code, username, 'invite');
});
$('role-cancel')?.addEventListener('click', () => $('role-dialog').close());
$('role-dialog')?.addEventListener('close', () => { pendingPerson = null; });
bind('role-form', async () => {
  const person = pendingPerson, chosen = document.querySelector('input[name=person-role]:checked')?.value;
  if (!person || !Object.hasOwn(roleWords, chosen)) return;
  if (chosen !== person.role) {
    try { await request(`/api/users/${person.id}/role`, 'POST', { role: chosen }); }
    catch (error) { throw error.status === 409 ? Object.assign(new Error('last-admin'), { status: 'last-admin' }) : error; }
  }
  $('role-dialog').close(); await loadUsers();
  if (chosen !== person.role) notice(`${person.username} is now ${chosen === 'admin' ? 'an administrator' : chosen === 'auditor' ? 'an auditor' : 'a user'}, from their next sign-in.`);
});
click('copy-code', () => copy('person-code'));
$('close-code')?.addEventListener('click', () => $('code-dialog').close());
$('code-dialog')?.addEventListener('close', () => { $('person-code').textContent = ''; });
click('begin-enroll', async () => {
  // An operator-created account proves its one-time setup code before a seed
  // is shown; a bootstrap or replacement session needs none.
  const body = setupRequired ? { setup: pastedCode('enroll-setup') } : {}; clearInputs();
  let data;
  try { data = await request('/api/mfa/enrollment', 'POST', body); }
  catch (error) { throw setupRequired && error.status === 403 ? Object.assign(new Error('setup'), { status: 'setup' }) : error; }
  setupRequired = false; $('setup-proof').hidden = true;
  if (typeof data?.secret !== 'string' || !/^[A-Z2-7]{32}$/.test(data.secret) || !qrOK(data.qr)) throw new Error('invalid seed');
  if (document.visibilityState !== 'visible') return;
  showSeed(data.secret, data.qr);
});
bind('enrollment', async () => { const code = $('enrollment-code').value; clearInputs(); showCodes(await request('/api/mfa/confirm', 'POST', { code })); });
bind('factor', async () => { const code = $('factor-code').value; clearInputs(); await request('/api/mfa/verify', 'POST', { code }); await loadAccount(); });
// The one line a server needs: append the key's public half for its user.
const publicOK = value => typeof value === 'string' && value.length < 200 && /^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/.test(value);
function showInstall(publicLine) {
  if (!publicOK(publicLine)) return;
  $('install-command').textContent = `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${publicLine}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`;
  $('install-dialog').showModal();
}
bind('generate', async () => {
  const name = $('generate-name').value, username = $('generate-user').value;
  const made = await request('/api/credentials/generate', 'POST', { name, username });
  if (!idOK(made?.id) || !publicOK(made.public)) throw new Error('invalid key');
  $('generate').reset(); $('record-dialog').close(); await loadRecords(); notice('Key made. Now add it to your server.'); showInstall(made.public);
});
// One dialog adds all three kinds: a password, an SSH key, or a key made here.
let recordKind = 'password';
function chooseKind(kind) {
  clearInputs(); recordKind = kind;
  document.querySelectorAll('#record-dialog .segment').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.kind === kind)));
  $('credential').hidden = kind === 'generate'; $('generate').hidden = kind !== 'generate';
  $('key-fields').hidden = kind !== 'ssh-key'; $('password-fields').hidden = kind !== 'password';
}
function openRecordDialog(kind) {
  if (busy) return;
  $('credential').reset(); $('generate').reset(); chooseKind(kind); dialogNotice('');
  $('record-dialog').showModal(); $(kind === 'generate' ? 'generate-name' : 'credential-name').focus();
}
document.querySelectorAll('#record-dialog .segment').forEach(button => button.addEventListener('click', () => { if (!busy) chooseKind(button.dataset.kind); }));
document.querySelectorAll('.record-cancel').forEach(button => button.addEventListener('click', () => $('record-dialog').close()));
$('add-record')?.addEventListener('click', () => openRecordDialog('password'));
$('record-dialog')?.addEventListener('close', () => { clearInputs(); dialogNotice(''); });
$('change-password')?.addEventListener('click', () => { if (busy) return; clearInputs(); dialogNotice(''); $('password-dialog').showModal(); $('current-password').focus(); });
$('password-cancel')?.addEventListener('click', () => $('password-dialog').close());
$('password-dialog')?.addEventListener('close', clearInputs);
click('copy-install', () => copy('install-command'));
$('new-connection')?.addEventListener('click', () => {
  if (busy) return;
  pickedSystem = ''; const choose = name => { pickedSystem = name; systemGrid($('connection-system'), pickedSystem, choose); };
  systemGrid($('connection-system'), pickedSystem, choose); dialogNotice('');
  $('connection-dialog').showModal(); $('connection-name').focus();
});
$('system-cancel')?.addEventListener('click', () => $('system-dialog').close());
$('connection-cancel')?.addEventListener('click', () => $('connection-dialog').close());
$('close-install')?.addEventListener('click', () => $('install-dialog').close());
bind('credential', async () => {
  const kind = recordKind;
  if (!['password', 'ssh-key'].includes(kind)) return;
  const value = { name: $('credential-name').value, kind, username: $('credential-user').value, secret: $(kind === 'password' ? 'credential-password' : 'credential-key').value, passphrase: kind === 'ssh-key' ? $('credential-passphrase').value : '' };
  clearInputs(); await request('/api/credentials', 'POST', value); $('credential').reset(); $('record-dialog').close(); await loadRecords(); notice('Encrypted and saved.');
});
bind('connection', async () => {
  // The approval binds this choice to the identity shown; if the catalog
  // changed meanwhile the server refuses and the page shows the new one.
  const target = selectedTarget;
  if (!target?.available || target.id !== $('connection-target').value || !catalog.has(target.id)) throw new Error('server review missing');
  const made = await request('/api/connections', 'POST', {name: $('connection-name').value, target: target.id, credential: $('connection-credential').value, approval: target.approval});
  if (idOK(made?.id) && systems[pickedSystem]) await request(`/api/connections/${made.id}/system`, 'POST', { system: pickedSystem });
  $('connection-name').value = ''; pickedSystem = ''; if ($('connection-dialog').open) $('connection-dialog').close(); await loadConnections(); notice('Connection saved.');
});
bind('trust-confirm', async () => {
  const current = reviewing;
  if (!current?.target.available) throw new Error('server review missing');
  await request(`/api/connections/${current.record.id}/trust`, 'POST', {approval: current.target.approval, revision: current.record.revision});
  closeReview(); await loadConnections(); notice('New identity accepted. This connection’s earlier sessions were closed.');
});
$('connection-target')?.addEventListener('change', () => { void chooseTarget().catch(error => notice(errorMessage(error))); });
$('cancel-trust')?.addEventListener('click', closeReview);
$('trust-dialog')?.addEventListener('close', closeReview);
$('key-file')?.addEventListener('change', () => { void run(async () => {
  const file = $('key-file').files[0]; $('credential-key').value = ''; if (!file) return;
  if (file.size > 65536) throw Object.assign(new Error('file too large'), { status: 400 });
  const content = await file.text(); $('key-file').value = '';
  if (document.visibilityState === 'visible') $('credential-key').value = content;
}); });
bind('password-change', async () => {
  const password = $('current-password').value, next = $('new-password').value, confirm = $('confirm-password').value; clearInputs();
  if (next !== confirm) { notice('The new passwords don’t match.'); return; }
  await request('/api/password', 'POST', { password, next }); clearAll(); location.replace('/login');
});
click('reset-mfa', async () => { await request('/api/mfa/reset', 'POST', {}); hideSecret(); await loadAccount(); });
click('regenerate-recovery', async () => { showCodes(await request('/api/mfa/recovery', 'POST', {})); });
click('saved-recovery', async () => { $('recovery-codes').value = ''; await loadAccount(); });
const signOut = async () => { hideSecret(); clearInputs(); await request('/api/session', 'DELETE', {}); clearAll(); location.replace('/login'); };
click('logout', signOut); click('focus-logout', signOut);
click('copy-seed', () => copy('seed')); click('copy-recovery', () => copy('recovery-codes'));
for (const name of ['build', 'upgrade']) click(`copy-${name}`, () => copy(`command-${name}`));
click('copy-secret', () => copy('revealed-secret')); click('copy-passphrase', () => copy('revealed-passphrase'));
$('hide-secret')?.addEventListener('click', hideSecret);
$('secret-dialog')?.addEventListener('close', hideSecret);
click('confirm-delete', async () => {
  const { kind, id, name } = pendingDelete ?? {}; pendingDelete = null; $('delete-dialog').close();
  if (!Object.hasOwn(confirmKinds, kind) || !idOK(id)) return;
  const reply = await request(confirmKinds[kind].path(id), confirmKinds[kind].method ?? 'DELETE', {});
  if (kind === 'credential') { hideSecret(); await loadRecords(); notice('Deleted.'); }
  else if (kind === 'connection') { await loadConnections(); notice('Deleted.'); }
  else if (kind === 'server') { await loadServers(); notice(`${name} was removed.`); }
  else {
    await loadUsers();
    if (kind === 'newcode') showCode(reply?.code, name, kind);
    notice(kind === 'person' ? 'Deleted.' : kind === 'block' ? `${name} is blocked and signed out.` : `${name} has a new invite code.`);
  }
});
$('cancel-delete')?.addEventListener('click', () => $('delete-dialog').close());
$('delete-dialog')?.addEventListener('close', () => { pendingDelete = null; });
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') { hideSecret(); clearInputs(); closeReview(); hideSeed(); } });
window.addEventListener('pagehide', clearAll);
window.addEventListener('pageshow', event => { if (event.persisted) { clearAll(); location.reload(); } });
void run(async () => {
  if (document.body.dataset.screen === 'login') {
    const data = await request('/api/setup'); if (typeof data?.initialized !== 'boolean') throw new Error('invalid setup');
    $(data.initialized ? 'signin' : 'bootstrap').hidden = false; $('signin-switch').hidden = !data.initialized;
    if (!data.initialized) { $('signin-title').textContent = 'Set up Keybash'; document.title = 'Keybash · Set up'; }
  } else await loadAccount();
});
setInterval(() => {
  if (busy || !csrf || document.visibilityState !== 'visible' || !$('recovery')?.hidden) return;
  void run(async () => {
    try { const data = await request('/api/session'); if (data.csrf !== csrf) throw new Error('session changed'); }
    catch (error) { hideSecret(); if (error.status === 401) { clearAll(); location.replace('/login'); } else throw error; }
  });
}, 30000);
