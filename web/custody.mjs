import { systems } from '/systems.mjs';
const $ = id => document.getElementById(id);
let csrf = '', busy = false, secretTimer, pendingDelete = null, remoteEnabled = false, setupRequired = false;
let catalog = new Map(), selectedTarget = null, targetGeneration = 0, reviewing = null, reviewGeneration = 0, owned = new Map();
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
  hideSecret(); clearInputs(); closeReview(); hideSeed(); csrf = ''; catalog.clear(); selectedTarget = null; ++targetGeneration;
  for (const id of ['account', 'account-name', 'focus-account', 'records', 'connections', 'connection-server']) if ($(id)) $(id).textContent = '';
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  if ($('recovery-codes')) $('recovery-codes').value = '';
  for (const id of sections) if ($(id)) $(id).hidden = true;
  delete document.body.dataset.stage;
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
  if (error.status === 'setup') return 'The setup code was not accepted. Check the one-time code from your administrator, or ask for a new one if it expired.';
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
  row.append(tile, titles);
  const print = document.createElement('code'); print.className = 'fingerprint'; print.textContent = record.fingerprint; print.title = 'Key fingerprint';
  if (record.fingerprint) row.append(print);
  const actions = document.createElement('div'); actions.className = 'record-actions'; row.append(actions);
  return { row, actions };
}
// One sheet asks before anything is deleted: a key or password, or a connection.
const deleteKinds = {
  credential: { title: 'Delete this key or password?', hint: 'Connections that sign in with it stop working. This cannot be undone.', path: id => `/api/credentials/${id}` },
  connection: { title: 'Delete this connection?', hint: 'The key or password it signs in with stays under Keys & passwords. This cannot be undone.', path: id => `/api/connections/${id}` },
};
function askDelete(kind, record) {
  pendingDelete = { kind, id: record.id };
  $('delete-title').textContent = deleteKinds[kind].title; $('delete-hint').textContent = deleteKinds[kind].hint; $('delete-name').textContent = record.name;
  $('delete-dialog').showModal();
}
async function loadRecords() {
  const records = await request('/api/credentials');
  if (!Array.isArray(records) || records.length > 256) throw new Error('invalid records');
  $('records').replaceChildren();
  for (const record of records) {
    if (!idOK(record.id) || typeof record.name !== 'string' || !['password', 'ssh-key'].includes(record.kind) || typeof record.username !== 'string' || typeof record.fingerprint !== 'string' || record.generated !== undefined && (record.generated !== true || !publicOK(record.public))) throw new Error('invalid record');
    const { row, actions } = recordRow(record);
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'ghost'; remove.textContent = 'Delete';
    remove.addEventListener('click', () => askDelete('credential', record));
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
  if (data?.id !== id || typeof data.name !== 'string' || data.name.length > 160 || !['ssh', 'rdp'].includes(data.protocol) || typeof data.hostname !== 'string' || !/^[a-z0-9.-]{1,253}$/.test(data.hostname) || !Number.isInteger(data.port) || data.port < 1 || data.port > 65535 || !Array.isArray(data.addresses) || !data.addresses.length || data.addresses.length > 16 || !data.addresses.every(ip => typeof ip === 'string' && /^[a-f0-9:.]{1,45}$/.test(ip)) || typeof data.algorithm !== 'string' || data.algorithm.length > 80 || !fingerprintOK(data.fingerprint) || typeof data.approval !== 'string' || !/^[a-f0-9]{64}$/.test(data.approval) || typeof data.available !== 'boolean') throw new Error('invalid server identity');
  if (catalog.get(id)?.protocol !== data.protocol || data.protocol === 'ssh' && !/^SHA256:[A-Za-z0-9+/]{43}$/.test(data.fingerprint) || data.protocol === 'rdp' && !/^SHA256:[a-f0-9]{64}$/.test(data.fingerprint)) throw new Error('inconsistent server identity');
  return data;
}
function serverText(data) {
  return `Address: ${data.hostname}:${data.port} · ${data.protocol.toUpperCase()}\nIP: ${data.addresses.join(', ')}\nIdentity (fingerprint): ${data.fingerprint}${data.available ? '' : '\nThis server identity cannot be used right now.'}`;
}
async function chooseTarget() {
  const id = $('connection-target').value, generation = ++targetGeneration;
  selectedTarget = null; $('connection-server').textContent = 'Checking the server…'; updateTrustButtons();
  if (!idOK(id)) { $('connection-server').textContent = 'Your administrator has not added any servers yet.'; return; }
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
const trustWords = { verified: 'Ready', changed: 'Identity changed', unverified: 'Needs approval', unavailable: 'Unavailable' };
const trustHelp = { changed: 'The administrator changed this server’s identity. Review it before connecting.', unverified: 'Review and accept this server’s identity before connecting.', unavailable: 'This server is not in the administrator’s list right now.' };
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
  if (target) { const review = document.createElement('button'); review.type = 'button'; review.className = 'secondary'; review.textContent = 'Server identity'; review.addEventListener('click', () => { void run(() => openReview(record)); }); actions.append(review); }
  const remove = document.createElement('button'); remove.textContent = 'Delete'; remove.type = 'button'; remove.className = 'ghost'; remove.addEventListener('click', () => askDelete('connection', record));
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
    if (!idOK(record.id) || typeof record.name !== 'string' || record.name.length > 160 || !idOK(record.target) || !idOK(record.credential) || typeof record.revision !== 'string' || !/^[1-9][0-9]{0,9}$/.test(record.revision) || !['verified', 'changed', 'unverified', 'unavailable'].includes(record.trust) || record.fingerprint !== '' && !fingerprintOK(record.fingerprint) || record.trust === 'verified' && !fingerprintOK(record.fingerprint)) throw new Error('invalid connection');
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
// One document, three pages: the path picks what a ready session sees. Without
// an operator catalog there is nothing to connect to, so "/" shows the keys.
const pages = {
  connections: { path: '/', panel: 'connections-panel', title: 'Connections', lead: 'Your servers, one click from a terminal.' },
  keys: { path: '/keys', panel: 'records-panel', title: 'Keys & passwords', lead: 'What you sign in to servers with, encrypted on this server.' },
  account: { path: '/account', panel: 'account-panel', title: 'Account', lead: 'Your password, your phone authenticator and your recovery codes.' },
};
function showPage(ready) {
  let name = Object.keys(pages).find(key => pages[key].path === location.pathname) ?? 'connections';
  if (name === 'connections' && !remoteEnabled) name = 'keys';
  for (const [key, page] of Object.entries(pages)) $(page.panel).hidden = !ready || key !== name;
  document.querySelectorAll('.rail-item').forEach(item => {
    if (item.dataset.page === name) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
    item.hidden = item.dataset.page === 'connections' && !remoteEnabled;
  });
  $('new-connection').hidden = !ready || name !== 'connections'; $('add-record').hidden = !ready || name !== 'keys';
  $('topbar-page').textContent = ready ? pages[name].title : 'Sign-in';
  $('lead').textContent = ready ? pages[name].lead : ''; $('lead').hidden = !ready;
  if (ready) { $('heading').textContent = pages[name].title; document.title = `Keybash · ${pages[name].title}`; }
}
async function loadAccount() {
  const data = await request('/api/session');
  if (typeof data?.username !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(data.username) || typeof data.csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.csrf) || !['enroll', 'challenge', 'ready'].includes(data.stage)) throw new Error('invalid session');
  csrf = data.csrf; for (const id of ['account', 'account-name', 'focus-account']) $(id).textContent = data.username; document.body.dataset.stage = data.stage;
  remoteEnabled = data.remote === true;
  setupRequired = data.stage === 'enroll' && data.setup === true; $('setup-proof').hidden = !setupRequired;
  sections.forEach(id => { $(id).hidden = true; });
  $('heading').textContent = data.stage === 'enroll' ? 'Set up your phone' : 'Confirm it’s you';
  showPage(data.stage === 'ready');
  $(data.stage === 'ready' ? 'vault' : data.stage).hidden = false;
  if (data.stage === 'ready') await loadRecords();
}
bind('signin', async () => {
  const username = $('username').value, password = $('password').value; clearInputs();
  await request('/api/session', 'POST', { username, password }); location.replace('/');
});
bind('bootstrap', async () => {
  const code = $('setup-code').value, username = $('setup-user').value, password = $('setup-password').value; clearInputs();
  await request('/api/bootstrap', 'POST', { code, username, password }); location.replace('/');
});
click('begin-enroll', async () => {
  // An operator-created account proves its one-time setup code before a seed
  // is shown; a bootstrap or replacement session needs none.
  const body = setupRequired ? { setup: $('enroll-setup').value } : {}; clearInputs();
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
click('copy-secret', () => copy('revealed-secret')); click('copy-passphrase', () => copy('revealed-passphrase'));
$('hide-secret')?.addEventListener('click', hideSecret);
$('secret-dialog')?.addEventListener('close', hideSecret);
click('confirm-delete', async () => {
  const { kind, id } = pendingDelete ?? {}; pendingDelete = null; $('delete-dialog').close();
  if (!Object.hasOwn(deleteKinds, kind) || !idOK(id)) return;
  await request(deleteKinds[kind].path(id), 'DELETE', {});
  if (kind === 'credential') { hideSecret(); await loadRecords(); } else await loadConnections();
  notice('Deleted.');
});
$('cancel-delete')?.addEventListener('click', () => $('delete-dialog').close());
$('delete-dialog')?.addEventListener('close', () => { pendingDelete = null; });
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') { hideSecret(); clearInputs(); closeReview(); hideSeed(); } });
window.addEventListener('pagehide', clearAll);
window.addEventListener('pageshow', event => { if (event.persisted) { clearAll(); location.reload(); } });
void run(async () => {
  if (document.body.dataset.screen === 'login') {
    const data = await request('/api/setup'); if (typeof data?.initialized !== 'boolean') throw new Error('invalid setup');
    $(data.initialized ? 'signin' : 'bootstrap').hidden = false;
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
