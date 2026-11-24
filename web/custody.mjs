import { systems } from '/systems.mjs';
const $ = id => document.getElementById(id);
let csrf = '', busy = false, pendingDelete = null, remoteEnabled = false, setupRequired = false, role = 'user', pendingPerson = null, pendingServer = null, scanned = null, self = '';
// The page's answer goes where the person is looking: into the open sheet
// that asked, or under the page.
const notice = text => {
  const sheet = [...document.querySelectorAll('dialog[open] .dialog-notice')].at(-1);
  if (sheet) { sheet.textContent = text; $('notice').textContent = ''; } else $('notice').textContent = text;
};
const dialogNotice = text => document.querySelectorAll('.dialog-notice').forEach(el => { el.textContent = text; });
const sections = ['enroll', 'challenge', 'recovery', 'vault'];
const idOK = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
// A typed password or code leaves the page as soon as it is sent, and when the
// page goes out of view.
function clearInputs() {
  document.querySelectorAll('input[type=password], input[autocomplete=one-time-code]').forEach(el => { el.value = ''; });
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
  clearInputs(); hideSeed(); csrf = ''; pendingPerson = null; pendingServer = null; scanned = null; pendingDelete = null;
  for (const id of ['account', 'account-name', 'focus-account', 'access', 'people', 'person-code', 'servers', 'server-networks', 'server-card', 'accounts', 'person-card', 'person-access', 'key-command', 'server-name-now', 'server-system-now']) if ($(id)) $(id).textContent = '';
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
      size += part.byteLength; if (size > 512 * 1024) { await reader.cancel(); throw new Error('response too large'); }
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
  if (error.status === 'account-taken') return 'This server already has an account with that name. Choose it from the list instead.';
  if (error.status === 'account-full') return 'That was not allowed: a server holds at most 16 accounts, and an auditor signs in to none.';
  if (error.status === 403) return 'That is not allowed. Reload the page and try again.';
  if (error.status === 404) return 'That is not here any more. Reload the page.';
  if (error.status === 428) return 'This needs confirmation with your phone. Try again.';
  if (error.status === 409) return 'The server details changed meanwhile. Reload the page and check again.';
  if (error.status === 429) return 'Too many attempts. Wait a moment.';
  if (error.status === 401) return 'Not accepted, or your session ended. Check the code, and sign in again if needed.';
  if (error.status === 400) return 'That input was not accepted. Check the name and the password.';
  return 'That did not go through. Check your connection and reload the page.';
}
async function run(action) {
  if (busy) return;
  busy = true; notice('');
  // The step-up dialog stays usable while the action that opened it waits.
  const buttons = [...document.querySelectorAll('button')].filter(el => !el.closest('#stepup-dialog')); buttons.forEach(el => { el.disabled = true; });
  document.body.dataset.busy = '';
  try { await action(); } catch (error) { notice(errorMessage(error)); }
  finally { busy = false; delete document.body.dataset.busy; buttons.forEach(el => { el.disabled = false; }); }
}
function bind(id, action) {
  $(id)?.addEventListener('submit', event => { event.preventDefault(); void run(action); });
}
function click(id, action) { $(id)?.addEventListener('click', () => { void run(action); }); }
// A copy says so on the button that made it, for a moment, where the person is
// looking; only a refusal is said in words under the page or the sheet.
const copyWords = new WeakMap(), copyTimers = new WeakMap();
function sayCopied(button) {
  const label = button.querySelector('.copy-label') ?? button;
  if (!copyWords.has(button)) copyWords.set(button, label.textContent);
  clearTimeout(copyTimers.get(button));
  label.textContent = 'Copied'; button.dataset.copied = '';
  copyTimers.set(button, setTimeout(() => { label.textContent = copyWords.get(button); delete button.dataset.copied; }, 1800));
}
async function copy(target, button) {
  const element = typeof target === 'string' ? $(target) : target, value = element?.value ?? element?.textContent;
  if (!value) return;
  try { await navigator.clipboard.writeText(value); if (button) sayCopied(button); else notice('Copied.'); }
  catch { if (element.select) element.select(); notice('The browser did not allow copying. Select the text and copy it yourself.'); }
}
// A command's own Copy, in the head of its box, copies that box's command.
document.addEventListener('click', event => {
  const chip = event.target.closest?.('.copy-chip'), command = chip?.closest('.command-box')?.querySelector('output');
  if (command) void run(() => copy(command, chip));
});
function showCodes(data) {
  if (!Array.isArray(data?.codes) || data.codes.length !== 10 || !data.codes.every(code => typeof code === 'string' && /^[A-Za-z0-9_-]{22}$/.test(code))) throw new Error('invalid codes');
  clearInputs(); hideSeed();
  sections.forEach(id => { $(id).hidden = id !== 'recovery'; });
  $('heading').textContent = 'Your recovery codes are ready';
  $('recovery-codes').value = data.codes.join('\n');
}

// ── Pictures ─────────────────────────────────────────────────────────────
// Icons are drawn with DOM calls, like everything else the page builds.
const svgNS = 'http://www.w3.org/2000/svg';
// Two tones, as on the menu: a soft body ('soft:'), solid marks ('dot:') and lines.
const keyIcon = ['soft:M8 11.4a4.6 4.6 0 1 1 0 9.2a4.6 4.6 0 1 1 0-9.2z', 'dot:M8 14.7a1.3 1.3 0 1 1 0 2.6a1.3 1.3 0 1 1 0-2.6z', 'M11.3 12.7L20 4', 'M16.6 7.4l2.4 2.4', 'M14.3 9.7l1.8 1.8'];
const icons = {
  ssh: ['soft:M5.6 4.5h12.8a2.6 2.6 0 0 1 2.6 2.6v9.8a2.6 2.6 0 0 1-2.6 2.6H5.6A2.6 2.6 0 0 1 3 16.9V7.1a2.6 2.6 0 0 1 2.6-2.6z', 'M3 8.6h18', 'M7 12.2l2.4 2-2.4 2', 'dot:M12.2 15.2h3.4a.6.6 0 0 1 .6.6v.7a.6.6 0 0 1-.6.6h-3.4a.6.6 0 0 1-.6-.6v-.7a.6.6 0 0 1 .6-.6z'],
  rdp: ['soft:M5.4 4h13.2A2.4 2.4 0 0 1 21 6.4v8.2a2.4 2.4 0 0 1-2.4 2.4H5.4A2.4 2.4 0 0 1 3 14.6V6.4A2.4 2.4 0 0 1 5.4 4z', 'M9 20.5h6', 'M12 17v3.5', 'dot:M9.8 7.4l5.6 2.3-2.4.9-.9 2.4z'],
  play: ['dot:M8 6.3v11.4a1.2 1.2 0 0 0 1.8 1l9-5.7a1.2 1.2 0 0 0 0-2L9.8 5.3A1.2 1.2 0 0 0 8 6.3z'],
  password: ['soft:M5 7h14a2.5 2.5 0 0 1 2.5 2.5v5A2.5 2.5 0 0 1 19 17H5a2.5 2.5 0 0 1-2.5-2.5v-5A2.5 2.5 0 0 1 5 7z', 'dot:M7.5 10.7a1.3 1.3 0 1 1 0 2.6a1.3 1.3 0 1 1 0-2.6z', 'dot:M12 10.7a1.3 1.3 0 1 1 0 2.6a1.3 1.3 0 1 1 0-2.6z', 'dot:M16.5 10.7a1.3 1.3 0 1 1 0 2.6a1.3 1.3 0 1 1 0-2.6z'],
  'ssh-key': keyIcon,
  // A key made here, with a spark: it waits to be put on its server.
  made: [...keyIcon, 'dot:M6 2.4l.8 1.9 1.9.8-1.9.8-.8 1.9-.8-1.9-1.9-.8 1.9-.8z'],
  key: keyIcon,
  back: ['M14.5 6l-6 6 6 6'],
  close: ['M7 7l10 10', 'M17 7L7 17'],
};
function glyph(name, className) {
  const svg = document.createElementNS(svgNS, 'svg');
  for (const [key, value] of [['viewBox', '0 0 24 24'], ['aria-hidden', 'true'], ['focusable', 'false'], ['class', className]]) svg.setAttribute(key, value);
  for (const part of icons[name]) {
    const [, tone, d] = part.match(/^(?:(soft|dot):)?(.*)$/);
    const path = document.createElementNS(svgNS, 'path'); path.setAttribute('d', d);
    if (tone) path.setAttribute('class', `g-${tone}`);
    svg.append(path);
  }
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
// A server's tile: the mark an administrator chose, its kind until then.
function serverTile(server, element = 'span') {
  const tile = document.createElement(element); tile.className = 'server-icon';
  if (systems[server.system]) { paintTile(tile, server.system); tile.append(systemMark(server.system)); }
  else tile.append(glyph(server.protocol === 'rdp' ? 'rdp' : 'ssh', 'server-glyph'));
  return tile;
}
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
// Who signs in where, as the prompt it opens to: a terminal's, or a desktop's.
function serverScreen(who, where, protocol) {
  const screen = document.createElement('p'); screen.className = 'server-screen';
  const part = (className, text, hidden) => { const span = document.createElement('span'); span.className = className; span.textContent = text; if (hidden) span.setAttribute('aria-hidden', 'true'); return span; };
  screen.append(part('who', who), part('at', '@'), part('where', where));
  if (protocol === 'rdp') screen.append(part('tail', ' · desktop', true));
  else screen.append(part('tail', ' ~ $ ', true), part('cursor', '▍', true));
  return screen;
}
const make = (tag, className, text) => { const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = text; return element; };
const buttonIn = (parent, text, style, act) => { const b = make('button', style, text); b.type = 'button'; b.addEventListener('click', act); parent.append(b); return b; };
// A link inside the workspace: it changes the page without leaving it.
function pageLink(path, text, className) {
  const link = make('a', className, text); link.href = path; link.dataset.page = '';
  return link;
}
const kindWords = protocol => protocol === 'rdp' ? 'Desktop (RDP)' : 'Terminal (SSH)';
const dayOf = seconds => new Date(seconds * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
// An IPv6 address is written in brackets before its port.
const hostPort = (host, port) => `${host.includes(':') ? `[${host}]` : host}:${port}`;

// ── Your servers: one card per account the person is on ─────────────────
// A row as the page gets it: the account, its server and whether it opens.
// Nothing else, and never a secret, so a row with any other field is refused.
const accessKeys = ['account', 'server', 'name', 'protocol', 'username', 'trust', 'unchecked', 'system'];
const accessRowOK = x => typeof x === 'object' && x !== null && Object.keys(x).every(key => accessKeys.includes(key)) && idOK(x.account) && idOK(x.server) &&
  typeof x.name === 'string' && x.name.length >= 1 && x.name.length <= 160 && ['ssh', 'rdp'].includes(x.protocol) && typeof x.username === 'string' && x.username.length >= 1 && x.username.length <= 128 &&
  ['verified', 'stopped', 'unavailable'].includes(x.trust) && (x.unchecked === undefined || x.unchecked === true && x.protocol === 'rdp') && (x.system === undefined || Object.hasOwn(systems, x.system));
const trustWords = { verified: 'Ready', stopped: 'Server changed', unavailable: 'Unavailable' };
const trustHelp = {
  stopped: 'This server now shows a different certificate, so Keybash will not connect and sends it no password. Your administrator can see this and has to check it.',
  unavailable: 'This server does not open right now: it is outside the networks Keybash may reach, or its certificate has ended. Your administrator can see this.',
};
function accessCard(row) {
  const card = make('article', 'server-card'); card.dataset.account = row.account; card.dataset.trust = row.trust;
  const head = make('div', 'server-card-head'), titles = make('div', 'server-titles');
  titles.append(make('h3', 'server-name', row.name), make('p', 'server-kind', [kindWords(row.protocol), systems[row.system]?.title].filter(Boolean).join(' · ')));
  const state = make('span', 'trust-state pill', trustWords[row.trust]); state.dataset.trust = row.trust;
  head.append(serverTile(row), titles, state); card.append(head, serverScreen(row.username, row.name, row.protocol));
  const help = [trustHelp[row.trust], row.unchecked ? 'Not checked: your administrator added this desktop without comparing it on its own screen.' : ''].filter(Boolean).join(' ');
  if (help) card.append(make('p', 'server-help', help));
  if (row.trust === 'verified') {
    const actions = make('div', 'server-actions');
    // Each session opens in its own tab.
    const link = make('a', 'connect'); link.href = `/remote/${row.protocol}/${row.account}`; link.target = '_blank'; link.rel = 'noopener';
    link.append(glyph('play', 'button-glyph'), 'Connect'); actions.append(link); card.append(actions);
  }
  return card;
}
async function loadAccess() {
  const rows = await request('/api/access');
  if (!Array.isArray(rows) || rows.length > 4096 || !rows.every(accessRowOK) || new Set(rows.map(row => row.account)).size !== rows.length) throw new Error('invalid access');
  $('access').replaceChildren(...rows.map(accessCard));
  if (!rows.length) {
    let start;
    if (role === 'admin') start = pageLink('/servers', 'Open Servers', 'button-link');
    $('access').append(emptyState('No servers yet', role === 'admin' ? 'Put yourself on a server’s account, on the Servers page, to connect from here.' : 'Your administrator gives you servers to use. They appear here, ready to open.', 'terminal', start));
  }
  $('access-foot').textContent = accessFoot[role] ?? '';
}
const accessFoot = {
  admin: 'You are here for each account you are on. Who signs in with an account, you included, is chosen on its server’s page under Servers.',
  user: 'Your administrator chooses which servers and accounts you may use.',
  auditor: 'Auditors connect to no server. Servers shows every server and who signs in with each.',
};

// ── Servers, their accounts and the people on each ───────────────────────
// The Servers page and each server's own page read the same list.
// Administrators change it; auditors read it.
const sshPrintOK = value => typeof value === 'string' && /^SHA256:[A-Za-z0-9+/]{43}$/.test(value);
const fingerprintOK = value => typeof value === 'string' && (sshPrintOK(value) || /^SHA256:[a-f0-9]{64}$/.test(value));
// A key's line for the account's authorized_keys, as Keybash writes it.
const lineOK = value => typeof value === 'string' && value.length < 240 && /^restrict,pty ssh-ed25519 [A-Za-z0-9+/]+={0,2} keybash$/.test(value);
const accountOK = (a, protocol) => typeof a === 'object' && a !== null && idOK(a.id) && typeof a.username === 'string' && a.username.length >= 1 && a.username.length <= 128 &&
  Array.isArray(a.people) && a.people.length <= 256 && a.people.every(idOK) && idOK(a.set_by) && Number.isInteger(a.set) &&
  (a.kind === 'ssh-key' ? protocol === 'ssh' && lineOK(a.line) && sshPrintOK(a.fingerprint) && (a.used === undefined || a.used === true) &&
    (a.next === undefined ? a.next_fingerprint === undefined : lineOK(a.next) && sshPrintOK(a.next_fingerprint) && a.next_fingerprint !== a.fingerprint)
    : a.kind === 'password' && [a.line, a.fingerprint, a.used, a.next, a.next_fingerprint].every(value => value === undefined));
const serverOK = s => idOK(s?.id) && typeof s.name === 'string' && s.name.length <= 160 && ['ssh', 'rdp'].includes(s.protocol) && typeof s.hostname === 'string' && /^[a-z0-9.:-]{1,253}$/.test(s.hostname) &&
  Number.isInteger(s.port) && s.port >= 1 && s.port <= 65535 && Array.isArray(s.addresses) && s.addresses.length >= 1 && s.addresses.length <= 16 && s.addresses.every(ip => typeof ip === 'string' && /^[a-f0-9:.]{1,45}$/.test(ip)) &&
  fingerprintOK(s.fingerprint) && (s.protocol === 'rdp' || sshPrintOK(s.fingerprint)) && typeof s.available === 'boolean' &&
  (s.certificate === undefined || ['current', 'soon', 'expired', 'changed'].includes(s.certificate)) && (s.expires === undefined || Number.isInteger(s.expires)) &&
  (s.unchecked === undefined || s.unchecked === true && s.protocol === 'rdp') && (s.system === undefined || Object.hasOwn(systems, s.system)) &&
  Array.isArray(s.accounts) && s.accounts.length <= 16 && s.accounts.every(a => accountOK(a, s.protocol)) && new Set(s.accounts.map(a => a.id)).size === s.accounts.length &&
  (s.added_by === undefined || idOK(s.added_by)) && Number.isInteger(s.added);
const serversOK = data => Array.isArray(data?.networks) && data.networks.length <= 64 && data.networks.every(n => typeof n === 'string' && /^[a-f0-9:.]{2,45}\/[0-9]{1,3}$/.test(n)) && typeof data.adding === 'boolean' && typeof data.ssh === 'boolean' && typeof data.rdp === 'boolean' &&
  Array.isArray(data.servers) && data.servers.length <= 256 && data.servers.every(serverOK) && typeof data.names === 'object' && data.names !== null &&
  Object.entries(data.names).every(([id, name]) => idOK(id) && typeof name === 'string' && /^[a-z0-9._-]{1,64}$/.test(name));
// What an administrator runs once on the server, as the account people sign in as.
const keyCommand = line => `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${line}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`;
// The command an administrator runs on a Windows server: the fingerprint of the
// certificate Remote Desktop uses now. Fixed text, the same for every server.
const windowsCommand = `$t = (Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'").SSLCertificateSHA1Hash; $c = Get-ChildItem Cert:\\LocalMachine -Recurse | Where-Object Thumbprint -eq $t | Select-Object -First 1; 'SHA256:' + -join ([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData) | ForEach-Object { $_.ToString('x2') })`;
for (const id of ['server-command', 'identity-command']) if ($(id)) $(id).textContent = windowsCommand;
// The line that command prints, as pasted: the spaces and breaks a terminal may
// add are dropped. Keybash, not the person, compares it with what the server
// shows, and the page is never told that value.
function pastedPrint(id) {
  const value = $(id).value.replace(/\s+/g, '');
  if (/^SHA256:[A-Fa-f0-9]{64}$/.test(value)) return `SHA256:${value.slice(7).toLowerCase()}`;
  throw Object.assign(new Error('print shape'), { status: 'print-shape' });
}
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
  $('attention-open').hidden = route.name === 'servers' || route.name === 'server';
}
// On the other pages the same check runs behind the page; failing it changes nothing there.
async function checkAttention() {
  try { const data = await request('/api/servers'); if (serversOK(data)) paintAttention(data.servers); } catch { /* the Servers page itself reports this */ }
}
let people = new Map(), names = new Map(), serverKinds = { ssh: true, rdp: false }, serverProtocol = 'ssh', serverList = [], networks = [], adding = false;
const nameOf = id => id === self ? `${names.get(id) ?? 'you'} (you)` : names.get(id) ?? 'someone since deleted';
// Everyone on this installation, as the People page lists them. Only an
// administrator reads it.
const roleWords = { user: 'User', admin: 'Administrator', auditor: 'Auditor' };
const stateWords = { active: 'Active', setup: 'Setting up phone', invited: 'Invited', expired: 'Code expired', blocked: 'Blocked' };
async function loadPeople() {
  const data = await request('/api/users');
  if (!idOK(data?.self) || !Array.isArray(data.accounts) || data.accounts.length > 256) throw new Error('invalid users');
  for (const person of data.accounts) {
    if (!idOK(person.id) || typeof person.username !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(person.username) || !Object.hasOwn(roleWords, person.role) || !Object.hasOwn(stateWords, person.state)) throw new Error('invalid person');
  }
  people = new Map(data.accounts.map(person => [person.id, person]));
  for (const person of data.accounts) names.set(person.id, person.username);
  return data;
}
async function loadServerList() {
  const data = await request('/api/servers');
  if (!serversOK(data)) throw new Error('invalid servers');
  names = new Map(Object.entries(data.names));
  serverKinds = { ssh: data.ssh, rdp: data.rdp }; networks = data.networks; adding = data.adding; serverList = data.servers;
  // Only an administrator chooses people, so only they need the full list.
  if (role === 'admin') await loadPeople();
  paintAttention(data.servers);
  return data.servers;
}
const serverById = id => serverList.find(server => server.id === id);
// The people who may be put on an account: everyone but auditors, you first.
const eligible = () => [...people.values()].filter(person => person.role !== 'auditor').sort((a, b) => (b.id === self) - (a.id === self) || a.username.localeCompare(b.username));
function accountsLine(server) {
  if (!server.accounts.length) return 'No accounts yet: nobody can connect.';
  const who = new Set(server.accounts.flatMap(a => a.people));
  const list = server.accounts.map(a => a.username).join(', ');
  return `${server.accounts.length === 1 ? 'Account' : `${server.accounts.length} accounts`}: ${list} · ${who.size ? `${who.size} ${who.size === 1 ? 'person signs in' : 'people sign in'}` : 'nobody on them yet'}`;
}
function stateOf(server) {
  const name = needsChecking(server) ? server.certificate : !server.available ? 'unreachable' : server.unchecked ? 'unchecked' : server.certificate === 'soon' ? 'soon' : 'ready';
  const pill = make('span', 'pill server-state', { changed: 'Identity changed', expired: 'Certificate ended', unreachable: 'Not reachable', unchecked: 'Not checked', soon: 'Ending soon', ready: 'Ready' }[name]); pill.dataset.state = name;
  return pill;
}
function serverNote(server) {
  const whoChecks = role === 'admin' ? 'you check it' : 'an administrator checks it';
  const said = {
    changed: `It shows a different certificate, usually because Windows renewed its own. Nobody can connect until ${whoChecks}.`,
    expired: `Its certificate ended on ${dayOf(server.expires ?? 0)}. Nobody can connect until ${whoChecks}.`,
    soon: `Its certificate ends on ${dayOf(server.expires ?? 0)}. Windows renews it by itself; Keybash then asks ${role === 'admin' ? 'you' : 'an administrator'} to check the new one.`,
  }[server.certificate] ?? (server.available ? '' : 'Nobody can connect to it now: it is outside the networks this Keybash may reach, or its identity cannot be used.');
  const unchecked = server.unchecked && !needsChecking(server) ? `Added without comparing it on the server’s own screen, so Keybash cannot be sure it is your server. ${role === 'admin' ? 'Check it now to be sure.' : 'An administrator can check it.'}` : '';
  return [said, unchecked].filter(Boolean).join(' ');
}
// The Servers page: one row per server, with what matters at a glance.
function serverRow(server) {
  const row = make('article', 'record server-row'); row.dataset.server = server.id;
  const titles = make('div', 'record-titles'), name = make('h3', 'record-name');
  name.append(pageLink(`/servers/${server.id}`, server.name, 'record-link'));
  const where = server.addresses.length === 1 && server.addresses[0] === server.hostname ? '' : ` (${server.addresses.join(', ')})`;
  titles.append(name, make('p', 'record-meta', `${kindWords(server.protocol)} · ${hostPort(server.hostname, server.port)}${where}`));
  const accounts = make('p', 'server-access server-accounts', accountsLine(server)); accounts.dataset.empty = String(!server.accounts.length); titles.append(accounts);
  const actions = make('div', 'record-actions');
  row.append(serverTile(server), titles, stateOf(server), actions);
  const note = serverNote(server);
  if (note) row.append(make('p', 'server-help server-note', note));
  // What needs doing comes first, and looks like it.
  if (role === 'admin' && needsChecking(server)) buttonIn(actions, 'Check identity', '', () => { void run(() => openIdentity(server)); });
  actions.append(pageLink(`/servers/${server.id}`, role === 'admin' ? 'Open' : 'View', 'button-link secondary'));
  return row;
}
async function loadServers() {
  const servers = await loadServerList();
  $('add-server').hidden = !adding;
  const code = text => make('code', '', text);
  const option = code('upgrade.sh --target-networks=…');
  if (networks.length) $('server-networks').replaceChildren('Servers can be added inside ', ...networks.flatMap((n, i) => i ? [', ', code(n)] : [code(n)]), '. To allow other networks, run ', option, ' on the Keybash server.');
  else $('server-networks').replaceChildren('This installation names no networks for servers, so none can be added here. On the Keybash server, run ', option, ' (see Installation).');
  $('server-networks').hidden = role !== 'admin';
  $('servers').replaceChildren(...servers.map(serverRow));
  if (!servers.length) $('servers').append(emptyState('No servers yet', role === 'admin' ? 'Add one, then the account people sign in as.' : 'An administrator adds servers here.', 'terminal'));
  return servers;
}

// ── One server's own page ────────────────────────────────────────────────
let shownServer = null;
function serverHead(server) {
  const card = make('article', 'record server-row server-detail'); card.dataset.server = server.id;
  const titles = make('div', 'record-titles');
  const where = server.addresses.length === 1 && server.addresses[0] === server.hostname ? '' : ` (${server.addresses.join(', ')})`;
  titles.append(make('h2', 'record-name', 'Server identity'), make('p', 'record-meta', `${kindWords(server.protocol)} · ${hostPort(server.hostname, server.port)}${where}`));
  const print = make('p', 'record-print'), code = make('code', 'fingerprint', server.fingerprint); code.title = 'Identity (fingerprint)'; print.append(code); titles.append(print);
  titles.append(make('p', 'server-access identity-why', 'Keybash connects only while the server shows this identity.'));
  const facts = [server.certificate === 'current' ? `Certificate until ${dayOf(server.expires)}` : '', server.added_by ? `Added by ${nameOf(server.added_by)} on ${dayOf(server.added)}` : `From the server file, ${dayOf(server.added)}`];
  titles.append(make('p', 'server-access', facts.filter(Boolean).join(' · ')));
  const actions = make('div', 'record-actions');
  card.append(serverTile(server), titles, stateOf(server), actions);
  const note = serverNote(server);
  if (note) card.append(make('p', 'server-help server-note', note));
  if (role !== 'admin') return card;
  const check = () => { void run(() => openIdentity(server)); };
  if (needsChecking(server)) buttonIn(actions, 'Check identity', '', check);
  else if (server.available && server.unchecked) buttonIn(actions, 'Check now', '', check);
  else if (server.available) buttonIn(actions, 'Check identity', 'secondary', check);
  return card;
}
// This server: its name, its picture and removing it, as on the Account page.
function paintSettings(server) {
  $('server-settings').hidden = !server || role !== 'admin';
  if ($('server-settings').hidden) return;
  $('server-name-now').textContent = `${server.name}. Everyone who signs in to it sees this name.`;
  $('server-system-now').textContent = `${systems[server.system]?.title ?? 'Not chosen'}. Only the picture on its cards; Keybash connects the same way.`;
  $('server-system').textContent = systems[server.system] ? 'Change' : 'Choose';
}
$('server-rename')?.addEventListener('click', () => { if (shownServer) openRename(shownServer); });
$('server-system')?.addEventListener('click', () => { if (shownServer) openSystemPicker(shownServer); });
$('server-remove')?.addEventListener('click', () => { if (shownServer) askConfirm('server', { id: shownServer.id, name: shownServer.name }); });
// One account: its name on the server, how Keybash signs in as it, and the
// people who may.
function accountCard(server, account) {
  const card = make('article', 'server-account'); card.dataset.account = account.id; card.dataset.kind = account.kind;
  const head = make('div', 'server-account-head');
  const tile = make('span', 'record-icon'); tile.append(glyph(account.kind === 'password' ? 'password' : account.used ? 'ssh-key' : 'made', 'server-glyph'));
  const titles = make('div', 'record-titles');
  titles.append(make('h3', 'record-name server-account-name', account.username));
  titles.append(make('p', 'record-meta server-account-how', account.kind === 'password' ? 'Password kept by Keybash' : 'Key kept by Keybash'));
  head.append(tile, titles);
  if (account.kind === 'ssh-key') {
    const state = account.next ? 'next' : account.used ? 'set' : 'waiting';
    const pill = make('span', 'pill account-state', { next: 'New key waiting', set: 'Set up', waiting: 'Not set up yet' }[state]); pill.dataset.state = state; head.append(pill);
  }
  card.append(head);
  const who = make('div', 'people-chips'); who.append(make('span', 'chips-label', 'Signs in with it'));
  if (!account.people.length) who.append(make('span', 'chips-none', 'Nobody yet'));
  for (const id of [...account.people].sort((a, b) => nameOf(a).localeCompare(nameOf(b)))) {
    const chip = make('span', 'person-chip'); chip.dataset.person = id;
    chip.append(make('span', 'chip-avatar', (names.get(id) ?? '?')[0]), make('span', 'chip-name', nameOf(id)));
    who.append(chip);
  }
  card.append(who, make('p', 'server-account-set', `Set by ${nameOf(account.set_by)} on ${dayOf(account.set)}`));
  const actions = make('div', 'server-account-actions');
  if (role === 'admin') buttonIn(actions, account.people.length ? 'Change who' : 'Choose who', 'secondary', () => openPeople(server, account));
  if (role === 'admin' && account.kind === 'ssh-key') {
    const [words, style] = account.next ? ['Switch to the new key', ''] : account.used ? ['Replace key', 'ghost'] : ['Put the key on the server', ''];
    buttonIn(actions, words, style, () => showKey(server, account));
  } else if (role === 'admin') buttonIn(actions, 'Change password', 'ghost', () => openSecret(server, account));
  if (role === 'admin') buttonIn(actions, 'Remove', 'ghost destructive', () => askConfirm('account', { id: account.id, name: `${account.username} on ${server.name}`, server: server.id }));
  if (actions.childElementCount) card.append(actions);
  return card;
}
function paintServer(server) {
  shownServer = server ?? null;
  $('accounts').replaceChildren(); $('server-card').replaceChildren();
  $('add-account').hidden = !server || role !== 'admin'; paintSettings(server);
  if (!server) {
    $('heading').textContent = 'Server not found'; $('lead').textContent = 'It was removed, or the address is wrong.';
    return;
  }
  $('heading').textContent = server.name; document.title = `Keybash · ${server.name}`; $('topbar-page').textContent = server.name;
  $('lead').textContent = `${kindWords(server.protocol)}${systems[server.system] ? ` · ${systems[server.system].title}` : ''}`;
  $('server-card').append(serverHead(server));
  $('accounts').append(...server.accounts.map(account => accountCard(server, account)));
  if (!server.accounts.length) {
    let start;
    if (role === 'admin') { start = make('button', '', 'Add the first account'); start.type = 'button'; start.addEventListener('click', () => openAccountForm(server)); }
    $('accounts').append(emptyState('No accounts yet', role === 'admin' ? 'Add the account people sign in to this server as, and who may use it. Until then nobody can connect.' : 'Nobody can connect until an administrator adds an account.', 'key', start));
  }
}
async function loadServerPage(id) {
  await loadServerList();
  paintServer(serverById(id));
}
// After a change the page shows the server as it is now, and an open sheet
// follows it.
async function refreshServer(id) {
  await loadServerList();
  const server = serverById(id);
  if (route.name === 'server' && route.id === id) paintServer(server);
  else if (route.name === 'servers') await loadServers();
  else if (route.name === 'person') paintPerson(people.get(route.id));
  return server;
}

// ── Adding an account ────────────────────────────────────────────────────
let accountServer = null, accountKind = 'ssh-key';
function chooseAccountKind(kind) {
  accountKind = kind;
  document.querySelectorAll('#account-kind .segment').forEach(segment => segment.setAttribute('aria-pressed', String(segment.dataset.kind === kind)));
  $('account-secret-field').hidden = kind !== 'password'; $('account-secret').required = kind === 'password'; $('account-secret').value = '';
  $('account-own-key').hidden = kind !== 'ssh-key'; $('account-own-key').open = false;
  $('account-kind-hint').textContent = kind === 'ssh-key' ? 'Keybash makes a key for this account and keeps it; you put its line on the server once. Nobody ever sees the key, so nobody can take it along.' :
    `${accountServer?.protocol === 'rdp' ? 'A desktop signs in with a password. ' : ''}Typed once here and never shown again. Anyone who already knows it can still sign in without Keybash: when one of them leaves, change it on the server, then here.`;
  $('account-submit').textContent = kind === 'ssh-key' ? 'Make the key' : 'Save the password';
}
document.querySelectorAll('#account-kind .segment').forEach(segment => segment.addEventListener('click', () => { if (!busy) chooseAccountKind(segment.dataset.kind); }));
// People as ticks: everyone who may be put on an account, you first.
function peopleChoices(container, legend, chosen) {
  const choices = eligible().map(person => {
    const label = make('label', 'role-option'), input = make('input'); input.type = 'checkbox'; input.value = person.id; input.checked = chosen.has(person.id);
    const text = make('span', 'role-text'); text.append(make('strong', '', person.id === self ? `${person.username} (you)` : person.username), make('span', '', roleWords[person.role]));
    label.append(input, text); return label;
  });
  container.replaceChildren(make('legend', '', legend), ...choices);
}
function openAccountForm(server, afterAdding = false) {
  if (busy || role !== 'admin') return;
  accountServer = server; dialogNotice(''); $('account-form').reset();
  $('account-title').textContent = `Add an account on ${server.name}`;
  $('account-lead').textContent = afterAdding ? `${server.name} was added. Now the account people sign in as: until it has one, nobody can connect.` :
    'Each account is one way in. People ticked here sign in as it, and never see its key or password.';
  $('account-user-hint').textContent = `The name you type to sign in on ${server.name}, for example ${server.protocol === 'rdp' ? 'Administrator' : 'root or deploy'}. It must already exist there.`;
  $('account-kind').hidden = server.protocol !== 'ssh';
  // Someone alone here is ticked already: there is nobody else to choose.
  const others = eligible();
  peopleChoices($('account-people'), 'Who signs in with it', new Set(others.length === 1 ? [others[0].id] : []));
  chooseAccountKind(server.protocol === 'ssh' ? 'ssh-key' : 'password');
  $('account-dialog').showModal(); $('account-user').focus();
}
$('add-account')?.addEventListener('click', () => { if (shownServer) openAccountForm(shownServer); });
$('account-cancel')?.addEventListener('click', () => $('account-dialog').close());
$('account-dialog')?.addEventListener('close', () => { accountServer = null; $('account-secret').value = ''; });
bind('account-form', async () => {
  const server = accountServer, kind = accountKind;
  if (!server) return;
  const username = $('account-user').value.trim(), secret = kind === 'password' ? $('account-secret').value : '';
  const chosen = [...document.querySelectorAll('#account-people input:checked')].map(input => input.value).filter(idOK);
  $('account-secret').value = '';
  let made;
  try { made = await request(`/api/servers/${server.id}/accounts`, 'POST', { kind, username, secret, people: chosen.join(',') }); }
  catch (error) { throw error.status === 409 ? Object.assign(new Error('taken'), { status: 'account-taken' }) : error.status === 403 ? Object.assign(new Error('full'), { status: 'account-full' }) : error; }
  if (!idOK(made?.id)) throw new Error('invalid account');
  $('account-dialog').close();
  const now = await refreshServer(server.id), account = now?.accounts.find(a => a.id === made.id);
  if (account?.kind === 'ssh-key') { showKey(now, account, true); return; }
  notice(chosen.length ? `${username} on ${server.name} is ready: the people you ticked can connect now.` : `${username} on ${server.name} is saved. Choose who signs in with it.`);
});

// ── A key's line, and replacing the key ──────────────────────────────────
let keyAccount = null;
function showKey(server, account, fresh = false) {
  if (role !== 'admin' || account.kind !== 'ssh-key') return;
  keyAccount = { server: server.id, account: account.id }; dialogNotice('');
  const view = account.next ? 'next' : account.used ? 'replace' : 'put', who = account.username;
  $('key-dialog').dataset.view = view;
  $('key-title').textContent = { put: `${fresh ? 'Now put' : 'Put'} the key on ${server.name}`, replace: `Replace the key for ${who}?`, next: `Switch ${who} to the new key` }[view];
  $('key-lead').textContent = {
    put: `Until its line is there, nobody can sign in as ${who}.`,
    replace: 'Keybash makes a new key. The current one keeps working until you switch, so nobody is cut off. Do this for a fresh key, or if its line came off the server.',
    next: 'The current key keeps working until you switch.',
  }[view];
  $('key-steps').hidden = view === 'replace';
  $('key-step-open').textContent = `On ${server.name}, open a terminal signed in as ${who}.`;
  $('key-step-run').textContent = view === 'next' ? 'Add the new key’s line, once:' : 'Run this once:';
  $('key-command-head').textContent = `Shell on ${server.name}, as ${who}`;
  $('key-command').textContent = view === 'replace' ? '' : keyCommand(view === 'next' ? account.next : account.line);
  $('key-step-end').textContent = view === 'next' ? 'Then use the new key. Keybash destroys the old one, and its line can come off the server.' : 'Connect once from Your servers. This account then shows Set up.';
  $('key-keep').hidden = $('key-switch').hidden = view !== 'next'; $('key-make').hidden = view !== 'replace';
  $('key-close').textContent = { put: 'Done', replace: 'Cancel', next: 'Later' }[view]; $('key-close').className = view === 'put' ? '' : 'secondary';
  if (!$('key-dialog').open) $('key-dialog').showModal();
  $('key-close').focus();
}
// Making a key shows its line next; switching or dropping one ends the task.
async function keyChange(path, method, body, said, stay = false) {
  const at = keyAccount;
  if (!at) return;
  await request(`/api/servers/${at.server}/accounts/${at.account}/${path}`, method, body);
  const server = await refreshServer(at.server), account = server?.accounts.find(a => a.id === at.account);
  if (stay && account && $('key-dialog').open) showKey(server, account); else $('key-dialog').close();
  if (said) notice(said);
}
click('key-make', () => keyChange('next', 'POST', {}, '', true));
// The switch names the key this sheet showed, so a key made again elsewhere
// meanwhile is never switched to unseen.
click('key-switch', async () => {
  const at = keyAccount, account = serverById(at?.server)?.accounts.find(a => a.id === at.account);
  if (!sshPrintOK(account?.next_fingerprint)) return;
  await keyChange('switch', 'POST', { fingerprint: account.next_fingerprint }, `${account.username} uses the new key now. The old key is destroyed: its line can come off the server.`);
});
click('key-keep', () => keyChange('next', 'DELETE', {}, 'The new key was destroyed. The current one stays.'));
$('key-close')?.addEventListener('click', () => $('key-dialog').close());
$('key-dialog')?.addEventListener('close', () => { keyAccount = null; });

// ── A password changed on the server, then here ──────────────────────────
let secretAccount = null;
function openSecret(server, account) {
  if (busy) return;
  secretAccount = { server: server.id, account: account.id, name: `${account.username} on ${server.name}` }; dialogNotice('');
  $('secret-title').textContent = `New password for ${account.username}`; $('secret-new').value = '';
  $('secret-dialog').showModal(); $('secret-new').focus();
}
$('secret-cancel')?.addEventListener('click', () => $('secret-dialog').close());
$('secret-dialog')?.addEventListener('close', () => { secretAccount = null; $('secret-new').value = ''; });
bind('secret-form', async () => {
  const at = secretAccount, secret = $('secret-new').value;
  $('secret-new').value = '';
  if (!at) return;
  await request(`/api/servers/${at.server}/accounts/${at.account}/password`, 'POST', { secret });
  $('secret-dialog').close(); await refreshServer(at.server); notice(`Keybash uses the new password for ${at.name} from the next session on.`);
});

// ── Who signs in with an account ─────────────────────────────────────────
let peopleAccount = null;
function openPeople(server, account) {
  if (busy) return;
  peopleAccount = { server: server.id, account: account.id, had: [...account.people], name: `${account.username} on ${server.name}` }; dialogNotice('');
  $('people-title').textContent = `Who signs in as ${account.username}?`;
  peopleChoices($('people-choices'), 'People', new Set(account.people));
  $('people-dialog').showModal();
}
$('people-cancel')?.addEventListener('click', () => $('people-dialog').close());
$('people-dialog')?.addEventListener('close', () => { peopleAccount = null; });
bind('people-form', async () => {
  const at = peopleAccount;
  if (!at) return;
  const chosen = new Set([...document.querySelectorAll('#people-choices input:checked')].map(input => input.value).filter(idOK));
  const base = `/api/servers/${at.server}/accounts/${at.account}`;
  for (const id of chosen) if (!at.had.includes(id)) await request(`${base}/grant`, 'POST', { person: id });
  for (const id of at.had) if (!chosen.has(id)) await request(`${base}/revoke`, 'POST', { person: id });
  $('people-dialog').close(); await refreshServer(at.server); notice(`Saved who signs in as ${at.name}.`);
});

// ── What runs on a server: the mark on its cards ─────────────────────────
function openSystemPicker(server) {
  if (busy) return;
  $('system-title').textContent = `What runs on ${server.name}?`;
  systemGrid($('system-grid'), server.system, name => { void run(async () => {
    await request(`/api/servers/${server.id}/system`, 'POST', { system: name });
    $('system-dialog').close(); await refreshServer(server.id);
  }); });
  $('system-dialog').showModal();
}
$('system-cancel')?.addEventListener('click', () => $('system-dialog').close());

// ── Adding, renaming and checking a server ───────────────────────────────
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
  $('server-lead').textContent = rdp ? 'Keybash compares the server’s certificate with a line you bring from the server’s own screen, so nobody in between can pass for it. Next you add the account people sign in as.' : 'Keybash reads the server’s SSH identity, and you compare it on the server’s own console before it is added. Next you add the account people sign in as.';
  $('server-port-label').textContent = rdp ? 'RDP port' : 'SSH port';
  if (['', '22', '3389'].includes($('server-port').value)) $('server-port').value = rdp ? '3389' : '22';
  serverStep(false);
}
document.querySelectorAll('#server-kind .segment').forEach(segment => segment.addEventListener('click', () => { if (!busy) chooseServerKind(segment.dataset.protocol); }));
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
    await refreshServer(server.id);
    if (data.same && server.certificate === 'expired') { $('identity-now').textContent = 'The same certificate, and it has ended. Restart Remote Desktop Services on the server: Windows then makes a new one.'; return; }
    if (data.same && !server.unchecked) { $('identity-now').textContent = 'The same certificate: nothing to do.'; return; }
    // A different certificate is accepted with the check, or without it if the
    // administrator unticks it; an unchecked one that is the same is only ever
    // marked checked, so there the check cannot be unticked.
    scanned = { id: server.id, rdp: true, same: data.same };
    $('identity-now').textContent = data.same ? 'The same certificate, not checked yet.' : 'A different certificate.';
    $('identity-why').textContent = data.same ? 'Keybash kept this certificate without comparing it on the server’s own screen. Compare it now to be sure it is your server.' : 'Usually this means Windows renewed its own certificate, but someone in between would look the same. So check it on the server.';
    $('identity-after').textContent = data.same ? 'If it matches, the server is marked checked. Nothing else changes for anyone.' : 'If it matches, the new identity is pinned for everyone. Open sessions to this server end, and new ones use it.';
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
  // Straight on to the server's own page and its first account.
  await go(`/servers/${made.id}`);
  const added = serverById(made.id);
  if (added) { busy = false; openAccountForm(added, true); busy = true; }
  notice(`${name} was added${unchecked ? ', not checked' : ''}.`);
});
$('rename-cancel')?.addEventListener('click', () => $('rename-dialog').close());
$('rename-dialog')?.addEventListener('close', () => { pendingServer = null; });
bind('rename-form', async () => {
  const server = pendingServer, name = $('rename-name').value.trim();
  if (!server) return;
  if (name !== server.name) await request(`/api/servers/${server.id}/name`, 'POST', { name });
  $('rename-dialog').close(); await refreshServer(server.id); notice('Renamed.');
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
  $('identity-dialog').close(); await refreshServer(server.id);
  notice(next.same ? `${server.name} is checked now.` : `New identity pinned for ${server.name}${unchecked ? ', not checked' : ''}. Open sessions to it were closed; new ones use it.`);
});

// ── People ───────────────────────────────────────────────────────────────
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
  restart: { title: name => `New invite for ${name}`, lead: name => `${name}’s password and phone stopped working. This code is shown only now; with it, ${name} chooses a new password and sets up a phone. Their servers stay.`, steps: codeSteps.invite },
};
// What a person lost decides the reset: a phone keeps the password, a
// password keeps the phone, and losing both starts the account over.
const resetKinds = {
  phone: { path: 'reset', word: 'Make phone code', dialog: 'reset', done: name => `${name}’s phone was reset.` },
  password: { path: 'password', word: 'Make password code', dialog: 'password', done: name => `${name} has a password reset code.` },
  restart: { path: 'restart', word: 'Start over', dialog: 'restart', done: name => `${name} starts over with a new invite. Their servers stay.` },
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
    parts.forEach((part, i) => { if (i % 2) step.append(make('strong', '', part)); else step.append(part); });
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
// Where a person signs in: every account that lists them, on every server.
const signInsOf = id => serverList.flatMap(server => server.accounts.filter(account => account.people.includes(id)).map(account => ({ server, account })));
// A person as a row: who, which role, in what state, and where they sign in.
// Nothing about their password or phone is ever part of it.
function personRow(person) {
  const row = make('article', 'record person'); row.dataset.person = person.id;
  const tile = make('span', 'record-icon', person.username[0]); tile.setAttribute('aria-hidden', 'true');
  const titles = make('div', 'record-titles'), name = make('h3', 'record-name');
  name.append(pageLink(`/users/${person.id}`, person.username, 'record-link'));
  titles.append(name, make('p', 'record-meta', roleWords[person.role]));
  if (person.id === self) titles.append(make('span', 'record-badge', 'You'));
  const where = signInsOf(person.id);
  if (remoteEnabled) titles.append(make('p', 'server-access', person.role === 'auditor' ? 'Signs in to no server' : where.length ? `Signs in to ${where.map(({ server, account }) => `${server.name} as ${account.username}`).join(', ')}` : 'No servers yet'));
  const state = make('span', 'pill person-state', stateWords[person.state]); state.dataset.state = person.state;
  const actions = make('div', 'record-actions'); actions.append(pageLink(`/users/${person.id}`, 'Open', 'button-link secondary'));
  row.append(tile, titles, state, actions);
  return row;
}
async function loadUsers() {
  if (remoteEnabled) await loadServerList();
  await loadPeople();
  $('people').replaceChildren(...[...people.values()].map(personRow));
}
// One person's own page: where they sign in, and their access to Keybash.
function paintPerson(person) {
  $('person-card').replaceChildren(); $('person-access').replaceChildren(); $('give-access').hidden = true;
  if (!person) { $('heading').textContent = 'Person not found'; $('lead').textContent = 'They were deleted, or the address is wrong.'; return; }
  $('heading').textContent = person.username; document.title = `Keybash · ${person.username}`; $('topbar-page').textContent = person.username;
  $('lead').textContent = `${roleWords[person.role]} · ${stateWords[person.state]}`;
  const card = make('article', 'record person person-detail'); card.dataset.person = person.id;
  const tile = make('span', 'record-icon', person.username[0]); tile.setAttribute('aria-hidden', 'true');
  const titles = make('div', 'record-titles');
  titles.append(make('h2', 'record-name', 'Access to Keybash'), make('p', 'record-meta', person.id === self ? 'This is you: your own password and phone are on Account.' : 'Their own password and the authenticator on their phone. Nobody else ever sees either.'));
  const state = make('span', 'pill person-state', stateWords[person.state]); state.dataset.state = person.state;
  const actions = make('div', 'record-actions');
  card.append(tile, titles, state, actions);
  if (person.id !== self) {
    const record = { id: person.id, name: person.username };
    buttonIn(actions, 'Change role', 'secondary', () => openRole(person));
    if (person.state === 'blocked') buttonIn(actions, 'Unblock', 'ghost', () => { void run(async () => { await request(`/api/users/${person.id}/unblock`, 'POST', {}); await loadPersonPage(person.id); notice(`${person.username} can sign in again.`); }); });
    else buttonIn(actions, 'Block', 'ghost', () => askConfirm('block', record));
    if (['invited', 'expired'].includes(person.state)) buttonIn(actions, 'New code', 'ghost', () => askConfirm('newcode', record));
    else buttonIn(actions, 'Reset access…', 'ghost', () => openReset(person));
    buttonIn(actions, 'Delete', 'ghost destructive', () => askConfirm('person', record));
  }
  $('person-card').append(card);
  if (!remoteEnabled) return;
  if (person.role === 'auditor') { $('person-access').append(make('p', 'hint', 'Auditors see servers and who may use them, and sign in to none.')); return; }
  $('give-access').hidden = false;
  const where = signInsOf(person.id);
  for (const { server, account } of where) {
    const item = make('article', 'record access-item'); item.dataset.account = account.id;
    const titles = make('div', 'record-titles'), name = make('h3', 'record-name');
    name.append(pageLink(`/servers/${server.id}`, server.name, 'record-link'));
    titles.append(name, make('p', 'record-meta', `as ${account.username} · ${account.kind === 'password' ? 'password kept by Keybash' : 'key kept by Keybash'}`));
    const actions = make('div', 'record-actions');
    buttonIn(actions, 'Take off', 'ghost destructive', () => askConfirm('revoke', { id: account.id, name: `${person.username} as ${account.username} on ${server.name}`, server: server.id, person: person.id }));
    item.append(serverTile(server), titles, actions);
    $('person-access').append(item);
  }
  if (!where.length) {
    const start = make('button', '', 'Give access'); start.type = 'button'; start.addEventListener('click', () => openGive(person));
    $('person-access').append(emptyState('No servers yet', `${person.username} signs in to no server. Give them an account on one.`, 'terminal', start));
  }
}
async function loadPersonPage(id) {
  if (remoteEnabled) await loadServerList(); else await loadPeople();
  paintPerson(people.get(id));
}
// Giving access from a person's page: a server, then one of its accounts.
let givePerson = null;
function paintGive() {
  const server = serverById($('give-server').value), person = givePerson;
  const legend = make('legend', '', 'Account on the server');
  const choices = (server?.accounts ?? []).map((account, i) => {
    const label = make('label', 'role-option'), input = make('input'); input.type = 'radio'; input.name = 'give-account'; input.value = account.id;
    const on = account.people.includes(person.id); input.disabled = on; input.checked = !on && !$('give-accounts').querySelector('input:checked:not(:disabled)') && i === server.accounts.findIndex(a => !a.people.includes(person.id));
    const text = make('span', 'role-text'); text.append(make('strong', '', account.username), make('span', '', on ? `${person.username} is on it already` : account.kind === 'password' ? 'Password kept by Keybash' : 'Key kept by Keybash'));
    label.append(input, text); return label;
  });
  $('give-accounts').replaceChildren(legend, ...choices);
  const none = !server?.accounts.length;
  $('give-none').hidden = !none; $('give-accounts').hidden = none;
  if (none && server) $('give-none').replaceChildren(`${server.name} has no account yet. Add one on `, pageLink(`/servers/${server.id}`, 'its page', ''), '.');
  $('give-submit').disabled = !choices.some(label => label.querySelector('input:not(:disabled)'));
}
function openGive(person) {
  if (busy) return;
  givePerson = person; dialogNotice('');
  $('give-title').textContent = `Give ${person.username} access`;
  $('give-server').replaceChildren(...serverList.map(server => { const option = make('option', '', `${server.name} · ${kindWords(server.protocol)}`); option.value = server.id; return option; }));
  paintGive(); $('give-dialog').showModal(); $('give-server').focus();
}
$('give-server')?.addEventListener('change', paintGive);
$('give-access')?.addEventListener('click', () => { const person = people.get(route.id); if (person) openGive(person); });
$('give-cancel')?.addEventListener('click', () => $('give-dialog').close());
$('give-dialog')?.addEventListener('close', () => { givePerson = null; });
bind('give-form', async () => {
  const person = givePerson, server = serverById($('give-server').value), account = $('give-accounts').querySelector('input:checked:not(:disabled)')?.value;
  if (!person || !server || !idOK(account)) return;
  await request(`/api/servers/${server.id}/accounts/${account}/grant`, 'POST', { person: person.id });
  $('give-dialog').close(); await loadPersonPage(person.id);
  notice(`${person.username} can connect to ${server.name} now.`);
});

// ── One sheet asks before anything is deleted or taken away ─────────────
const confirmKinds = {
  person: { title: 'Delete this person?', hint: 'Their account goes, they are taken off every server account, and they are signed out at once. This cannot be undone.', path: x => `/api/users/${x.id}` },
  block: { title: 'Block this person?', hint: 'They are signed out at once and cannot sign in until you unblock them. Their servers stay.', path: x => `/api/users/${x.id}/block`, method: 'POST', word: 'Block' },
  newcode: { title: 'Make a new invite code?', hint: 'The earlier code stops working at once. You get a new one to give them.', path: x => `/api/users/${x.id}/reset`, method: 'POST', word: 'Make new code' },
  server: { title: 'Remove this server?', hint: 'Open sessions to it end at once, and its accounts go with it: their keys are destroyed and their passwords forgotten. This cannot be undone.', path: x => `/api/servers/${x.id}`, word: 'Remove' },
  account: { title: 'Remove this account?', hint: 'Nobody can sign in as it any more, and open sessions through it end at once. A key is destroyed: take its line off the server too. This cannot be undone.', path: x => `/api/servers/${x.server}/accounts/${x.id}`, word: 'Remove' },
  revoke: { title: 'Take them off this account?', hint: 'Their open sessions through it end at once. You can put them on again later.', path: x => `/api/servers/${x.server}/accounts/${x.id}/revoke`, method: 'POST', body: x => ({ person: x.person }), word: 'Take off' },
};
function askConfirm(kind, record) {
  pendingDelete = { kind, ...record };
  $('delete-title').textContent = confirmKinds[kind].title; $('delete-hint').textContent = confirmKinds[kind].hint; $('delete-name').textContent = record.name;
  $('confirm-delete').textContent = confirmKinds[kind].word ?? 'Delete';
  $('delete-dialog').showModal();
}
click('confirm-delete', async () => {
  const pending = pendingDelete ?? {}; pendingDelete = null; $('delete-dialog').close();
  const kind = confirmKinds[pending.kind];
  if (!kind || !idOK(pending.id) || ['account', 'revoke'].includes(pending.kind) && !idOK(pending.server) || pending.kind === 'revoke' && !idOK(pending.person)) return;
  const reply = await request(kind.path(pending), kind.method ?? 'DELETE', kind.body ? kind.body(pending) : {});
  if (pending.kind === 'server') { await go('/servers'); notice(`${pending.name} was removed.`); }
  else if (pending.kind === 'account') { await refreshServer(pending.server); notice(`${pending.name} was removed.`); }
  else if (pending.kind === 'revoke') { await refreshServer(pending.server); notice(`Taken off: ${pending.name}.`); }
  else if (pending.kind === 'person') { await go('/users'); notice(`${pending.name} was deleted.`); }
  else {
    await reloadPersonOrList(pending.id);
    if (pending.kind === 'newcode') showCode(reply?.code, pending.name, pending.kind);
    notice(pending.kind === 'block' ? `${pending.name} is blocked and signed out.` : `${pending.name} has a new invite code.`);
  }
});
$('cancel-delete')?.addEventListener('click', () => $('delete-dialog').close());
$('delete-dialog')?.addEventListener('close', () => { pendingDelete = null; });
async function reloadPersonOrList(id) { if (route.name === 'person') await loadPersonPage(id); else await loadUsers(); }

// ── Installation ─────────────────────────────────────────────────────────
// What this copy runs and serves comes from the server; the commands on the
// page are fixed text, the same for every installation.
async function loadInstallation() {
  const data = await request('/api/installation');
  if (typeof data?.revision !== 'string' || !/^(?:[0-9a-f]{40})?$/.test(data.revision) || typeof data.built !== 'string' || data.built !== '' && Number.isNaN(Date.parse(data.built)) ||
    typeof data.modified !== 'boolean' || typeof data.ssh !== 'boolean' || typeof data.rdp !== 'boolean' || !Number.isInteger(data.servers) || data.servers < 0 || data.servers > 256) throw new Error('invalid installation');
  if (data.revision) {
    const link = document.createElement('a'); link.href = `https://github.com/denyfirst/keybash/commit/${data.revision}`; link.target = '_blank'; link.rel = 'noopener noreferrer';
    link.append(make('code', '', data.revision.slice(0, 7)));
    const notes = [];
    if (data.built) notes.push(`built ${new Date(data.built).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' })}`);
    if (data.modified) notes.push('with local changes');
    $('install-version').replaceChildren(link, notes.length ? ` · ${notes.join(' · ')}` : '');
  } else $('install-version').textContent = 'Not recorded in this build.';
  const kinds = data.ssh && data.rdp ? 'SSH and RDP' : data.ssh ? 'SSH' : data.rdp ? 'RDP' : '';
  $('install-serves').textContent = kinds ? `${kinds}, to ${data.servers} ${data.servers === 1 ? 'server' : 'servers'} on the Servers page.` : 'No servers: this copy connects to none.';
  // An installation with RDP is rebuilt with its runtime.
  if (data.rdp && !$('command-build').textContent.endsWith(' --with-rdp')) $('command-build').textContent += ' --with-rdp';
}

// ── Pages ────────────────────────────────────────────────────────────────
// One document, a page per path: the path picks what a ready session sees.
// A server's and a person's own pages sit under their lists.
const pages = {
  access: { path: '/', panel: 'access-panel', title: 'Your servers', lead: 'Open one, and Keybash signs you in. You never see its key or password.' },
  servers: { path: '/servers', panel: 'servers-panel', title: 'Servers', lead: 'Each server, the accounts on it, and who signs in with each.' },
  server: { under: 'servers', panel: 'server-panel', title: 'Server', lead: '' },
  users: { path: '/users', panel: 'users-panel', title: 'People', lead: 'Who signs in to Keybash, what each may do, and where.' },
  person: { under: 'users', panel: 'person-panel', title: 'Person', lead: '' },
  account: { path: '/account', panel: 'account-panel', title: 'Account', lead: 'Your password, your phone authenticator and your recovery codes.' },
  installation: { path: '/installation', panel: 'installation-panel', title: 'Installation', lead: 'What this copy of Keybash runs, and how to update it.' },
};
// Which pages each role sees; the first is where a role lands. The server
// refuses the rest whatever the page shows.
const access = { user: ['access', 'account'], admin: ['access', 'servers', 'server', 'users', 'person', 'installation', 'account'], auditor: ['servers', 'server', 'account'] };
const route = { name: '', id: '' };
function pageOf(path) {
  for (const [name, page] of Object.entries(pages)) if (page.path === path) return { name, id: '' };
  const detail = /^\/(servers|users)\/([a-f0-9]{32})$/.exec(path);
  if (detail) return { name: detail[1] === 'servers' ? 'server' : 'person', id: detail[2] };
  return { name: 'access', id: '' };
}
function showPage(ready) {
  // Without servers there is nothing to connect to or manage.
  const allowed = access[role].filter(key => !['access', 'servers', 'server'].includes(key) || remoteEnabled);
  let { name, id } = pageOf(location.pathname);
  if (!allowed.includes(name)) { name = allowed[0]; id = ''; }
  route.name = name; route.id = id;
  const page = pages[name], rail = page.under ?? name;
  // The alarm may stay up from the page before: its way to Servers shows on
  // every other page as soon as that page does.
  $('attention-open').hidden = rail === 'servers';
  for (const [key, each] of Object.entries(pages)) $(each.panel).hidden = !ready || key !== name;
  document.querySelectorAll('.rail-item').forEach(item => {
    if (item.dataset.page === rail) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
    item.hidden = !allowed.includes(item.dataset.page);
  });
  $('invite-person').hidden = !ready || name !== 'users'; $('add-server').hidden = true; /* shown once the page knows it can add */
  const back = $('back-link');
  back.hidden = !ready || !page.under;
  if (page.under) { back.replaceChildren(glyph('back', 'button-glyph'), pages[page.under].title); back.href = pages[page.under].path; back.dataset.page = ''; }
  $('topbar-page').textContent = $('rail-page').textContent = ready ? pages[rail].title : 'Sign-in';
  $('lead').textContent = ready ? page.lead : ''; $('lead').hidden = !ready || !page.lead && !page.under;
  if (ready) { $('heading').textContent = page.title; document.title = `Keybash · ${page.title}`; }
  return name;
}
// The page's data, for the page now shown.
async function loadPage() {
  const page = route.name;
  if (page === 'access') await loadAccess();
  else if (page === 'servers') await loadServers();
  else if (page === 'server') await loadServerPage(route.id);
  else if (page === 'users') await loadUsers();
  else if (page === 'person') await loadPersonPage(route.id);
  else if (page === 'installation') await loadInstallation();
  if (!['servers', 'server'].includes(page) && role === 'admin' && remoteEnabled) void checkAttention();
}
// Moving between pages keeps the document: the address changes, the page
// shows, and its data loads.
async function go(path) {
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  if (location.pathname !== path) history.pushState(null, '', path);
  showPage(true); window.scrollTo(0, 0);
  await loadPage();
}
document.addEventListener('click', event => {
  const link = event.target.closest?.('a[data-page], .rail-item');
  if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || link.target) return;
  const url = new URL(link.href, location.href);
  if (url.origin !== location.origin || document.body.dataset.stage !== 'ready') return;
  event.preventDefault(); setMenu(false);
  void run(() => go(url.pathname));
});
window.addEventListener('popstate', () => { if (document.body.dataset.stage === 'ready') { showPage(true); void run(loadPage); } });
async function loadAccount() {
  const data = await request('/api/session');
  if (typeof data?.username !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(data.username) || typeof data.csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.csrf) || !['enroll', 'challenge', 'ready'].includes(data.stage) || !Object.hasOwn(access, data.role)) throw new Error('invalid session');
  csrf = data.csrf; role = data.role; for (const id of ['account', 'account-name', 'focus-account']) $(id).textContent = data.username; document.body.dataset.stage = data.stage;
  remoteEnabled = data.remote === true;
  setupRequired = data.stage === 'enroll' && data.setup === true; $('setup-proof').hidden = !setupRequired;
  sections.forEach(id => { $(id).hidden = true; });
  $('heading').textContent = data.stage === 'enroll' ? 'Set up your phone' : 'Confirm it’s you';
  showPage(data.stage === 'ready');
  $(data.stage === 'ready' ? 'vault' : data.stage).hidden = false; document.body.dataset.loaded = '';
  if (data.stage !== 'ready') return;
  // Who "you" is, to mark yourself among people.
  if (role === 'admin') { try { self = (await loadPeople()).self; } catch { self = ''; } }
  await loadPage();
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
// How this account's pages look: light or dark, and the menu open or
// collapsed. The page arrives in the saved look; a change shows at once and is
// kept with the account on the server, never in the browser. Saves go one
// after another, each with the look as it is when it goes.
const root = document.documentElement, systemDark = matchMedia('(prefers-color-scheme: dark)');
const looksDark = () => root.dataset.theme ? root.dataset.theme === 'dark' : systemDark.matches;
let saving = Promise.resolve();
function showLook() {
  for (const button of document.querySelectorAll('.theme-toggle')) button.setAttribute('aria-label', looksDark() ? 'Switch to the light colour scheme' : 'Switch to the dark colour scheme');
  const collapse = $('rail-collapse'), collapsed = root.dataset.menu === 'collapsed';
  collapse?.setAttribute('aria-expanded', String(!collapsed));
  collapse?.setAttribute('aria-label', collapsed ? 'Expand the menu' : 'Collapse the menu');
}
function changeLook(change) {
  change(); showLook();
  saving = saving.then(() => request('/api/preferences', 'POST', { theme: root.dataset.theme ?? 'system', menu: root.dataset.menu ?? 'open' }))
    .catch(() => notice('The look was not saved: it lasts until you leave this page.'));
}
for (const button of document.querySelectorAll('.theme-toggle')) {
  button.addEventListener('click', () => {
    const next = looksDark() ? 'light' : 'dark';
    button.dataset.turning = ''; setTimeout(() => { delete button.dataset.turning; }, 500);
    changeLook(() => { root.dataset.theme = next; });
  });
}
$('rail-collapse')?.addEventListener('click', () => changeLook(() => { if (root.dataset.menu === 'collapsed') delete root.dataset.menu; else root.dataset.menu = 'collapsed'; }));
systemDark.addEventListener('change', showLook);
showLook();
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
  $('reset-dialog').close(); await reloadPersonOrList(person.id); showCode(reply?.code, person.username, resetKinds[kind].dialog); notice(resetKinds[kind].done(person.username));
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
  $('role-dialog').close(); await reloadPersonOrList(person.id);
  if (chosen !== person.role) notice(`${person.username} is now ${chosen === 'admin' ? 'an administrator' : chosen === 'auditor' ? 'an auditor, and on no server account' : 'a user'}, from their next sign-in.`);
});
click('copy-code', () => copy('person-code', $('copy-code')));
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
$('change-password')?.addEventListener('click', () => { if (busy) return; clearInputs(); dialogNotice(''); $('password-dialog').showModal(); $('current-password').focus(); });
$('password-cancel')?.addEventListener('click', () => $('password-dialog').close());
$('password-dialog')?.addEventListener('close', clearInputs);
bind('password-change', async () => {
  const password = $('current-password').value, next = $('new-password').value, confirm = $('confirm-password').value; clearInputs();
  if (next !== confirm) { notice('The new passwords don’t match.'); return; }
  await request('/api/password', 'POST', { password, next }); clearAll(); location.replace('/login');
});
click('reset-mfa', async () => { await request('/api/mfa/reset', 'POST', {}); await loadAccount(); });
click('regenerate-recovery', async () => { showCodes(await request('/api/mfa/recovery', 'POST', {})); });
click('saved-recovery', async () => { $('recovery-codes').value = ''; await loadAccount(); });
const signOut = async () => { clearInputs(); await request('/api/session', 'DELETE', {}); clearAll(); location.replace('/login'); };
click('logout', signOut); click('focus-logout', signOut);
click('copy-seed', () => copy('seed', $('copy-seed'))); click('copy-recovery', () => copy('recovery-codes', $('copy-recovery')));
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') { clearInputs(); hideSeed(); } });
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
    catch (error) { if (error.status === 401) { clearAll(); location.replace('/login'); } else throw error; }
  });
}, 30000);
