// The Files page: one folder of a server at a time. Everything it knows about
// the server arrives through files-socket.mjs; nothing here reaches the server
// another way. Remote names are untrusted: they are written as text, never as
// markup, and a control or direction character is shown as a visible mark.

import { openFiles } from './files-socket.mjs';

const $ = id => document.getElementById(id);
const MAX_NAME = 255;
const MAX_FILE = 2 * 1024 ** 3;

const state = {
  session: null,
  home: null, // the account's home folder, from the first listing
  path: '/',
  entries: [],
  sort: { key: 'name', down: false },
  filter: '',
  selected: new Set(),
  active: 0,
  busy: false,
};

// ── Names, shown for what they are ─────────────────────────────────────────
function hidden(point) {
  return point < 0x20 || (point >= 0x7f && point <= 0x9f) || point === 0x061c || point === 0x180e ||
    (point >= 0x200b && point <= 0x200f) || (point >= 0x202a && point <= 0x202e) ||
    (point >= 0x2060 && point <= 0x2064) || (point >= 0x2066 && point <= 0x2069) || point === 0xfeff;
}
function hasHidden(name) {
  for (const char of name) if (hidden(char.codePointAt(0))) return true;
  return false;
}
function nameNodes(name) {
  const out = document.createDocumentFragment();
  let run = '';
  for (const char of name) {
    const point = char.codePointAt(0);
    if (!hidden(point)) { run += char; continue; }
    if (run) { out.append(run); run = ''; }
    const mark = document.createElement('span');
    mark.className = 'ctl';
    mark.textContent = `U+${point.toString(16).toUpperCase().padStart(4, '0')}`;
    mark.title = 'A hidden character in this name';
    out.append(mark);
  }
  if (run) out.append(run);
  return out;
}
// The name a download is saved under: the same, with hidden characters and
// separators replaced, so it cannot pretend to be another kind of file.
function saveName(name) {
  let out = '';
  for (const char of name) out += hidden(char.codePointAt(0)) || char === '/' || char === '\\' ? '_' : char;
  return out.replace(/^\.+/, '_') || 'download';
}
function nameProblem(name, taken) {
  if (!name.trim()) return 'Type a name.';
  if (name === '.' || name === '..') return 'That name is reserved.';
  if (name.includes('/')) return 'A name cannot hold a slash.';
  if (hasHidden(name)) return 'A name cannot hold control or direction characters.';
  if (new TextEncoder().encode(name).length > MAX_NAME) return `A name is at most ${MAX_NAME} bytes.`;
  if (taken.has(name)) return 'Something in this folder already has that name.';
  return '';
}

// ── Paths ──────────────────────────────────────────────────────────────────
const join = (dir, name) => (dir === '/' ? `/${name}` : `${dir}/${name}`);
const parent = path => (path === '/' ? '/' : path.slice(0, path.lastIndexOf('/')) || '/');
const base = path => path.slice(path.lastIndexOf('/') + 1);

// ── Numbers people read ────────────────────────────────────────────────────
function bytes(size) {
  if (size < 1024) return `${size} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = size / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}
const clock = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' });
const day = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
function when(seconds) {
  if (!seconds) return '—';
  const date = new Date(seconds * 1000);
  const today = new Date();
  const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
  if (date.toDateString() === today.toDateString()) return `Today, ${clock.format(date)}`;
  if (date.toDateString() === yesterday.toDateString()) return `Yesterday, ${clock.format(date)}`;
  return `${day.format(date)}, ${clock.format(date)}`;
}

// ── What a row is ──────────────────────────────────────────────────────────
const isFolder = entry => entry.kind === 'dir' || (entry.kind === 'link' && entry.target === 'dir');
const isFile = entry => entry.kind === 'file' || (entry.kind === 'link' && entry.target === 'file');
const kinds = [
  ['archive', /\.(zip|tar|gz|tgz|xz|bz2|zst|7z|rar|deb|rpm)$/i],
  ['image', /\.(png|jpe?g|gif|webp|svg|bmp|ico|tiff?)$/i],
  ['code', /\.(sh|bash|py|go|rs|js|mjs|ts|c|h|cpp|java|rb|php|pl|ps1|sql|json|ya?ml|toml|xml|html?|css)$/i],
  ['text', /\.(txt|md|log|conf|cfg|ini|env|csv|pem|pub|crt|service)$/i],
];
function glyph(entry) {
  let name = 'other';
  if (entry.kind === 'dir') name = 'folder';
  else if (entry.kind === 'link') name = entry.target === 'dir' ? 'folder' : 'link';
  else if (entry.kind === 'file') name = kinds.find(([, test]) => test.test(entry.name))?.[0] ?? 'file';
  return icon(name);
}
// Icons are drawn once, in the page's templates, and only ever copied.
function icon(name) { return $(`glyph-${name}`).content.firstElementChild.cloneNode(true); }

// ── Painting the folder ────────────────────────────────────────────────────
function visible() {
  const filter = state.filter.toLowerCase();
  const rows = state.entries.filter(entry => !filter || (entry.readable && entry.name.toLowerCase().includes(filter)));
  const { key, down } = state.sort;
  const byName = (a, b) => a.name.localeCompare(b.name, 'en', { numeric: true, sensitivity: 'base' });
  const by = { name: byName, size: (a, b) => (a.size ?? 0) - (b.size ?? 0), time: (a, b) => (a.time ?? 0) - (b.time ?? 0) }[key];
  return rows.sort((a, b) => (isFolder(b) - isFolder(a)) || (down ? -by(a, b) : by(a, b)) || byName(a, b));
}

function paintCrumbs() {
  const nav = $('crumbs');
  nav.replaceChildren();
  const home = state.home ?? '/';
  const inHome = state.path === home || state.path.startsWith(`${home}/`);
  const parts = [];
  if (inHome) {
    parts.push({ label: 'home', path: home, home: true });
    for (const piece of state.path.slice(home.length).split('/').filter(Boolean)) parts.push({ label: piece, path: join(parts.at(-1).path, piece) });
  } else {
    parts.push({ label: '/', path: '/', root: true });
    for (const piece of state.path.split('/').filter(Boolean)) parts.push({ label: piece, path: join(parts.at(-1).path, piece) });
  }
  parts.forEach((part, index) => {
    if (index > 0 && !parts[index - 1].root) { const sep = document.createElement('span'); sep.className = 'crumb-sep'; sep.textContent = '/'; sep.setAttribute('aria-hidden', 'true'); nav.append(sep); }
    const last = index === parts.length - 1;
    const node = document.createElement(last ? 'span' : 'button');
    if (last) { node.className = 'crumb-here'; node.setAttribute('aria-current', 'location'); } else { node.type = 'button'; node.addEventListener('click', () => go(part.path)); }
    if (part.home) {
      node.classList.add('crumb-home');
      node.setAttribute('aria-label', `Home folder, ${home}`);
      node.title = home;
      node.append(icon('home'), 'Home');
    } else node.append(nameNodes(part.label));
    nav.append(node);
  });
  const edit = document.createElement('button');
  edit.type = 'button';
  edit.className = 'ghost icon-button crumb-edit';
  edit.title = 'Go to a folder by its path';
  edit.setAttribute('aria-label', 'Go to a folder by its path');
  edit.append(icon('edit'));
  edit.addEventListener('click', editPath);
  nav.append(edit);
}

function editPath() {
  const nav = $('crumbs');
  const field = document.createElement('input');
  field.value = state.path;
  field.spellcheck = false;
  field.autocomplete = 'off';
  field.maxLength = 4096;
  field.setAttribute('aria-label', 'Folder path');
  nav.replaceChildren(field);
  field.focus();
  field.select();
  let done = false;
  const finish = target => { if (done) return; done = true; if (target) go(target); else paintCrumbs(); };
  field.addEventListener('keydown', event => {
    if (event.key === 'Enter') { event.preventDefault(); const typed = field.value.trim(); finish(typed.startsWith('/') ? typed.replace(/\/+$/, '') || '/' : join(state.path, typed)); }
    if (event.key === 'Escape') { event.preventDefault(); finish(null); }
  });
  field.addEventListener('blur', () => finish(null));
}

function row(entry, index) {
  const tr = document.createElement('tr');
  tr.tabIndex = index === state.active ? 0 : -1;
  tr.dataset.index = String(index);
  const picked = state.selected.has(entry.name);
  tr.setAttribute('aria-selected', String(picked));

  const pick = document.createElement('td');
  pick.className = 'col-pick';
  const box = document.createElement('input');
  box.type = 'checkbox';
  box.checked = picked;
  box.disabled = !entry.readable;
  box.setAttribute('aria-label', entry.readable ? `Select ${entry.name}` : 'Select');
  box.addEventListener('change', () => { toggle(entry, box.checked); });
  pick.append(box);

  const name = document.createElement('td');
  name.className = 'col-name';
  const cell = document.createElement('div');
  cell.className = 'name-cell';
  cell.append(glyph(entry));
  const text = document.createElement('div');
  text.className = 'name-text';
  let line;
  if (!entry.readable) {
    line = document.createElement('span');
    line.className = 'name-line name-unreadable';
    line.textContent = 'A name that is not readable text';
    line.title = 'Keybash shows only names in UTF-8 and offers no action on this one.';
  } else if (isFolder(entry)) {
    line = document.createElement('button');
    line.type = 'button';
    line.className = 'name-open';
    line.tabIndex = -1;
    line.append(nameNodes(entry.name));
    line.addEventListener('click', () => go(join(state.path, entry.name)));
  } else {
    line = document.createElement('span');
    line.className = 'name-line';
    line.append(nameNodes(entry.name));
  }
  if (entry.readable) line.title = entry.name;
  if (entry.kind === 'link') {
    const mark = document.createElement('span');
    mark.className = 'link-mark';
    mark.textContent = 'link';
    mark.title = entry.target === 'dir' ? 'A link to a folder' : entry.target === 'file' ? 'A link to a file' : 'A link';
    line.append(mark);
  }
  const meta = document.createElement('span');
  meta.className = 'name-meta';
  meta.textContent = isFolder(entry) ? when(entry.time) : `${bytes(entry.size ?? 0)} · ${when(entry.time)}`;
  text.append(line, meta);
  cell.append(text);
  name.append(cell);

  const size = document.createElement('td');
  size.className = 'col-size';
  size.textContent = isFile(entry) ? bytes(entry.size ?? 0) : '—';
  const time = document.createElement('td');
  time.className = 'col-time';
  time.textContent = when(entry.time);

  const acts = document.createElement('td');
  acts.className = 'col-acts';
  const box2 = document.createElement('div');
  box2.className = 'row-acts';
  if (entry.readable) {
    box2.append($('row-actions').content.cloneNode(true));
    const download = box2.querySelector('.act-download');
    if (isFile(entry)) download.addEventListener('click', () => downloadAll([entry]));
    else download.remove();
    box2.querySelector('.act-rename').addEventListener('click', () => rename(entry));
    box2.querySelector('.act-delete').addEventListener('click', () => remove([entry]));
    for (const button of box2.querySelectorAll('button')) { button.tabIndex = -1; button.title = button.getAttribute('aria-label'); }
  }
  acts.append(box2);

  tr.append(pick, name, size, time, acts);
  tr.addEventListener('click', event => {
    if (event.target.closest('button, input')) return;
    state.active = index;
    if (event.ctrlKey || event.metaKey) toggle(entry, !state.selected.has(entry.name));
    else focusRow(index);
  });
  tr.addEventListener('dblclick', event => { if (!event.target.closest('button, input')) openEntry(entry); });
  tr.addEventListener('focus', () => { state.active = index; });
  return tr;
}

function paint() {
  const rows = visible();
  state.active = Math.min(state.active, Math.max(rows.length - 1, 0));
  $('rows').replaceChildren(...rows.map(row));
  const empty = rows.length === 0;
  $('empty').hidden = !empty;
  $('empty-title').textContent = state.entries.length ? 'Nothing here matches the filter' : 'This folder is empty';
  $('empty-hint').textContent = state.entries.length ? 'Clear the filter to see everything.' : (state.session?.mode === 'both' ? 'Drop files here, or press Upload.' : 'There is nothing to download here.');
  for (const th of document.querySelectorAll('th[aria-sort]')) {
    const key = th.querySelector('.sort').dataset.sort;
    th.setAttribute('aria-sort', key === state.sort.key ? (state.sort.down ? 'descending' : 'ascending') : 'none');
  }
  const folders = state.entries.filter(isFolder).length;
  const files = state.entries.filter(isFile);
  const total = files.reduce((sum, entry) => sum + (entry.size ?? 0), 0);
  $('files-summary').textContent = state.entries.length
    ? [folders && `${folders} folder${folders === 1 ? '' : 's'}`, files.length && `${files.length} file${files.length === 1 ? '' : 's'}`, files.length && bytes(total)].filter(Boolean).join(' · ')
    : '';
  paintSelection();
}

function paintSelection() {
  const count = state.selected.size;
  $('selection').hidden = count === 0;
  $('selection-count').textContent = String(count);
  const all = $('pick-all');
  const readable = state.entries.filter(entry => entry.readable).length;
  all.checked = readable > 0 && count === readable;
  all.indeterminate = count > 0 && count < readable;
  for (const tr of $('rows').children) {
    const entry = visible()[Number(tr.dataset.index)];
    const picked = state.selected.has(entry?.name);
    tr.setAttribute('aria-selected', String(picked));
    const box = tr.querySelector('input[type=checkbox]');
    if (box) box.checked = picked;
  }
}

function toggle(entry, on) {
  if (!entry.readable) return;
  if (on) state.selected.add(entry.name); else state.selected.delete(entry.name);
  paintSelection();
}

function focusRow(index) {
  const rows = $('rows').children;
  if (!rows.length) return;
  state.active = Math.max(0, Math.min(index, rows.length - 1));
  for (const tr of rows) tr.tabIndex = -1;
  rows[state.active].tabIndex = 0;
  rows[state.active].focus();
}

// ── Messages ───────────────────────────────────────────────────────────────
const reasons = {
  exists: 'Something with that name is already there.',
  missing: 'It is no longer there. The folder was refreshed.',
  denied: 'The server account may not do that here.',
  'not-empty': 'The folder is not empty. Delete what is inside it first.',
  'too-large': 'Files of up to 2 GB can be moved here.',
  'not-allowed': 'This server does not allow that.',
  failed: 'The server could not do that.',
};
function say(text) {
  const line = $('message');
  line.textContent = text;
  line.hidden = !text;
}
const reasonText = error => reasons[error?.reason] ?? reasons.failed;

// ── Moving around ──────────────────────────────────────────────────────────
async function go(path, keep = false) {
  if (state.busy) return;
  state.busy = true;
  document.body.dataset.busy = '';
  try {
    const listing = await state.session.list(path);
    if (state.home === null) state.home = listing.path;
    const same = listing.path === state.path;
    state.path = listing.path;
    state.entries = listing.entries;
    if (!same || !keep) { state.selected.clear(); state.active = 0; }
    else for (const name of [...state.selected]) if (!listing.entries.some(entry => entry.name === name)) state.selected.delete(name);
    if (!same) { state.filter = ''; $('filter').value = ''; say(''); }
    $('drop-path').replaceChildren(nameNodes(state.path));
    document.title = `Keybash · Files · ${state.session.server.name}`;
    paintCrumbs();
    paint();
  } catch (error) {
    say(error?.reason === 'missing' ? 'That folder is not there.' : error?.reason === 'too-large' ? 'That folder holds more than 10,000 names, more than this page lists.' : reasonText(error));
    paintCrumbs();
  } finally {
    state.busy = false;
    delete document.body.dataset.busy;
  }
}
const refresh = () => go(state.path, true);

function openEntry(entry) {
  if (!entry.readable) return;
  if (isFolder(entry)) go(join(state.path, entry.name));
  else if (isFile(entry)) downloadAll([entry]);
}

// ── Transfers ──────────────────────────────────────────────────────────────
const tray = { items: [] };
function transferItem(direction, name, total) {
  const li = document.createElement('li');
  li.className = 'transfer';
  li.dataset.state = 'running';
  const way = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  way.setAttribute('viewBox', '0 0 24 24');
  way.setAttribute('class', 'row-glyph');
  way.setAttribute('aria-hidden', 'true');
  const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  arrow.setAttribute('d', direction === 'up' ? 'M12 19V5M6.5 10.5 12 5l5.5 5.5' : 'M12 5v14M6.5 13.5 12 19l5.5-5.5');
  way.append(arrow);
  const label = document.createElement('p');
  label.className = 'transfer-name';
  label.append(nameNodes(name));
  label.title = name;
  const detail = document.createElement('p');
  detail.className = 'transfer-detail';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'ghost icon-button';
  cancel.setAttribute('aria-label', `Cancel ${name}`);
  cancel.title = 'Cancel';
  cancel.append(icon('cancel'));
  const bar = document.createElement('progress');
  bar.max = Math.max(total, 1);
  bar.value = 0;
  li.append(way, label, cancel, detail, bar);
  $('transfer-list').prepend(li);
  const item = { li, detail, bar, cancel, total, started: performance.now(), controller: new AbortController(), direction };
  cancel.addEventListener('click', () => item.controller.abort());
  tray.items.push(item);
  paintTray();
  return item;
}
function progress(item, done) {
  item.bar.value = done;
  const seconds = (performance.now() - item.started) / 1000;
  const speed = seconds > 0.3 ? done / seconds : 0;
  const left = speed > 0 ? Math.ceil((item.total - done) / speed) : 0;
  item.detail.textContent = `${bytes(done)} of ${bytes(item.total)}${speed ? ` · ${bytes(speed)}/s` : ''}${left > 1 ? ` · ${left < 60 ? `${left} s` : `${Math.ceil(left / 60)} min`} left` : ''}`;
}
function finish(item, outcome, text) {
  item.li.dataset.state = outcome;
  if (outcome === 'done') item.bar.value = item.bar.max;
  item.detail.textContent = text;
  item.cancel.hidden = true;
  paintTray();
}
function paintTray() {
  const running = tray.items.filter(item => item.li.dataset.state === 'running').length;
  $('transfers').hidden = tray.items.length === 0;
  $('transfers-title').textContent = running ? `${running} transfer${running === 1 ? '' : 's'} in progress` : 'Transfers finished';
  $('transfers-clear').hidden = running > 0;
}

async function downloadAll(entries) {
  const files = entries.filter(isFile);
  if (files.length < entries.length) say('Folders are not downloaded. Open one to download what is inside it.');
  for (const entry of files) {
    if ((entry.size ?? 0) > MAX_FILE) { say(`${entry.name} is larger than 2 GB, which is as much as moves here.`); continue; }
    const item = transferItem('down', entry.name, entry.size ?? 0);
    try {
      const blob = await state.session.download(join(state.path, entry.name), { signal: item.controller.signal, progress: done => progress(item, done) });
      const url = URL.createObjectURL(new Blob([blob], { type: 'application/octet-stream' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = saveName(entry.name);
      link.rel = 'noopener';
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
      finish(item, 'done', `Downloaded · ${bytes(blob.size)}`);
    } catch (error) {
      finish(item, 'failed', item.controller.signal.aborted ? 'Cancelled' : reasonText(error));
    }
  }
}

function ask(dialog) {
  return new Promise(resolve => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue), { once: true });
    dialog.returnValue = '';
    dialog.showModal();
  });
}

async function uploadAll(list) {
  if (state.session.mode !== 'both') return;
  const target = state.path;
  const names = new Set(state.entries.map(entry => entry.name));
  let every = null;
  for (const file of list) {
    const problem = nameProblem(file.name, new Set());
    if (problem) { say(`${file.name}: ${problem}`); continue; }
    if (file.size > MAX_FILE) { say(`${file.name} is larger than 2 GB, which is as much as moves here.`); continue; }
    let replace = false;
    if (names.has(file.name)) {
      const existing = state.entries.find(entry => entry.name === file.name);
      if (!isFile(existing)) { say(`${file.name}: a folder already has that name.`); continue; }
      if (every === null) {
        $('replace-title').replaceChildren('Replace ', nameNodes(file.name), '?');
        $('replace-all').checked = false;
        $('replace-all').parentElement.hidden = list.length < 2;
        const answer = await ask($('replace-dialog'));
        if ($('replace-all').checked) every = answer;
        if (answer !== 'replace') continue;
      } else if (every !== 'replace') continue;
      replace = true;
    }
    const item = transferItem('up', file.name, file.size);
    try {
      await state.session.upload(join(target, file.name), file, { replace, signal: item.controller.signal, progress: done => progress(item, done) });
      finish(item, 'done', `Uploaded · ${bytes(file.size)}`);
      names.add(file.name);
      if (state.path === target) refresh();
    } catch (error) {
      finish(item, 'failed', item.controller.signal.aborted ? 'Cancelled' : reasonText(error));
    }
  }
}

// ── Changing things ────────────────────────────────────────────────────────
async function nameDialog(title, label, action, start = '') {
  const dialog = $('name-dialog');
  $('name-title').textContent = title;
  $('name-save').textContent = action;
  $('name-hint').textContent = '';
  const field = $('name-input');
  field.value = start;
  const taken = new Set(state.entries.map(entry => entry.name));
  taken.delete(start);
  const check = event => {
    if (event.submitter?.value !== 'save') return;
    const problem = nameProblem(field.value, taken);
    if (problem) { event.preventDefault(); $('name-hint').textContent = problem; field.focus(); }
  };
  $('name-form').addEventListener('submit', check);
  const pending = ask(dialog);
  field.focus();
  const dot = start.lastIndexOf('.');
  field.setSelectionRange(0, dot > 0 ? dot : start.length);
  const answer = await pending;
  $('name-form').removeEventListener('submit', check);
  return answer === 'save' ? field.value : null;
}

async function newFolder() {
  const name = await nameDialog('New folder', 'Name', 'Create');
  if (name === null) return;
  try { await state.session.mkdir(join(state.path, name)); say(''); await refresh(); } catch (error) { say(reasonText(error)); }
}

async function rename(entry) {
  const name = await nameDialog('Rename', 'New name', 'Rename', entry.name);
  if (name === null || name === entry.name) return;
  try { await state.session.rename(join(state.path, entry.name), join(state.path, name)); say(''); await refresh(); } catch (error) { say(reasonText(error)); }
}

async function remove(entries) {
  if (!entries.length) return;
  const one = entries.length === 1 ? entries[0] : null;
  if (one) $('delete-title').replaceChildren(`Delete ${isFolder(one) ? 'the folder' : ''} `, nameNodes(one.name), '?');
  else $('delete-title').textContent = `Delete ${entries.length} items?`;
  $('delete-hint').textContent = entries.some(isFolder)
    ? 'They are removed from the server, and this cannot be undone. A folder is removed only when it is empty.'
    : 'They are removed from the server. This cannot be undone.';
  if (one) $('delete-hint').textContent = isFolder(one) ? 'It is removed from the server only if it is empty. This cannot be undone.' : 'It is removed from the server. This cannot be undone.';
  if (await ask($('delete-dialog')) !== 'delete') return;
  let failed = '';
  for (const entry of entries) {
    try {
      const path = join(state.path, entry.name);
      if (isFolder(entry) && entry.kind === 'dir') await state.session.rmdir(path); else await state.session.remove(path);
      state.selected.delete(entry.name);
    } catch (error) { failed = `${entry.name}: ${reasonText(error)}`; }
  }
  say(failed);
  await refresh();
}

// ── The keyboard ───────────────────────────────────────────────────────────
function keys(event) {
  if (state.session === null || document.querySelector('dialog[open]')) return;
  const typing = event.target.closest('input, textarea');
  if (event.key === 'Backspace' && !typing) { event.preventDefault(); if (state.path !== '/') go(parent(state.path)); return; }
  const tr = event.target.closest('#rows tr');
  if (!tr) return;
  const rows = visible();
  const entry = rows[Number(tr.dataset.index)];
  const write = state.session.mode === 'both';
  switch (event.key) {
    case 'ArrowDown': event.preventDefault(); focusRow(state.active + 1); break;
    case 'ArrowUp': event.preventDefault(); focusRow(state.active - 1); break;
    case 'Home': event.preventDefault(); focusRow(0); break;
    case 'End': event.preventDefault(); focusRow(rows.length - 1); break;
    case 'Enter': event.preventDefault(); openEntry(entry); break;
    case ' ': event.preventDefault(); toggle(entry, !state.selected.has(entry.name)); break;
    case 'F2': if (write && entry.readable) { event.preventDefault(); rename(entry); } break;
    case 'Delete': if (write) { event.preventDefault(); remove(state.selected.size ? rows.filter(item => state.selected.has(item.name)) : [entry].filter(item => item.readable)); } break;
    case 'Escape': state.selected.clear(); paintSelection(); break;
    case 'a': if (event.ctrlKey || event.metaKey) { event.preventDefault(); for (const item of rows) if (item.readable) state.selected.add(item.name); paintSelection(); } break;
    default: break;
  }
}

// ── Dropping files ─────────────────────────────────────────────────────────
function drops() {
  let depth = 0;
  const carriesFiles = event => [...(event.dataTransfer?.types ?? [])].includes('Files');
  const show = on => { $('drop').hidden = !on; };
  document.addEventListener('dragenter', event => {
    if (!carriesFiles(event) || state.session?.mode !== 'both') return;
    depth += 1;
    show(true);
  });
  document.addEventListener('dragleave', () => { depth = Math.max(0, depth - 1); if (!depth) show(false); });
  document.addEventListener('dragover', event => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = state.session?.mode === 'both' ? 'copy' : 'none';
  });
  document.addEventListener('drop', event => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    depth = 0;
    show(false);
    if (state.session?.mode !== 'both') return;
    const items = [...event.dataTransfer.items];
    const folders = items.some(item => item.webkitGetAsEntry?.()?.isDirectory);
    const files = items.filter(item => item.kind === 'file' && !item.webkitGetAsEntry?.()?.isDirectory).map(item => item.getAsFile()).filter(Boolean);
    if (folders) say('Folders are not uploaded. Drop the files inside them, or make the folder here first.');
    uploadAll(files);
  });
}

// ── Starting ───────────────────────────────────────────────────────────────
function ended(reason) {
  document.body.dataset.stage = 'ended';
  $('status').textContent = 'Ended';
  $('notice').textContent = reason;
  $('ended').hidden = false;
  // The folder stays in view as it was, but nothing on it answers any more.
  document.querySelector('.files-card').inert = true;
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
}

async function start() {
  for (const th of document.querySelectorAll('.sort')) th.addEventListener('click', () => {
    const key = th.dataset.sort;
    state.sort = { key, down: state.sort.key === key ? !state.sort.down : key !== 'name' };
    paint();
  });
  $('filter').addEventListener('input', () => { state.filter = $('filter').value; paint(); });
  $('refresh').addEventListener('click', refresh);
  $('new-folder').addEventListener('click', newFolder);
  $('upload').addEventListener('click', () => $('upload-input').click());
  $('upload-input').addEventListener('change', () => { const files = [...$('upload-input').files]; $('upload-input').value = ''; uploadAll(files); });
  $('pick-all').addEventListener('change', () => {
    state.selected.clear();
    if ($('pick-all').checked) for (const entry of visible()) if (entry.readable) state.selected.add(entry.name);
    paintSelection();
  });
  $('selection-clear').addEventListener('click', () => { state.selected.clear(); paintSelection(); });
  $('selection-download').addEventListener('click', () => downloadAll(visible().filter(entry => state.selected.has(entry.name))));
  $('selection-delete').addEventListener('click', () => remove(visible().filter(entry => state.selected.has(entry.name))));
  $('transfers-fold').addEventListener('click', () => {
    const tray = $('transfers');
    const folded = tray.toggleAttribute('data-folded');
    $('transfers-fold').setAttribute('aria-expanded', String(!folded));
  });
  $('transfers-clear').addEventListener('click', () => {
    tray.items = tray.items.filter(item => { const keep = item.li.dataset.state === 'running'; if (!keep) item.li.remove(); return keep; });
    paintTray();
  });
  $('reconnect').addEventListener('click', () => location.reload());
  document.addEventListener('keydown', keys);
  drops();

  try {
    state.session = await openFiles(document.body.dataset.account ?? '', { ended });
  } catch (error) {
    ended(error?.message || 'Files could not be opened.');
    return;
  }
  const { server, account, mode } = state.session;
  $('server-name').textContent = server.name;
  $('server-account').textContent = `${account}@${server.address}`;
  document.body.dataset.mode = mode;
  $('mode').textContent = mode === 'both' ? 'Upload and download' : 'Download only';
  $('mode').hidden = false;
  $('readonly-note').hidden = mode === 'both';
  document.body.dataset.stage = 'ready';
  $('status').textContent = 'Connected';
  // An empty path is the account's home folder, as the server names it.
  await go('');
}

start();
