const $ = id => document.getElementById(id);
let csrf = '', busy = false, secretTimer, pendingDelete = '', remoteEnabled = false, setupRequired = false;
let catalog = new Map(), selectedTarget = null, targetGeneration = 0, reviewing = null, reviewGeneration = 0;
const notice = text => { $('notice').textContent = text; };
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
}
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
  for (const id of ['account', 'records', 'connections', 'connection-server']) if ($(id)) $(id).textContent = '';
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
          $('stepup-error').textContent = 'Kod qəbul edilmədi. Tətbiqdəki hazırkı kodu yaz: eyni kod iki dəfə qəbul edilmir.';
        } else $('stepup-error').textContent = error.status === 429 ? 'Cəhd limiti dolub. Bir dəqiqə gözlə və yenidən yaz.' : 'Kodu yoxlamaq alınmadı. Bağlantını yoxla və yenidən yaz.';
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
  if (error.status === 'cancelled') return 'Təsdiq ləğv edildi. Heç nə dəyişmədi.';
  if (error.status === 'ended') return 'Çox səhv kod yazıldı və sessiya bağlandı. Yenidən daxil ol.';
  if (error.status === 'setup') return 'Quraşdırma kodu qəbul edilmədi. Administratordan aldığın birdəfəlik kodu yoxla; vaxtı keçibsə yenisini istə.';
  if (error.status === 403) return 'Bu əməliyyata icazə verilmədi. Səhifəni yenilə və yenidən yoxla.';
  if (error.status === 428) return 'Bu əməliyyat telefondakı kodla təsdiq tələb edir. Yenidən yoxla.';
  if (error.status === 409) return 'Server məlumatı bu arada dəyişib. Səhifəni yenilə və yenidən yoxla.';
  if (error.status === 429) return 'Cəhd limiti dolub. Bir qədər gözlə.';
  if (error.status === 401) return 'Doğrulama qəbul edilmədi və ya sessiya bitib. Kodu yoxla; lazım olsa yenidən daxil ol.';
  if (error.status === 400) return 'Məlumat qəbul edilmədi. Şifrəni, kodu və açarın formatını yoxla.';
  return 'Əməliyyat təsdiqlənmədi. Bağlantını yoxla və hesabın vəziyyətini yenilə.';
}
async function run(action) {
  if (busy) return;
  busy = true; notice('');
  // The step-up dialog stays usable while the action that opened it waits.
  const buttons = [...document.querySelectorAll('button')].filter(el => !el.closest('#stepup-dialog')); buttons.forEach(el => { el.disabled = true; });
  try { await action(); } catch (error) { notice(errorMessage(error)); }
  finally { busy = false; buttons.forEach(el => { el.disabled = false; }); updateTrustButtons(); }
}
function bind(id, action) {
  $(id)?.addEventListener('submit', event => { event.preventDefault(); void run(action); });
}
function click(id, action) { $(id)?.addEventListener('click', () => { void run(action); }); }
async function copy(id) {
  const element = $(id), value = element.value ?? element.textContent;
  if (!value) return;
  try { await navigator.clipboard.writeText(value); notice('Kopyalandı.'); }
  catch { if (element.select) element.select(); notice('Brauzer kopyalamağa icazə vermədi. Mətni əl ilə seçib kopyala.'); }
}
function showCodes(data) {
  if (!Array.isArray(data?.codes) || data.codes.length !== 10 || !data.codes.every(code => typeof code === 'string' && /^[A-Za-z0-9_-]{22}$/.test(code))) throw new Error('invalid codes');
  clearInputs(); hideSecret(); hideSeed();
  sections.forEach(id => { $(id).hidden = id !== 'recovery'; });
  $('heading').textContent = 'Bərpa kodların hazırdır.';
  $('recovery-codes').value = data.codes.join('\n');
}
async function loadRecords() {
  const records = await request('/api/credentials');
  if (!Array.isArray(records) || records.length > 256) throw new Error('invalid records');
  $('records').replaceChildren();
  for (const record of records) {
    if (!idOK(record.id) || typeof record.name !== 'string' || !['password', 'ssh-key'].includes(record.kind) || typeof record.username !== 'string' || typeof record.fingerprint !== 'string' || record.generated !== undefined && (record.generated !== true || !publicOK(record.public))) throw new Error('invalid record');
    const row = document.createElement('div'); row.className = 'record';
    const label = document.createElement('span'); label.textContent = record.name;
    const meta = document.createElement('span'); meta.textContent = `${record.kind === 'ssh-key' ? 'SSH açarı' : 'Şifrə'}${record.generated ? ' · Keybash-də yaradılıb' : ''} · istifadəçi: ${record.username}`;
    row.append(label, meta);
    if (record.fingerprint) { const print = document.createElement('span'); print.className = 'fingerprint'; print.textContent = record.fingerprint; row.append(print); }
    // A key made here is never shown; its row offers the install command instead.
    if (record.generated) {
      const install = document.createElement('button'); install.type = 'button'; install.textContent = 'Serverə əlavə et';
      install.addEventListener('click', () => showInstall(record.public));
      const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'secondary'; remove.textContent = 'Sil';
      remove.addEventListener('click', () => { pendingDelete = record.id; $('delete-name').textContent = record.name; $('delete-dialog').showModal(); });
      row.append(install, remove); $('records').append(row); continue;
    }
    const reveal = document.createElement('button'); reveal.type = 'button'; reveal.textContent = 'Göstər';
    reveal.addEventListener('click', () => { void run(async () => {
      hideSecret();
      const item = await request(`/api/credentials/${record.id}/reveal`, 'POST', {});
      if (item?.id !== record.id || typeof item.secret !== 'string' || item.secret.length > 65536 || typeof item.passphrase !== 'string' || item.passphrase.length > 1024 || typeof item.name !== 'string') throw new Error('invalid secret');
      if (document.visibilityState !== 'visible') return;
      $('secret-title').textContent = item.name; $('revealed-secret').value = item.secret; $('revealed-passphrase').value = item.passphrase;
      $('copy-passphrase').hidden = !item.passphrase; $('revealed-passphrase').hidden = !item.passphrase;
      $('secret-dialog').showModal(); secretTimer = setTimeout(hideSecret, 60000);
    }); });
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'secondary'; remove.textContent = 'Sil';
    remove.addEventListener('click', () => { pendingDelete = record.id; $('delete-name').textContent = record.name; $('delete-dialog').showModal(); });
    row.append(reveal, remove); $('records').append(row);
  }
  if (!records.length) {
    const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'Hələ açar və ya şifrə yoxdur. Aşağıda “Yeni açar və ya şifrə” ilə əlavə et.';
    $('records').append(empty); $('credential-fold').open = true;
  }
  if(remoteEnabled){$('connection-credential').replaceChildren();for(const record of records){const option=document.createElement('option');option.value=record.id;option.textContent=`${record.name} · ${record.kind === 'ssh-key' ? 'SSH açarı' : 'Şifrə'}`;$('connection-credential').append(option);}await loadConnections();}
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
  return `Ünvan: ${data.hostname}:${data.port} · ${data.protocol.toUpperCase()}\nIP: ${data.addresses.join(', ')}\nKimlik (barmaq izi): ${data.fingerprint}${data.available ? '' : '\nBu serverin kimliyi hazırda istifadəyə yararlı deyil.'}`;
}
async function chooseTarget() {
  const id = $('connection-target').value, generation = ++targetGeneration;
  selectedTarget = null; $('connection-server').textContent = 'Server məlumatı yoxlanır…'; updateTrustButtons();
  if (!idOK(id)) { $('connection-server').textContent = 'Operator tərəfindən icazəli server yoxdur.'; return; }
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
  $('trust-title').textContent = record.name; $('trust-server').textContent = 'Server məlumatı yoxlanır…';
  $('trust-previous').textContent = record.fingerprint ? `Əvvəl qəbul etdiyin kimlik: ${record.fingerprint}` : 'Bu bağlantı üçün ayrıca kimlik təsdiqi yoxdur.';
  $('trust-dialog').showModal(); updateTrustButtons();
  const target = validateTarget(await request(`/api/targets/${record.target}`), record.target);
  if (generation !== reviewGeneration || !$('trust-dialog').open) return;
  reviewing = {record, target}; $('trust-server').textContent = serverText(target); updateTrustButtons();
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
    const row = document.createElement('div'); row.className = 'record'; row.dataset.connection = record.id;
    const name = document.createElement('span'); name.textContent = record.name;
    const state = document.createElement('span'); state.className = 'trust-state'; state.dataset.trust = record.trust;
    state.textContent = ({verified: 'Server kimliyi təsdiqlənib', changed: 'Server kimliyi və ya ünvanı dəyişib — bağlantı bağlıdır', unverified: 'Server kimliyini təsdiqlə — bağlantı bağlıdır', unavailable: 'Server hazırda əlçatan siyahıda deyil'})[record.trust]; row.append(name, state);
    const target = approved.get(record.target);
    if (target && record.trust === 'verified') { const link = document.createElement('a'); link.textContent = 'Qoşul'; link.href = `/remote/${target.protocol}/${record.id}`; link.target = '_blank'; link.rel = 'noopener'; /* each session in its own tab */ row.append(link); }
    if (target) { const review = document.createElement('button'); review.type = 'button'; review.className = 'secondary'; review.textContent = 'Server kimliyi'; review.addEventListener('click', () => { void run(() => openReview(record)); }); row.append(review); }
    const remove = document.createElement('button'); remove.textContent = 'Bağlantını sil'; remove.type = 'button'; remove.className = 'secondary'; remove.addEventListener('click', () => { void run(async () => { await request(`/api/connections/${record.id}`, 'DELETE', {}); await loadConnections(); }); }); row.append(remove); rows.append(row);
  }
  catalog = approved; $('connection-target').replaceChildren(options); if (approved.has(previous)) $('connection-target').value = previous; $('connections').replaceChildren(rows);
  // With no connection yet, the first steps say what to do, and which is done.
  const hasRecords = $('connection-credential').options.length > 0;
  $('first-steps').hidden = connections.length > 0; $('first-step-key').dataset.done = String(hasRecords);
  if (!connections.length) {
    const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'Hələ bağlantı yoxdur.';
    $('connections').append(empty); if (hasRecords) $('connection-fold').open = true;
  }
  await chooseTarget();
}
// One document, three pages: the path picks what a ready session sees. Without
// an operator catalog there is nothing to connect to, so "/" shows the keys.
const pages = {
  connections: { path: '/', panel: 'connections-panel', title: 'Bağlantılar', lead: 'Serverlərinə buradan qoşul.' },
  keys: { path: '/keys', panel: 'records-panel', title: 'Açarlar və şifrələr', lead: 'Serverlərə girmək üçün açar və şifrələrin. Hamısı bu serverdə şifrələnmiş saxlanır.' },
  account: { path: '/account', panel: 'account-panel', title: 'Hesab', lead: 'Giriş şifrən, telefonundakı autentifikator və bərpa kodların.' },
};
function showPage(ready) {
  let name = Object.keys(pages).find(key => pages[key].path === location.pathname) ?? 'connections';
  if (name === 'connections' && !remoteEnabled) name = 'keys';
  for (const [key, page] of Object.entries(pages)) $(page.panel).hidden = !ready || key !== name;
  document.querySelectorAll('.rail-item').forEach(item => {
    if (item.dataset.page === name) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
    item.hidden = item.dataset.page === 'connections' && !remoteEnabled;
  });
  $('topbar-page').textContent = ready ? pages[name].title : 'Giriş';
  $('lead').textContent = ready ? pages[name].lead : ''; $('lead').hidden = !ready;
  if (ready) { $('heading').textContent = pages[name].title; document.title = `Keybash · ${pages[name].title}`; }
}
async function loadAccount() {
  const data = await request('/api/session');
  if (typeof data?.username !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(data.username) || typeof data.csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.csrf) || !['enroll', 'challenge', 'ready'].includes(data.stage)) throw new Error('invalid session');
  csrf = data.csrf; $('account').textContent = data.username; document.body.dataset.stage = data.stage;
  remoteEnabled = data.remote === true;
  setupRequired = data.stage === 'enroll' && data.setup === true; $('setup-proof').hidden = !setupRequired;
  sections.forEach(id => { $(id).hidden = true; });
  $('heading').textContent = data.stage === 'enroll' ? 'MFA-nı quraq.' : 'Girişini təsdiqlə.';
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
  $('generate').reset(); $('generate-fold').open = false; await loadRecords(); notice('Açar yaradıldı. İndi onu serverə əlavə et.'); showInstall(made.public);
});
click('copy-install', () => copy('install-command'));
$('close-install')?.addEventListener('click', () => $('install-dialog').close());
bind('credential', async () => {
  const kind = $('credential-kind').value;
  const value = { name: $('credential-name').value, kind, username: $('credential-user').value, secret: $(kind === 'password' ? 'credential-password' : 'credential-key').value, passphrase: kind === 'ssh-key' ? $('credential-passphrase').value : '' };
  clearInputs(); await request('/api/credentials', 'POST', value); $('credential').reset(); await loadRecords(); notice('Şifrələnmiş qeyd saxlanıldı.');
});
bind('connection', async () => {
  // The approval binds this choice to the identity shown; if the catalog
  // changed meanwhile the server refuses and the page shows the new one.
  const target = selectedTarget;
  if (!target?.available || target.id !== $('connection-target').value || !catalog.has(target.id)) throw new Error('server review missing');
  await request('/api/connections', 'POST', {name: $('connection-name').value, target: target.id, credential: $('connection-credential').value, approval: target.approval});
  $('connection-name').value = ''; await loadConnections(); notice('Bağlantı saxlanıldı.');
});
bind('trust-confirm', async () => {
  const current = reviewing;
  if (!current?.target.available) throw new Error('server review missing');
  await request(`/api/connections/${current.record.id}/trust`, 'POST', {approval: current.target.approval, revision: current.record.revision});
  closeReview(); await loadConnections(); notice('Yeni kimlik qəbul edildi. Bu bağlantının əvvəlki sessiyaları bağlandı.');
});
$('connection-target')?.addEventListener('change', () => { void chooseTarget().catch(error => notice(errorMessage(error))); });
$('cancel-trust')?.addEventListener('click', closeReview);
$('trust-dialog')?.addEventListener('close', closeReview);
$('credential-kind')?.addEventListener('change', () => {
  clearInputs(); const key = $('credential-kind').value === 'ssh-key'; $('key-fields').hidden = !key; $('password-fields').hidden = key;
});
$('key-file')?.addEventListener('change', () => { void run(async () => {
  const file = $('key-file').files[0]; $('credential-key').value = ''; if (!file) return;
  if (file.size > 65536) throw Object.assign(new Error('file too large'), { status: 400 });
  const content = await file.text(); $('key-file').value = '';
  if (document.visibilityState === 'visible') $('credential-key').value = content;
}); });
bind('password-change', async () => {
  const password = $('current-password').value, next = $('new-password').value, confirm = $('confirm-password').value; clearInputs();
  if (next !== confirm) { notice('Yeni şifrələr eyni deyil.'); return; }
  await request('/api/password', 'POST', { password, next }); clearAll(); location.replace('/login');
});
click('reset-mfa', async () => { await request('/api/mfa/reset', 'POST', {}); hideSecret(); await loadAccount(); });
click('regenerate-recovery', async () => { showCodes(await request('/api/mfa/recovery', 'POST', {})); });
click('saved-recovery', async () => { $('recovery-codes').value = ''; await loadAccount(); });
click('logout', async () => { hideSecret(); clearInputs(); await request('/api/session', 'DELETE', {}); clearAll(); location.replace('/login'); });
click('copy-seed', () => copy('seed')); click('copy-recovery', () => copy('recovery-codes'));
click('copy-secret', () => copy('revealed-secret')); click('copy-passphrase', () => copy('revealed-passphrase'));
$('hide-secret')?.addEventListener('click', hideSecret);
$('secret-dialog')?.addEventListener('close', hideSecret);
click('confirm-delete', async () => { const id = pendingDelete; pendingDelete = ''; $('delete-dialog').close(); if (!idOK(id)) return; await request(`/api/credentials/${id}`, 'DELETE', {}); hideSecret(); await loadRecords(); notice('Qeyd silindi.'); });
$('cancel-delete')?.addEventListener('click', () => { pendingDelete = ''; $('delete-dialog').close(); });
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') { hideSecret(); clearInputs(); closeReview(); hideSeed(); } });
window.addEventListener('pagehide', clearAll);
window.addEventListener('pageshow', event => { if (event.persisted) { clearAll(); location.reload(); } });
void run(async () => {
  if (document.body.dataset.screen === 'login') {
    const data = await request('/api/setup'); if (typeof data?.initialized !== 'boolean') throw new Error('invalid setup');
    $(data.initialized ? 'signin' : 'bootstrap').hidden = false;
  } else await loadAccount();
});
setInterval(() => {
  if (busy || !csrf || document.visibilityState !== 'visible' || !$('recovery')?.hidden) return;
  void run(async () => {
    try { const data = await request('/api/session'); if (data.csrf !== csrf) throw new Error('session changed'); }
    catch (error) { hideSecret(); if (error.status === 401) { clearAll(); location.replace('/login'); } else throw error; }
  });
}, 30000);
