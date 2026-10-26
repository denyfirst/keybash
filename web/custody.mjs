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
  for (const id of ['credential-key', 'key-file', 'connection-fingerprint', 'trust-fingerprint']) if ($(id)) $(id).value = '';
}
function clearAll() {
  hideSecret(); clearInputs(); closeReview(); csrf = ''; catalog.clear(); selectedTarget = null; ++targetGeneration;
  for (const id of ['seed', 'account', 'records', 'connections', 'connection-server']) if ($(id)) $(id).textContent = '';
  if ($('recovery-codes')) $('recovery-codes').value = '';
  for (const id of sections) if ($(id)) $(id).hidden = true;
}
async function request(path, method = 'GET', value) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const headers = { 'X-Keybash-Request': '1' };
    if (method !== 'GET') { headers['Content-Type'] = 'application/json'; headers['X-Keybash-CSRF'] = csrf; }
    const response = await fetch(path, { method, headers, body: value === undefined ? undefined : JSON.stringify(value), credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal });
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
function errorMessage(error) {
  hideSecret();
  if (error.status === 'setup') return 'Quraşdırma kodu qəbul edilmədi. Administratordan aldığın birdəfəlik kodu yoxla; vaxtı keçibsə yenisini istə.';
  if (error.status === 403) return 'Bu əməliyyat üçün giriş şifrəsi və yeni MFA kodu ilə təkrar doğrula.';
  if (error.status === 409) return 'Fingerprint uyğun gəlmədi və ya server məlumatı dəyişib. Məlumatı yenilə və ayrıca etibarlı kanaldan yoxla.';
  if (error.status === 429) return 'Cəhd limiti dolub. Bir qədər gözlə.';
  if (error.status === 401) return 'Doğrulama qəbul edilmədi və ya sessiya bitib. Kodu yoxla; lazım olsa yenidən daxil ol.';
  if (error.status === 400) return 'Məlumat qəbul edilmədi. Şifrəni, kodu və açarın formatını yoxla.';
  return 'Əməliyyat təsdiqlənmədi. Bağlantını yoxla və hesabın vəziyyətini yenilə.';
}
async function run(action) {
  if (busy) return;
  busy = true; notice('');
  const buttons = [...document.querySelectorAll('button')]; buttons.forEach(el => { el.disabled = true; });
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
  clearInputs(); hideSecret(); $('seed').textContent = ''; $('seed-panel').hidden = true;
  sections.forEach(id => { $(id).hidden = id !== 'recovery'; });
  $('heading').textContent = 'Bərpa kodların hazırdır.';
  $('recovery-codes').value = data.codes.join('\n');
}
async function loadRecords() {
  const records = await request('/api/credentials');
  if (!Array.isArray(records) || records.length > 256) throw new Error('invalid records');
  $('records').replaceChildren();
  for (const record of records) {
    if (!idOK(record.id) || typeof record.name !== 'string' || !['password', 'ssh-key'].includes(record.kind) || typeof record.username !== 'string' || typeof record.fingerprint !== 'string') throw new Error('invalid record');
    const row = document.createElement('div'); row.className = 'record';
    const label = document.createElement('span'); label.textContent = `${record.name} · ${record.kind === 'ssh-key' ? 'SSH' : 'Şifrə'} · ${record.username}${record.fingerprint ? ' · ' + record.fingerprint : ''}`;
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
    row.append(label, reveal, remove); $('records').append(row);
  }
  if (!records.length) $('records').textContent = 'Hələ qeyd yoxdur.';
  if(remoteEnabled){$('connection-credential').replaceChildren();for(const record of records){const option=document.createElement('option');option.value=record.id;option.textContent=`${record.name} · ${record.kind}`;$('connection-credential').append(option);}await loadConnections();}
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
  return `${data.hostname}:${data.port} · ${data.protocol.toUpperCase()}\nİcazəli IP-lər: ${data.addresses.join(', ')}\n${data.algorithm}\n${data.fingerprint}${data.available ? '' : '\nServer kimliyi hazırda istifadəyə yararlı deyil.'}`;
}
async function chooseTarget() {
  const id = $('connection-target').value, generation = ++targetGeneration;
  selectedTarget = null; $('connection-fingerprint').value = ''; $('connection-server').textContent = 'Server məlumatı yoxlanır…'; updateTrustButtons();
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
  if ($('trust-fingerprint')) $('trust-fingerprint').value = '';
  updateTrustButtons();
}
async function openReview(record) {
  closeReview(); const generation = ++reviewGeneration;
  $('trust-title').textContent = record.name; $('trust-server').textContent = 'Server məlumatı yoxlanır…';
  $('trust-previous').textContent = record.fingerprint ? `Əvvəl təsdiqlədiyin fingerprint: ${record.fingerprint}` : 'Bu bağlantı üçün ayrıca kimlik təsdiqi yoxdur.';
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
    if (target && record.trust === 'verified') { const link = document.createElement('a'); link.textContent = 'Qoşul'; link.href = `/remote/${target.protocol}/${record.id}`; row.append(link); }
    if (target) { const review = document.createElement('button'); review.type = 'button'; review.className = 'secondary'; review.textContent = 'Server kimliyi'; review.addEventListener('click', () => { void run(() => openReview(record)); }); row.append(review); }
    const remove = document.createElement('button'); remove.textContent = 'Bağlantını sil'; remove.type = 'button'; remove.className = 'secondary'; remove.addEventListener('click', () => { void run(async () => { await request(`/api/connections/${record.id}`, 'DELETE', {}); await loadConnections(); }); }); row.append(remove); rows.append(row);
  }
  catalog = approved; $('connection-target').replaceChildren(options); if (approved.has(previous)) $('connection-target').value = previous; $('connections').replaceChildren(rows);
  if (!connections.length) $('connections').textContent = 'Hələ bağlantı yoxdur.';
  await chooseTarget();
}
async function loadAccount() {
  const data = await request('/api/session');
  if (typeof data?.username !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(data.username) || typeof data.csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.csrf) || !['enroll', 'challenge', 'ready'].includes(data.stage)) throw new Error('invalid session');
  csrf = data.csrf; $('account').textContent = data.username;
  remoteEnabled=data.remote===true;$('connections-panel').hidden=!remoteEnabled;
  setupRequired = data.stage === 'enroll' && data.setup === true; $('setup-proof').hidden = !setupRequired;
  sections.forEach(id => { $(id).hidden = true; });
  $('heading').textContent = data.stage === 'ready' ? 'Açarların öz yerində.' : data.stage === 'enroll' ? 'MFA-nı quraq.' : 'Girişini təsdiqlə.';
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
  if (typeof data?.secret !== 'string' || !/^[A-Z2-7]{32}$/.test(data.secret)) throw new Error('invalid seed');
  if (document.visibilityState !== 'visible') return;
  $('seed').textContent = data.secret; $('seed-panel').hidden = false;
});
bind('enrollment', async () => { const code = $('enrollment-code').value; clearInputs(); showCodes(await request('/api/mfa/confirm', 'POST', { code })); });
bind('factor', async () => { const code = $('factor-code').value; clearInputs(); await request('/api/mfa/verify', 'POST', { code }); await loadAccount(); });
bind('reauth', async () => {
  const password = $('reauth-password').value, code = $('reauth-code').value; clearInputs();
  await request('/api/reauth', 'POST', { password, code }); notice('Doğrulandı. Həssas əməliyyatlar iki dəqiqə ərzində mümkündür.');
});
bind('credential', async () => {
  const kind = $('credential-kind').value;
  const value = { name: $('credential-name').value, kind, username: $('credential-user').value, secret: $(kind === 'password' ? 'credential-password' : 'credential-key').value, passphrase: kind === 'ssh-key' ? $('credential-passphrase').value : '' };
  clearInputs(); await request('/api/credentials', 'POST', value); $('credential').reset(); await loadRecords(); notice('Şifrələnmiş qeyd saxlanıldı.');
});
bind('connection', async () => {
  const target = selectedTarget, fingerprint = $('connection-fingerprint').value; $('connection-fingerprint').value = '';
  if (!target?.available || target.id !== $('connection-target').value || !catalog.has(target.id)) throw new Error('server review missing');
  await request('/api/connections', 'POST', {name: $('connection-name').value, target: target.id, credential: $('connection-credential').value, fingerprint, approval: target.approval});
  $('connection-name').value = ''; await loadConnections(); notice('Server kimliyi təsdiqləndi, bağlantı saxlanıldı.');
});
bind('trust-confirm', async () => {
  const current = reviewing, fingerprint = $('trust-fingerprint').value; $('trust-fingerprint').value = '';
  if (!current?.target.available) throw new Error('server review missing');
  await request(`/api/connections/${current.record.id}/trust`, 'POST', {fingerprint, approval: current.target.approval, revision: current.record.revision});
  closeReview(); await loadConnections(); notice('Server kimliyi yenidən təsdiqləndi. Bu bağlantının əvvəlki sessiyaları bağlandı.');
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
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') { hideSecret(); clearInputs(); closeReview(); if ($('seed')) { $('seed').textContent = ''; $('seed-panel').hidden = true; } } });
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
