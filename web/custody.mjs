const $ = id => document.getElementById(id);
let csrf = '', busy = false, secretTimer, pendingDelete = '', remoteEnabled = false;
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
function clearAll() {
  hideSecret(); clearInputs(); csrf = '';
  for (const id of ['seed', 'account', 'records']) if ($(id)) $(id).textContent = '';
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
  if (error.status === 403) return 'Bu əməliyyat üçün giriş şifrəsi və yeni MFA kodu ilə təkrar doğrula.';
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
  finally { busy = false; buttons.forEach(el => { el.disabled = false; }); }
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
async function loadConnections(){
 const targets=await request('/api/targets'),connections=await request('/api/connections');
 if(!Array.isArray(targets)||targets.length>256||!Array.isArray(connections)||connections.length>128)throw new Error('invalid connections');
 const approved=new Map();$('connection-target').replaceChildren();
 for(const target of targets){if(!idOK(target.id)||typeof target.name!=='string'||!['ssh','rdp'].includes(target.protocol))throw new Error('invalid target');approved.set(target.id,target);const option=document.createElement('option');option.value=target.id;option.textContent=`${target.name} · ${target.protocol.toUpperCase()}`;$('connection-target').append(option);}
 $('connections').replaceChildren();for(const record of connections){if(!idOK(record.id)||typeof record.name!=='string'||!idOK(record.target)||!idOK(record.credential))throw new Error('invalid connection');const row=document.createElement('div');row.className='record';const name=document.createElement('span');name.textContent=record.name;row.append(name);const target=approved.get(record.target);if(target){const link=document.createElement('a');link.textContent='Qoşul';link.href=`/remote/${target.protocol}/${record.id}`;row.append(link);}const remove=document.createElement('button');remove.textContent='Bağlantını sil';remove.type='button';remove.className='secondary';remove.addEventListener('click',()=>{void run(async()=>{await request(`/api/connections/${record.id}`,'DELETE',{});await loadConnections();});});row.append(remove);$('connections').append(row);}
 if(!connections.length)$('connections').textContent='Hələ bağlantı yoxdur.';
}
async function loadAccount() {
  const data = await request('/api/session');
  if (typeof data?.username !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(data.username) || typeof data.csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.csrf) || !['enroll', 'challenge', 'ready'].includes(data.stage)) throw new Error('invalid session');
  csrf = data.csrf; $('account').textContent = data.username;
  remoteEnabled=data.remote===true;$('connections-panel').hidden=!remoteEnabled;
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
  const data = await request('/api/mfa/enrollment', 'POST', {});
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
bind('connection',async()=>{await request('/api/connections','POST',{name:$('connection-name').value,target:$('connection-target').value,credential:$('connection-credential').value});$('connection-name').value='';await loadConnections();notice('Bağlantı saxlanıldı.');});
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
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') { hideSecret(); clearInputs(); if ($('seed')) { $('seed').textContent = ''; $('seed-panel').hidden = true; } } });
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
