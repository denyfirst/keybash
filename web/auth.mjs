const $ = id => document.getElementById(id);
const form = document.querySelector('form');
const fields = [...document.querySelectorAll('input')];
let busy = false, csrf = '', active;
const clear = () => fields.filter(field => field.type === 'password').forEach(field => { field.value = ''; });
const lock = value => { busy = value; for (const el of document.querySelectorAll('input,button')) el.disabled = value; };
function leave() { clear(); active?.abort(); }
window.addEventListener('pagehide', () => { leave(); csrf=''; if ($('account')) $('account').textContent=''; });
document.addEventListener('visibilitychange', () => { if (document.hidden) leave(); });
window.addEventListener('pageshow', event => { if (event.persisted) { leave(); location.reload(); } });

async function request(path, method, body) {
  const controller = new AbortController();
  active = controller;
  const timer = setTimeout(() => controller.abort(), 15000);
  let reader;
  try {
    const response = await fetch(path, {method, credentials:'same-origin', cache:'no-store', signal:controller.signal,
      headers:{'Content-Type':'application/json','X-Keybash-Request':'1','X-Keybash-CSRF':csrf},
      body:body === undefined ? undefined : JSON.stringify(body)});
    if (method !== 'GET' || response.status !== 200) {
      if (response.body) void response.body.cancel().catch(()=>{});
      return {status:response.status};
    }
    if (response.headers.get('Content-Type') !== 'application/json; charset=utf-8' || !response.body) throw new Error('invalid response');
    reader = response.body.getReader();
    const parts=[]; let length=0;
    while (true) {
      const {value,done}=await reader.read();
      if (controller.signal.aborted) throw new Error('unconfirmed');
      if (done) break;
      length+=value.byteLength;
      if (length>2048) throw new Error('response limit');
      parts.push(value);
    }
    const bytes=new Uint8Array(length); let offset=0;
    for (const part of parts) {bytes.set(part,offset);offset+=part.byteLength;}
    const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    if (!/^\s*\{\s*"username"\s*:\s*"[a-z0-9._-]{1,64}"\s*,\s*"csrf"\s*:\s*"[A-Za-z0-9_-]{43}"\s*\}\s*$/.test(text)) throw new Error('invalid response');
    return {status:response.status,data:JSON.parse(text)};
  } finally {
    clearTimeout(timer); active=undefined;
    if (reader) {void reader.cancel().catch(()=>{});reader.releaseLock();}
  }
}
async function account() {
  lock(true);
  try {
    const response = await request('/api/session','GET');
    if (response.status === 401) { location.replace('/login'); return; }
    if (response.status !== 200 || document.hidden) throw new Error('unavailable');
    const data=response.data;
    csrf = data.csrf; $('account').textContent = data.username;
    if (!document.hidden) lock(false);
  } catch { $('notice').textContent = 'The session could not be checked. Reload the page.'; }
}
if (document.body.dataset.screen === 'account') void account();
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || document.hidden) return;
  const login = form.id === 'login';
  if (!login && $('replacement').value !== $('confirm').value) { $('notice').textContent='The new passwords don’t match.'; return; }
  const body = login ? {username:$('username').value,password:$('password').value} : {password:$('current').value,next:$('replacement').value};
  clear(); lock(true); $('notice').textContent = '';
  try {
    const response = await request(login ? '/api/session' : '/api/password','POST',body);
    if (document.hidden) throw new Error('unconfirmed');
    if (response.status === 204) { location.assign(login ? '/' : '/login'); return; }
    $('notice').textContent = response.status === 429 ? 'Too many attempts. Try again in a minute.' :
      response.status === 401 ? 'The username or password was not accepted.' :
      response.status === 400 ? 'Check the details. The new password needs at least 15 characters.' : 'The request did not complete. Reload the page.';
  } catch { $('notice').textContent = 'Not confirmed. Reload the page before trying again.'; }
  finally { delete body.password; delete body.next; clear(); lock(false); }
});
$('logout')?.addEventListener('click', async () => {
  if (busy || document.hidden) return;
  clear(); lock(true);
  try {
    const response = await request('/api/session','DELETE');
    if (response.status !== 204 || document.hidden) throw new Error('unconfirmed');
    csrf = ''; location.replace('/login');
  } catch { $('notice').textContent='Sign-out was not confirmed. Try again before leaving this device.'; }
  finally { clear(); lock(false); }
});
