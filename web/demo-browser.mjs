// Test-only launcher: a disposable browser context, synthetic credentials and
// loopback TLS. This file is not included in the embedded runtime asset list.
import {chromium} from 'playwright';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHmac} from 'node:crypto';

const config = JSON.parse(readFileSync(0, 'utf8'));
const origin = new URL(config.Origin);
assert.equal(origin.protocol, 'https:');
assert.equal(origin.hostname, '127.0.0.1');
assert.equal(origin.pathname, '/');
assert.equal(origin.search + origin.hash + origin.username + origin.password, '');
const browser = await chromium.launch({headless: !config.Interactive, ...(process.env.KEYBASH_BROWSER_CHANNEL ? {channel: process.env.KEYBASH_BROWSER_CHANNEL} : {})});
const context = await browser.newContext({ignoreHTTPSErrors: true, acceptDownloads: false, serviceWorkers: 'block', viewport: {width: 1440, height: 1000}});
// Self-signed acceptance is confined to this disposable test context. Block
// external page/worker traffic; never change OS trust or normal browser flags.
await context.route('**/*', route => route.request().url().startsWith(config.Origin + '/') ? route.continue() : route.abort());
const errors = [];
context.on('page', page => page.on('pageerror', error => errors.push(error.name)));
const account = await context.newPage();
let stage = 'bootstrap';
let timer;
function otp(seed, counter) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bits = [...seed].map(ch => alphabet.indexOf(ch).toString(2).padStart(5, '0')).join('');
  const key = Buffer.from(bits.match(/.{8}/g).map(byte => parseInt(byte, 2)));
  const raw = Buffer.alloc(8); raw.writeBigUInt64BE(BigInt(counter));
  const hash = createHmac('sha1', key).update(raw).digest();
  return ((hash.readUInt32BE(hash[19] & 15) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}
async function settle() { await account.waitForFunction(() => !document.getElementById('logout')?.disabled); }
try {
  await account.goto(config.Origin + '/login');
  await account.locator('#setup-code').fill(config.Code);
  await account.locator('#setup-user').fill('demo');
  await account.locator('#setup-password').fill(config.Password);
  await account.locator('#bootstrap button').click();
  await account.waitForURL(config.Origin + '/'); await settle();
  assert.equal((await account.request.get(config.Origin + '/api/connections')).status(), 403);
  stage = 'MFA';
  await account.locator('#begin-enroll').click();
  await account.locator('#seed-panel').waitFor({state: 'visible'});
  const seed = await account.locator('#seed').textContent(); await settle();
  const counter = Math.floor(Date.now() / 30000);
  await account.locator('#enrollment-code').fill(otp(seed, counter));
  await account.locator('#enrollment button').click();
  await account.locator('#recovery').waitFor({state: 'visible'}); await settle();
  const recovery = (await account.locator('#recovery-codes').inputValue()).split('\n');
  await account.locator('#saved-recovery').click(); await account.locator('#vault').waitFor({state: 'visible'}); await settle();
  await account.locator('#reauth-password').fill(config.Password);
  // Consume an ordinary one-use recovery code for initial reauthentication;
  // this avoids reusing the enrollment TOTP or a wall-clock boundary race.
  await account.locator('#reauth-code').fill(recovery[0]);
  await account.locator('#reauth button').click();
  await account.locator('#notice').filter({hasText: 'Doğrulandı'}).waitFor(); await settle();
  stage = 'sample connections';
  const state = await (await account.request.get(config.Origin + '/api/session')).json();
  const headers = {Origin: config.Origin, 'X-Keybash-Request': '1', 'X-Keybash-CSRF': state.csrf};
  const connections = {};
  const fingerprints = {ssh: config.SSHFingerprint, rdp: config.RDPFingerprint};
  for (const [mode, name, secret, target] of [
    ['ssh', 'Linux SSH · UI simulyasiyası', config.SSHSecret, config.SSH],
    ['rdp', 'Desktop · UI simulyasiyası (Windows deyil)', config.RDPSecret, config.RDP]
  ]) {
    const saved = await account.request.post(config.Origin + '/api/credentials', {headers, data: {name, kind: mode === 'ssh' ? 'ssh-key' : 'password', username: 'synthetic-user', secret, passphrase: ''}});
    assert.equal(saved.status(), 200);
    const credential = await saved.json();
    const linked = await account.request.post(config.Origin + '/api/connections', {headers, data: {name, target, credential: credential.id, fingerprint: fingerprints[mode], approval: (await (await account.request.get(config.Origin + '/api/targets/' + target)).json()).approval}});
    assert.equal(linked.status(), 200);
    connections[mode] = (await linked.json()).id;
  }
  await account.reload(); await account.locator('#connections-panel').waitFor({state: 'visible'}); await settle();
  const screenshot = process.env.KEYBASH_DEMO_SCREENSHOT;
  if (screenshot && !config.Interactive) await account.screenshot({path: screenshot + '-workspace.png', fullPage: true});

  {
    stage = 'interactive guide';
    const guide = await context.newPage();
    // about:blank is a separate disposable guide, never a product route or
    // script injected into the application. Only synthetic demo factors here.
    await guide.setContent(`<!doctype html><html lang="az"><meta charset="utf-8"><title>Keybash · Demo bələdçisi</title><style>
      body{background:#111216;color:#e8eaf0;font:17px system-ui;max-width:820px;margin:52px auto;padding:0 24px;line-height:1.6}h1{font-size:38px}strong{color:#ff6977}code,output{background:#20232b;padding:8px 12px;border-radius:6px;display:inline-block}output{font-size:28px;letter-spacing:5px}button{background:#d62f43;color:white;border:0;border-radius:6px;padding:12px 20px;font:inherit;cursor:pointer}textarea{width:100%;height:90px;background:#20232b;color:#eee;border:1px solid #444}small{color:#b3bac8}li{margin:10px 0}</style>
      <h1>keybash<span style="color:#e34254">.</span> Demo</h1>
      <p><strong>Bu, lokal UI simulyasiyasıdır.</strong> Real Linux shell və Windows yoxdur. Öz server açarlarını və şifrələrini daxil etmə.</p>
      <button id="workspace">İş yerini aç</button>
      <ol><li>İş yerində iki nümunə bağlantı var. <b>Qoşul</b> seç.</li><li>Terminalda <code>help</code>, <code>whoami</code>, <code>echo Salam dostum</code>, Ctrl+C və paste preview-ni sına.</li><li>Desktop-da kliklə, yaz, Backspace/Enter və tam ekranı sına. RDP clipboard/remote resize hələ bağlıdır.</li><li>İki dəqiqədən sonra yeni bağlantı üçün hesabda təkrar doğrula. Logout bütün açıq bağlantıları bağlayır.</li></ol>
      <p>Demo istifadəçisi: <code>demo</code><br>Demo giriş şifrəsi: <code id="password"></code></p>
      <p>Hazırkı MFA kodu: <output id="otp"></output><br><small id="remaining"></small><br><small>Eyni kod bir dəfə işləyir. Açılışda işlənmiş kod üçün növbəti 30 saniyəlik kodu gözlə.</small></p>
      <details><summary>Demo MFA seed və birdəfəlik bərpa kodları</summary><p>Autentifikatora əl ilə əlavə etmək üçün: <code id="seed"></code></p><textarea id="recovery" readonly></textarea><p>Hər bərpa kodunu yalnız bir dəfə işlət. Bunlar yalnız bu müvəqqəti demo üçündür.</p></details>
      <details><summary>Demo server kimlikləri</summary><p>Yeni demo bağlantısını təsdiqləmək üçün ayrıca fixture məlumatı:</p><p>SSH: <code id="ssh-fingerprint"></code></p><p>RDP: <code id="rdp-fingerprint"></code></p></details><p><small>Bütün demo pəncərələrini bağlayanda və ya bir saatdan sonra sessiya bitir. Hər işə salma yeni, müvəqqəti məlumatlarla başlayır.</small></p></html>`);
    await guide.locator('#ssh-fingerprint').evaluate((el, value) => { el.textContent = value; }, config.SSHFingerprint);
    await guide.locator('#rdp-fingerprint').evaluate((el, value) => { el.textContent = value; }, config.RDPFingerprint);
    await guide.locator('#password').evaluate((el, value) => { el.textContent = value; }, config.Password);
    await guide.locator('#seed').evaluate((el, value) => { el.textContent = value; }, seed);
    await guide.locator('#recovery').evaluate((el, value) => { el.value = value; }, recovery.slice(1).join('\n'));
    await guide.exposeFunction('openWorkspace', async () => {
      if (!account.isClosed()) await account.bringToFront();
      else await (await context.newPage()).goto(config.Origin + '/');
    });
    await guide.locator('#workspace').evaluate(el => el.addEventListener('click', () => { void window.openWorkspace(); }));
    const update = async () => {
      if (guide.isClosed()) return;
      const now = Math.floor(Date.now() / 1000);
      await guide.evaluate(({code, seconds}) => {
        document.getElementById('otp').textContent = code;
        document.getElementById('remaining').textContent = `Növbəti kod ${seconds} saniyə sonra.`;
      }, {code: otp(seed, Math.floor(now / 30)), seconds: 30 - now % 30});
    };
    await update();
    timer = setInterval(() => { void update().catch(() => {}); }, 1000);
    await guide.bringToFront();
    if (config.Interactive) {
      console.log('Keybash demo hazırdır. Ayrı brauzer pəncərəsində bələdçi və iş yeri açıldı. Demo maksimum bir saat işləyir.');
      await new Promise(resolve => {
        browser.on('disconnected', resolve);
        const check = () => { if (context.pages().length === 0) resolve(); };
        for (const page of context.pages()) page.on('close', check);
        context.on('page', page => page.on('close', check));
      });
    } else {
      assert.match(await guide.locator('#otp').textContent(), /^[0-9]{6}$/);
      assert.equal((await guide.locator('#recovery').inputValue()).split('\n').length, 9);
      await guide.locator('#workspace').click();
      await account.waitForFunction(() => document.visibilityState === 'visible');
      await guide.close();
    }
  }
  if (!config.Interactive) {
    stage = 'SSH simulation';
    const terminal = await context.newPage();
    await terminal.goto(config.Origin + '/remote/ssh/' + connections.ssh);
    await terminal.locator('#status').filter({hasText: 'Qoşulub'}).waitFor();
    await terminal.locator('.xterm-helper-textarea').focus();
    await terminal.keyboard.type('echo Salam dostum'); await terminal.keyboard.press('Enter');
    await terminal.waitForFunction(() => (document.querySelector('.xterm-rows')?.textContent.match(/Salam dostum/g) ?? []).length >= 2);
    if (screenshot) await terminal.screenshot({path: screenshot + '-terminal.png'});
    stage = 'desktop simulation';
    const desktop = await context.newPage();
    await desktop.goto(config.Origin + '/remote/rdp/' + connections.rdp);
    await desktop.locator('#status').filter({hasText: 'Sessiya açıldı'}).waitFor();
    await desktop.waitForFunction(() => [...document.querySelectorAll('#display canvas')].some(c => c.width >= 1024 && c.height >= 768 && c.getContext('2d').getImageData(0, 0, 1, 1).data[0] > 200));
    const pixels = () => desktop.evaluate(() => {
      const canvas = [...document.querySelectorAll('#display canvas')].find(c => c.width >= 1024 && c.height >= 768);
      return JSON.stringify([...canvas.getContext('2d').getImageData(52, 350, 600, 14).data]);
    });
    const beforeInput = await pixels();
    await desktop.locator('#desktop').focus(); await desktop.keyboard.press('a');
    await desktop.waitForFunction(before => {
      const canvas = [...document.querySelectorAll('#display canvas')].find(c => c.width >= 1024 && c.height >= 768);
      return JSON.stringify([...canvas.getContext('2d').getImageData(52, 350, 600, 14).data]) !== before;
    }, beforeInput);
    const beforeMouse = await pixels();
    const box = await desktop.locator('#display').boundingBox(); assert(box);
    await desktop.mouse.click(box.x + 120, box.y + 120);
    await desktop.waitForFunction(before => {
      const canvas = [...document.querySelectorAll('#display canvas')].find(c => c.width >= 1024 && c.height >= 768);
      return JSON.stringify([...canvas.getContext('2d').getImageData(52, 350, 600, 14).data]) !== before;
    }, beforeMouse);
    if (screenshot) await desktop.screenshot({path: screenshot + '-desktop.png'});
    stage = 'logout revocation';
    await account.bringToFront(); await account.locator('#logout').click(); await account.waitForURL(config.Origin + '/login');
    await terminal.waitForFunction(() => document.getElementById('terminal').childElementCount === 0);
    await desktop.waitForFunction(() => document.getElementById('display').childElementCount === 0);
    assert.deepEqual(errors, []);
    console.log('Interactive demo browser: MFA, owned samples, terminal input, desktop drawing/input and logout passed.');
  }
} catch (error) {
  // Never reflect Playwright request/fill diagnostics containing fixture data.
  console.error('Demo stage failed:', stage, error.name);
  process.exitCode = 1;
} finally {
  clearInterval(timer);
  await browser.close();
}
