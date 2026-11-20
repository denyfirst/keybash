import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createInterface } from 'node:readline';

// The whole desktop path on Linux (internal/rdplab, desktop_native_linux_test.go):
// a fresh installation's pages, the gateway, the RDP manager, the proxy in the
// worker's sandbox and the test peer. The test reads what reached the peer; this
// driver prints KB_INPUT_SENT and waits for its word before signing out.
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const config = JSON.parse((await lines.next()).value);
assert.equal(new URL(config.Origin).hostname, '127.0.0.1');
assert.match(config.Target, /^[a-f0-9]{32}$/);
const browser = await chromium.launch({ headless: true, ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 1000 } });
const account = await context.newPage(), page = await context.newPage(), scratch = await browser.newPage();
const errors = [], outbound = [], urls = [];
for (const p of [account, page]) p.on('pageerror', error => errors.push(error.name));
context.on('request', r => {
  const url = r.url();
  if (!url.startsWith(config.Origin + '/') && !url.startsWith('blob:' + config.Origin + '/')) outbound.push('external');
  if ([config.Password, config.Secret, config.Code].some(s => url.includes(s) || url.includes(encodeURIComponent(s)))) urls.push('secret in a URL');
});
function otp(seed, counter) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of seed) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', key).update(b).digest();
  return ((h.readUInt32BE(h[19] & 15) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}
const settle = () => account.waitForFunction(() => !document.getElementById('logout')?.disabled);
// The middle of the desktop as the browser shows it, read from a screenshot in
// a page of its own, so the desktop page's policy is untouched.
async function middle() {
  const shot = await page.locator('#screen-canvas').screenshot();
  return scratch.evaluate(async png => {
    const image = await createImageBitmap(await (await fetch('data:image/png;base64,' + png)).blob());
    const c = new OffscreenCanvas(image.width, image.height), g = c.getContext('2d');
    g.drawImage(image, 0, 0);
    return [...g.getImageData(image.width >> 1, image.height >> 1, 1, 1).data.slice(0, 3)];
  }, shot.toString('base64'));
}
let stage = 'bootstrap';
try {
  await account.goto(config.Origin + '/login');
  await account.locator('#setup-code').fill(config.Code); await account.locator('#setup-user').fill('alice'); await account.locator('#setup-password').fill(config.Password);
  await account.locator('#bootstrap button').click(); await account.waitForURL(config.Origin + '/'); await settle();
  stage = 'second factor';
  await account.locator('#begin-enroll').click(); await account.locator('#seed-panel').waitFor({ state: 'visible' });
  const seed = await account.locator('#seed').textContent(); await settle();
  await account.locator('#enrollment-code').fill(otp(seed, Math.floor(Date.now() / 30000))); await account.locator('#enrollment button').click();
  await account.locator('#recovery').waitFor({ state: 'visible' }); await settle();
  await account.locator('#saved-recovery').click(); await account.locator('#vault').waitFor({ state: 'visible' }); await settle();

  stage = 'the server\'s password and connection';
  const state = await (await account.request.get(config.Origin + '/api/session')).json();
  const headers = { Origin: config.Origin, 'X-Keybash-Request': '1', 'X-Keybash-CSRF': state.csrf };
  const saved = await account.request.post(config.Origin + '/api/credentials', { headers, data: { name: 'Synthetic Windows', kind: 'password', username: 'synthetic-user', secret: config.Secret, passphrase: '' } });
  assert.equal(saved.status(), 200); const credential = await saved.json();
  const users = await (await account.request.get(config.Origin + '/api/users')).json();
  assert.equal((await account.request.post(config.Origin + '/api/servers/' + config.Target + '/grant', { headers, data: { account: users.self } })).status(), 204);
  const target = await (await account.request.get(config.Origin + '/api/targets/' + config.Target)).json();
  const made = await account.request.post(config.Origin + '/api/connections', { headers, data: { name: 'Synthetic desktop', target: config.Target, credential: credential.id, approval: target.approval } });
  assert.equal(made.status(), 200); const connection = await made.json();

  stage = 'the desktop opens';
  await account.reload(); await settle();
  const link = account.getByRole('link', { name: 'Connect', exact: true });
  assert.equal(await link.getAttribute('href'), '/remote/rdp/' + connection.id);
  await page.goto(config.Origin + '/remote/rdp/' + connection.id);
  await page.locator('#status').filter({ hasText: /^Connected$/ }).waitFor({ timeout: 30000 });
  stage = 'the peer\'s grey desktop';
  for (const until = Date.now() + 20000; ;) {
    const [r, g, b] = await middle();
    if ([r, g, b].every(v => Math.abs(v - 160) <= 3)) break;
    assert.ok(Date.now() < until, `the desktop's middle is ${r},${g},${b}, not the peer's grey`);
    await page.waitForTimeout(200);
  }

  stage = 'input';
  await page.locator('#screen-canvas').click();
  await page.keyboard.press('KeyA');
  console.log('KB_INPUT_SENT');
  const word = await Promise.race([lines.next(), new Promise(resolve => setTimeout(() => resolve({ value: 'timeout' }), 30000))]);
  assert.equal(word.value, 'peer-saw-input', 'the test did not see the input at the peer');

  stage = 'signing out ends the desktop';
  await account.bringToFront(); await account.locator('#logout').click(); await account.waitForURL(config.Origin + '/login');
  await page.locator('#notice').filter({ hasText: /^You were signed out of Keybash, so this session ended\.$/ }).waitFor({ timeout: 15000 });
  assert.equal(await page.locator('#status').textContent(), 'Session ended');
  assert.deepEqual(await page.evaluate(() => { const c = document.getElementById('screen-canvas'); return [c.width, c.height]; }), [0, 0], 'the desktop\'s picture stayed');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.deepEqual(errors, []); assert.deepEqual(outbound, []); assert.deepEqual(urls, []);
  console.log('Native desktop: sign-up, second factor, saved password, the peer\'s desktop, input at the peer and sign-out passed');
} catch (error) {
  console.log('Native desktop stage:', stage, error.code === 'ERR_ASSERTION' ? error.message : error.name);
  if (process.env.KEYBASH_DESKTOP_SCREENSHOT) await page.screenshot({ path: process.env.KEYBASH_DESKTOP_SCREENSHOT });
  process.exitCode = 1;
} finally {
  await context.close(); await browser.close();
  process.stdin.destroy();
}
