import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
const config = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(new URL(config.Origin).hostname, '127.0.0.1');
const browser = await chromium.launch({ headless: true, ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1100 } });
const page = await context.newPage(); const errors = [], external = [], secretURLs = [];
const vaultSecret = 'Synthetic browser custody canary 73'; let seed = '', codes = [], seconds = config.Unix;
page.on('pageerror', error => errors.push(error.name));
page.on('request', request => {
  if (!request.url().startsWith(config.Origin + '/')) external.push('external request');
  if ([config.Password, config.Code, vaultSecret, seed, ...codes].filter(Boolean).some(secret => request.url().includes(secret) || request.url().includes(encodeURIComponent(secret)))) secretURLs.push('secret URL');
});
function otp(counter = Math.floor(seconds / 30)) {
  // Independent RFC 4226/6238 test oracle, never shipped by the application.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of seed) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
  const input = Buffer.alloc(8); input.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', key).update(input).digest(); const offset = digest[19] & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}
async function fixture(action) { const response = await page.request.post(config.Origin + '/__fixture/' + action, { headers: { 'X-Fixture-Control': config.Control } }); assert.equal(response.status(), 200); seconds = (await response.json()).Unix; }
async function settled() { await page.waitForFunction(() => !document.getElementById('logout')?.disabled); }
async function session() { return (await page.request.get(config.Origin + '/api/session')).json(); }
async function api(path, data, method = 'POST') { const state = await session(); return page.request.fetch(config.Origin + path, { method, headers: { Origin: config.Origin, 'X-Keybash-Request': '1', 'X-Keybash-CSRF': state.csrf, 'Content-Type': 'application/json' }, data }); }
async function login() { await page.locator('#username').fill(config.Username); await page.locator('#password').fill(config.Password); await page.locator('#signin button').click(); await page.waitForURL(config.Origin + '/'); await settled(); }
async function reauth(code) { await page.locator('#reauth-password').fill(config.Password); await page.locator('#reauth-code').fill(code); await page.locator('#reauth button').click(); await page.locator('#notice').filter({ hasText: 'Doğrulandı' }).waitFor(); await settled(); }
try {
  await page.goto(config.Origin + '/'); await page.waitForURL(config.Origin + '/login');
  await page.locator('#bootstrap').waitFor({ state: 'visible' });
  await page.locator('#setup-code').fill(config.Code); await page.locator('#setup-user').fill(config.Username); await page.locator('#setup-password').fill(config.Password); await page.locator('#bootstrap button').click();
  await page.waitForURL(config.Origin + '/'); await page.locator('#enroll').waitFor({ state: 'visible' }); await settled();
  assert.equal((await page.request.get(config.Origin + '/api/credentials')).status(), 403, 'password-only vault access');
  await page.locator('#begin-enroll').click(); await page.locator('#seed-panel').waitFor({ state: 'visible' }); seed = await page.locator('#seed').textContent(); assert.match(seed, /^[A-Z2-7]{32}$/); await settled();
  await page.locator('#enrollment-code').fill(otp(Math.floor(seconds / 30) - 1)); await page.locator('#enrollment button').click(); await page.locator('#recovery').waitFor({ state: 'visible' }); codes = (await page.locator('#recovery-codes').inputValue()).split('\n'); assert.equal(codes.length, 10); await settled();
  await page.locator('#saved-recovery').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('#recovery-codes').inputValue(), '');
  assert.equal((await api('/api/credentials', { name: 'x', kind: 'password', username: '', secret: vaultSecret, passphrase: '' })).status(), 403, 'fresh factor bypass');
  await reauth(otp());
  await page.locator('#credential').evaluate(el => { el.parentElement.open = true; });
  await page.locator('#credential-name').fill('<img src=x onerror=alert(1)>'); await page.locator('#credential-user').fill('fixture'); await page.locator('#credential-password').fill(vaultSecret); await page.locator('#credential button').click(); await page.locator('#notice').filter({ hasText: 'saxlanıldı' }).waitFor(); await settled();
  assert.equal(await page.locator('img').count(), 0, 'credential label became markup');
  const metadata = await (await page.request.get(config.Origin + '/api/credentials')).json(); assert.equal(metadata.length, 1); assert(!JSON.stringify(metadata).includes(vaultSecret));
  await page.getByRole('button', { name: 'Göstər', exact: true }).click(); await page.locator('#secret-dialog').waitFor({ state: 'visible' }); assert.equal(await page.locator('#revealed-secret').inputValue(), vaultSecret); await settled();
  await page.locator('#hide-secret').click(); assert.equal(await page.locator('#revealed-secret').inputValue(), '');
  if (config.Screenshot) await page.screenshot({ path: config.Screenshot });
  // A failed request cannot claim that the record was deleted.
  await page.route(config.Origin + '/api/credentials/' + metadata[0].id, route => route.fulfill({ status: 503, body: 'synthetic failure' }));
  await page.getByRole('button', { name: 'Sil', exact: true }).click(); await page.locator('#confirm-delete').click(); await page.locator('#notice').filter({ hasText: 'təsdiqlənmədi' }).waitFor(); await settled();
  assert.equal((await (await page.request.get(config.Origin + '/api/credentials')).json()).length, 1);
  await page.unroute(config.Origin + '/api/credentials/' + metadata[0].id);
  const cookie = (await context.cookies()).find(c => c.name === '__Host-keybash-session'); assert(cookie?.secure && cookie.httpOnly && cookie.sameSite === 'Strict');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0); assert.equal(await page.evaluate(() => document.cookie), '');
  await page.locator('#logout').click(); await page.waitForURL(config.Origin + '/login'); await login(); await page.locator('#challenge').waitFor({ state: 'visible' });
  assert.equal((await page.request.get(config.Origin + '/api/credentials')).status(), 403);
  await fixture('tick'); await page.locator('#factor-code').fill(otp()); await page.locator('#factor button').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();
  await fixture('restart'); assert.equal((await page.request.get(config.Origin + '/api/session')).status(), 401, 'restart retained session');
  await page.goto(config.Origin + '/login'); await login(); await page.locator('#factor-code').fill(otp()); await page.locator('#factor button').click(); await page.locator('#notice').filter({ hasText: 'qəbul edilmədi' }).waitFor(); await settled();
  await page.locator('#factor-code').fill(codes[0]); await page.locator('#factor button').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();
  assert.equal((await (await page.request.get(config.Origin + '/api/credentials')).json()).length, 1, 'restart lost vault');
  await fixture('tick'); await reauth(otp()); await page.getByRole('button', { name: 'Sil', exact: true }).click(); await page.locator('#confirm-delete').click(); await page.locator('#notice').filter({ hasText: 'silindi' }).waitFor(); await settled();
  assert.equal((await (await page.request.get(config.Origin + '/api/credentials')).json()).length, 0);
  await page.locator('#logout').click(); await page.waitForURL(config.Origin + '/login'); await login(); await page.locator('#factor-code').fill(codes[0]); await page.locator('#factor button').click(); await page.locator('#notice').filter({ hasText: 'qəbul edilmədi' }).waitFor();
  assert.deepEqual(errors, []); assert.deepEqual(external, []); assert.deepEqual(secretURLs, []);
  console.log('Browser custody: bootstrap, mandatory MFA, fresh proof, encrypted record UX, restart, replay refusal and failure handling passed');
} catch (error) { console.log(error.code === 'ERR_ASSERTION' ? error.message : error.name); throw new Error('browser custody checks failed'); }
finally { await context.close(); await browser.close(); }
