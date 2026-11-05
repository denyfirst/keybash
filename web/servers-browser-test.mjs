import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
const config = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(new URL(config.Origin).hostname, '127.0.0.1');
const browser = await chromium.launch({ headless: true, ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1000 } });
const page = await context.newPage(); const errors = [], external = [];
page.on('pageerror', error => errors.push(error.name));
page.on('request', request => { if (!request.url().startsWith(config.Origin + '/')) external.push('external request'); });
function otp(seed, counter) {
  // Independent RFC 4226/6238 test oracle, never shipped by the application.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of seed) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
  const input = Buffer.alloc(8); input.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', key).update(input).digest();
  return ((digest.readUInt32BE(digest[19] & 15) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}
async function settled() { await page.waitForFunction(() => !document.getElementById('logout')?.disabled); }
const row = name => page.locator('.server-row').filter({ has: page.locator('.record-name', { hasText: new RegExp(`^${name}$`) }) });
const sheetNotice = id => page.locator(`#${id} .dialog-notice`);
let stage = 'bootstrap';
try {
  await page.goto(config.Origin + '/login'); await page.locator('#setup-code').fill(config.Code); await page.locator('#setup-user').fill('alice'); await page.locator('#setup-password').fill(config.Password); await page.locator('#bootstrap button').click();
  await page.waitForURL(config.Origin + '/'); await settled();
  await page.locator('#begin-enroll').click(); await page.locator('#seed-panel').waitFor({ state: 'visible' }); const seed = await page.locator('#seed').textContent(); await settled();
  await page.locator('#enrollment-code').fill(otp(seed, Math.floor(Date.now() / 30000))); await page.locator('#enrollment button').click(); await page.locator('#recovery').waitFor({ state: 'visible' }); await settled();
  await page.locator('#saved-recovery').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();

  stage = 'servers page';
  await page.locator('.rail-item[data-page=servers]').click(); await page.waitForURL(config.Origin + '/servers'); await page.locator('#servers-panel').waitFor({ state: 'visible' }); await settled();
  await row('Catalog box').waitFor();
  // The server from the file moved into the list with nobody on it, and is
  // managed here like any other.
  assert.match(await row('Catalog box').textContent(), /Nobody can use it yet/, 'a server from the file came open to people');
  assert.equal(await row('Catalog box').getByRole('button', { name: 'Who can use it', exact: true }).count(), 1, 'a server from the file cannot be managed here');
  assert.match(await page.locator('#server-networks').textContent(), /inside 10\.20\.0\.0\/24/);
  assert(await page.locator('#add-server').isVisible(), 'no Add server button');

  stage = 'refused addresses';
  await page.locator('#add-server').click(); await page.locator('#server-dialog').waitFor({ state: 'visible' });
  await page.locator('#server-name').fill('Elsewhere'); await page.locator('#server-address').fill('10.21.0.7'); await page.locator('#server-submit').click();
  await sheetNotice('server-dialog').filter({ hasText: /outside the networks this Keybash may reach/ }).waitFor(); await settled();
  assert(await page.locator('#server-check').isHidden(), 'a refused address moved on to comparing');
  await page.locator('#server-address').fill('10.20.0.9'); await page.locator('#server-submit').click();
  await sheetNotice('server-dialog').filter({ hasText: /No SSH server with an Ed25519 key answered/ }).waitFor(); await settled();

  stage = 'compare and add';
  await page.locator('#server-name').fill('Build box'); await page.locator('#server-address').fill('10.20.0.7'); await page.locator('#server-submit').click();
  await page.locator('#server-check').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('#server-print').textContent(), config.Fingerprint);
  assert.match(await page.locator('#server-check').textContent(), /ssh-keygen -lf \/etc\/ssh\/ssh_host_ed25519_key\.pub/);
  await page.locator('#server-submit').click(); await sheetNotice('server-dialog').filter({ hasText: /Compare the fingerprint/ }).waitFor(); await settled();
  assert.equal(await row('Build box').count(), 0, 'a server was added before its fingerprint was compared');
  // Changing the address after reading starts the comparison over.
  await page.locator('#server-port').fill('2222'); assert(await page.locator('#server-check').isHidden(), 'a changed address kept the old fingerprint');
  await page.locator('#server-port').fill('22'); await page.locator('#server-submit').click(); await page.locator('#server-check').waitFor({ state: 'visible' }); await settled();
  await page.locator('#server-same').check(); await page.locator('#server-submit').click();

  stage = 'who can use it';
  await page.locator('#access-dialog').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('#access-title').textContent(), 'Who can use Build box?');
  assert.equal(await page.locator('#access-people input:checked').count(), 0, 'a new server came with people on it');
  assert.match(await row('Build box').textContent(), /Nobody can use it yet/);
  assert.equal((await (await page.request.get(config.Origin + '/api/targets')).json()).some(t => t.name === 'Build box'), false, 'the administrator reaches a server nobody was given');
  await page.locator('#access-people label').filter({ hasText: 'alice' }).locator('input').check(); await page.locator('#access-form button[type=submit]').click();
  await page.locator('#access-dialog').waitFor({ state: 'hidden' }); await settled();
  assert.match(await row('Build box').locator('.server-access').textContent(), /^Can use it: alice$/);

  stage = 'connection form';
  await page.locator('.rail-item[data-page=connections]').click(); await page.waitForURL(config.Origin + '/'); await settled();
  const options = await page.locator('#connection-target option').allTextContents();
  assert(options.includes('Build box · SSH'), 'the server given to alice is not offered');
  assert(!options.includes('Catalog box · SSH'), 'a server nobody gave alice is offered');

  stage = 'remove';
  await page.locator('.rail-item[data-page=servers]').click(); await page.waitForURL(config.Origin + '/servers'); await row('Build box').waitFor(); await settled();
  await row('Build box').getByRole('button', { name: 'Remove', exact: true }).click(); await page.locator('#delete-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#delete-title').textContent(), 'Remove this server?');
  await page.locator('#confirm-delete').click(); await page.locator('#notice').filter({ hasText: /^Build box was removed\.$/ }).waitFor(); await settled();
  assert.equal(await row('Build box').count(), 0, 'the server was not removed');

  assert.deepEqual(errors, []); assert.deepEqual(external, []);
  console.log('Servers page browser: list, refusals, compare-before-add, access, connection form and removal passed');
} catch (error) {
  console.log('Servers browser stage:', stage, error.code === 'ERR_ASSERTION' ? error.message : error.name);
  if (process.env.KEYBASH_SERVERS_SCREENSHOT) await page.screenshot({ path: process.env.KEYBASH_SERVERS_SCREENSHOT });
  throw new Error('servers page browser checks failed');
} finally { await context.close(); await browser.close(); }
