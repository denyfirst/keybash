import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
const config = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(new URL(config.Origin).hostname, '127.0.0.1');
const browser = await chromium.launch({ headless: true, ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1000 } });
// What the page copies is recorded here, never written to the workstation's clipboard.
await context.addInitScript(() => { globalThis.copiedText = []; Object.defineProperty(navigator, 'clipboard', { value: { writeText(text) { copiedText.push(text); return Promise.resolve(); } } }); });
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

  stage = 'desktop: refused';
  await page.locator('#add-server').click(); await page.locator('#server-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#server-port').inputValue(), '22');
  await page.locator('#server-kind [data-protocol=rdp]').click();
  assert.equal(await page.locator('#server-port').inputValue(), '3389', 'choosing a desktop did not offer its port');
  assert.equal(await page.locator('#server-port-label').textContent(), 'RDP port');
  await page.locator('#server-name').fill('Desk'); await page.locator('#server-address').fill('10.20.0.9'); await page.locator('#server-submit').click();
  await sheetNotice('server-dialog').filter({ hasText: /No RDP server answered there/ }).waitFor(); await settled();
  assert(await page.locator('#server-paste').isHidden(), 'a server that did not answer moved on to comparing');

  stage = 'desktop: add with the console line';
  await page.locator('#server-address').fill('10.20.0.8'); await page.locator('#server-submit').click();
  await page.locator('#server-paste').waitFor({ state: 'visible' }); await settled();
  assert(await page.locator('#server-check').isHidden(), 'a desktop showed the SSH comparison');
  assert.match(await page.locator('#server-command').textContent(), /Win32_TSGeneralSetting.*SHA256/s);
  // The command's own Copy copies it whole and says so on itself, not under the sheet.
  await page.locator('#server-copy').click(); await page.waitForFunction(() => copiedText.length === 1); await settled();
  assert.equal(await page.evaluate(() => copiedText[0]), await page.locator('#server-command').textContent(), 'Copy took other text than its command');
  assert.equal(await page.locator('#server-copy .copy-label').textContent(), 'Copied'); assert.equal(await sheetNotice('server-dialog').textContent(), '', 'the copy was said under the sheet');
  await page.waitForFunction(() => document.querySelector('#server-copy .copy-label').textContent === 'Copy', undefined, { timeout: 5000 });
  assert.doesNotMatch(await page.locator('#server-dialog').textContent(), /SHA256:[a-f0-9]{64}/, 'the page showed the fingerprint it asks for');
  await page.locator('#server-submit').click(); await sheetNotice('server-dialog').filter({ hasText: /Paste the whole line/ }).waitFor(); await settled();
  await page.locator('#server-answer').fill(config.Renewed); await page.locator('#server-submit').click();
  await sheetNotice('server-dialog').filter({ hasText: /not what the server shows/ }).waitFor(); await settled();
  assert.equal(await row('Desk').count(), 0, 'a desktop was added with a line that differs');
  // As pasted: a terminal's capitals and spaces do not matter.
  await page.locator('#server-answer').fill(`  ${config.Desktop.toUpperCase()} `); await page.locator('#server-submit').click();
  await page.locator('#access-dialog').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('#access-title').textContent(), 'Who can use Desk?');
  await page.locator('#access-cancel').click(); await page.locator('#access-dialog').waitFor({ state: 'hidden' });
  assert.match(await row('Desk').textContent(), /Certificate until/);
  assert.equal(await row('Desk').locator('.server-state').textContent(), 'Ready');
  assert(await page.locator('#attention').isHidden(), 'a new desktop raised an alarm');

  stage = 'desktop: Windows renews';
  console.log('KB_RENEW');
  for (let tries = 0; tries < 50 && await page.locator('#attention').isHidden(); tries++) { await page.waitForTimeout(200); await page.reload(); await settled(); await row('Desk').waitFor(); }
  assert.match(await page.locator('#attention-text').textContent(), /^Desk shows a different certificate\. Nobody can connect to it until you check it\.$/);
  assert.equal(await page.locator('#rail-attention').textContent(), '1');
  assert.equal(await row('Desk').locator('.server-state').textContent(), 'Identity changed');
  // Every page says so, with the way to the Servers page.
  await page.locator('.rail-item[data-page=keys]').click(); await page.waitForURL(config.Origin + '/keys');
  await page.locator('#attention').waitFor({ state: 'visible' }); assert(await page.locator('#attention-open').isVisible(), 'no way from the alarm to the Servers page');
  await page.locator('#attention-open').click(); await page.waitForURL(config.Origin + '/servers'); await row('Desk').waitFor(); await settled();

  stage = 'desktop: accept with the console line';
  await row('Desk').getByRole('button', { name: 'Check identity', exact: true }).click(); await page.locator('#identity-paste').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('#identity-now').textContent(), 'A different certificate.');
  assert.doesNotMatch(await page.locator('#identity-dialog').textContent(), new RegExp(config.Renewed.slice(7)), 'the page showed the new fingerprint');
  await page.locator('#identity-answer').fill(config.Desktop); await page.locator('#identity-submit').click();
  await sheetNotice('identity-dialog').filter({ hasText: /not what the server shows/ }).waitFor(); await settled();
  assert(await page.locator('#identity-dialog').isVisible(), 'a line that differs closed the dialog');
  await page.locator('#identity-answer').fill(config.Renewed); await page.locator('#identity-submit').click();
  await page.locator('#identity-dialog').waitFor({ state: 'hidden' }); await settled();
  await page.locator('#notice').filter({ hasText: /^New identity pinned for Desk\./ }).waitFor();
  assert.equal(await row('Desk').locator('.server-state').textContent(), 'Ready');
  assert(await page.locator('#attention').isHidden() && await page.locator('#rail-attention').isHidden(), 'the alarm outlived the check');

  stage = 'desktop: add without checking';
  await page.locator('#add-server').click(); await page.locator('#server-dialog').waitFor({ state: 'visible' });
  await page.locator('#server-kind [data-protocol=rdp]').click();
  await page.locator('#server-name').fill('Side'); await page.locator('#server-address').fill('10.20.0.10'); await page.locator('#server-submit').click();
  await page.locator('#server-paste').waitFor({ state: 'visible' }); await settled();
  assert(await page.locator('#server-verify').isChecked(), 'the check was not chosen from the start');
  assert(await page.locator('#server-unchecked').isHidden(), 'the warning showed with the check chosen');
  await page.locator('#server-verify').uncheck();
  assert(await page.locator('#server-steps').isHidden() && await page.locator('#server-unchecked').isVisible(), 'unticking the check did not say what it risks');
  assert.equal(await page.locator('#server-submit').textContent(), 'Add without checking');
  await page.locator('#server-submit').click();
  await page.locator('#access-dialog').waitFor({ state: 'visible' }); await settled();
  await page.locator('#access-cancel').click(); await page.locator('#access-dialog').waitFor({ state: 'hidden' });
  assert.equal(await row('Side').locator('.server-state').textContent(), 'Not checked');

  stage = 'desktop: check it later';
  await row('Side').getByRole('button', { name: 'Check now', exact: true }).click(); await page.locator('#identity-paste').waitFor({ state: 'visible' }); await settled();
  assert(await page.locator('#identity-verify-choice').isHidden(), 'marking a server checked could skip the check');
  await page.locator('#identity-answer').fill(config.Side); await page.locator('#identity-submit').click();
  await page.locator('#identity-dialog').waitFor({ state: 'hidden' }); await settled();
  await page.locator('#notice').filter({ hasText: /^Side is checked now\.$/ }).waitFor();
  assert.equal(await row('Side').locator('.server-state').textContent(), 'Ready');

  assert.deepEqual(errors, []); assert.deepEqual(external, []);
  console.log('Servers page browser: list, refusals, compare-before-add, access, connection form, removal, desktop, renewal and unchecked desktop passed');
} catch (error) {
  console.log('Servers browser stage:', stage, error.code === 'ERR_ASSERTION' ? error.message : error.name);
  if (process.env.KEYBASH_SERVERS_SCREENSHOT) await page.screenshot({ path: process.env.KEYBASH_SERVERS_SCREENSHOT });
  throw new Error('servers page browser checks failed');
} finally { await context.close(); await browser.close(); }
