import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
const config = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(new URL(config.Origin).hostname, '127.0.0.1');
const browser = await chromium.launch({ headless: true, ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1100 } });
const page = await context.newPage(); const errors = [], external = [], secretURLs = [];
const vaultSecret = 'Synthetic browser custody canary 73', inviteePassword = 'Synthetic invitee password 2026!'; let seed = '', codes = [], seconds = config.Unix, invite = '', inviteSeed = '';
page.on('pageerror', error => errors.push(error.name));
page.on('request', request => {
  if (!request.url().startsWith(config.Origin + '/')) external.push('external request');
  if ([config.Password, config.Code, vaultSecret, seed, invite, inviteSeed, inviteePassword, ...codes].filter(Boolean).some(secret => request.url().includes(secret) || request.url().includes(encodeURIComponent(secret)))) secretURLs.push('secret URL');
});
function otp(counter = Math.floor(seconds / 30), key32 = seed) {
  // Independent RFC 4226/6238 test oracle, never shipped by the application.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of key32) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
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
async function lapse() { for (let i = 0; i < 10; i++) await fixture('tick'); } // past the ten-minute fresh window
async function stepUp(code) { await page.locator('#stepup-dialog').waitFor({ state: 'visible' }); await page.locator('#stepup-code').fill(code); await page.locator('#stepup-submit').click(); }
try {
  await page.goto(config.Origin + '/'); await page.waitForURL(config.Origin + '/login');
  await page.locator('#bootstrap').waitFor({ state: 'visible' });
  await page.locator('#setup-code').fill(config.Code); await page.locator('#setup-user').fill(config.Username); await page.locator('#setup-password').fill(config.Password); await page.locator('#bootstrap button').click();
  await page.waitForURL(config.Origin + '/'); await page.locator('#enroll').waitFor({ state: 'visible' }); await settled();
  // Until the second factor is done the page is its card alone: no menu, and Sign out under the card.
  const alone = async () => { assert(!(await page.locator('.rail').isVisible()) && !(await page.locator('.topbar').isVisible()), 'the menu shows before the second factor'); assert(await page.locator('#focus-logout').isVisible(), 'no Sign out under the card'); assert.equal(await page.locator('#focus-account').textContent(), await page.locator('#account').textContent()); };
  await alone();
  assert.equal((await page.request.get(config.Origin + '/api/credentials')).status(), 403, 'password-only vault access');
  await page.locator('#begin-enroll').click(); await page.locator('#seed-panel').waitFor({ state: 'visible' }); seed = await page.locator('#seed').textContent(); assert.match(seed, /^[A-Z2-7]{32}$/); await settled();
  // The QR code is the server's drawing of this seed, module for module, with a
  // four-module quiet margin; a repeated request shows the same seed.
  const drawn = await page.locator('#seed-qr').evaluate(svg => ({ box: svg.getAttribute('viewBox'), d: svg.querySelector('path')?.getAttribute('d') ?? '' }));
  const again = await (await api('/api/mfa/enrollment', {})).json(); assert.equal(again.secret, seed);
  const cells = new Set(); for (const m of drawn.d.matchAll(/M(\d+) (\d+)h(\d+)v1h-\d+z/g)) for (let i = 0; i < +m[3]; i++) cells.add(`${+m[1] + i},${m[2]}`);
  assert.equal(drawn.box, `-4 -4 ${again.qr.length + 8} ${again.qr.length + 8}`);
  again.qr.forEach((row, y) => [...row].forEach((c, x) => { if (cells.has(`${x},${y}`) !== (c === '1')) assert.fail('QR module differs from the seed'); }));
  assert.equal(cells.size, again.qr.join('').split('1').length - 1);
  assert.equal(await page.locator('#seed').evaluate(el => el.value), seed, 'grouped key copies with spaces');
  // Leaving the page takes the code and the key off the screen.
  await page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true }); document.dispatchEvent(new Event('visibilitychange')); delete document.visibilityState; });
  assert.equal(await page.locator('#seed-qr path').count(), 0); assert.equal(await page.locator('#seed').textContent(), ''); assert(await page.locator('#qr-start').isVisible());
  await page.locator('#begin-enroll').click(); await page.locator('#seed-panel').waitFor({ state: 'visible' }); assert.equal(await page.locator('#seed').textContent(), seed); await settled();
  await page.locator('#enrollment-code').fill(otp(Math.floor(seconds / 30) - 1)); await page.locator('#enrollment button').click(); await page.locator('#recovery').waitFor({ state: 'visible' }); codes = (await page.locator('#recovery-codes').inputValue()).split('\n'); assert.equal(codes.length, 10); await settled();
  await alone(); await page.locator('#saved-recovery').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();
  assert(await page.locator('.rail').isVisible() && !(await page.locator('#focus-logout').isVisible()), 'the ready workspace has no menu');
  assert.equal(await page.locator('#recovery-codes').inputValue(), '');
  assert.equal(await page.locator('#reauth, #reauth-password').count(), 0, 'standing re-verification form');
  // A page per path. Without an operator catalog "/" shows the keys, the menu
  // marks it and hides Connections; Account is its own page.
  assert(await page.locator('#records-panel').isVisible()); assert(!(await page.locator('#account-panel').isVisible()));
  assert.equal(await page.locator('.rail-item[aria-current=page]').getAttribute('data-page'), 'keys');
  assert(!(await page.locator('.rail-item[data-page=connections]').isVisible()));
  assert(await page.locator('#records .empty-state').isVisible(), 'empty keys page did not say what to do'); assert(await page.locator('#add-record').isVisible()); assert(!(await page.locator('#new-connection').isVisible()));
  await page.locator('.rail-item[data-page=account]').click(); await page.waitForURL(config.Origin + '/account'); await page.locator('#account-panel').waitFor({ state: 'visible' }); await settled();
  assert(!(await page.locator('#records-panel').isVisible())); assert.equal(await page.locator('h1').textContent(), 'Account'); assert.equal(await page.title(), 'Keybash · Account'); assert(!(await page.locator('#add-record').isVisible()));
  // Installation says what this copy is, and how to add a server and update it.
  await page.locator('.rail-item[data-page=installation]').click(); await page.waitForURL(config.Origin + '/installation'); await page.locator('#installation-panel').waitFor({ state: 'visible' }); await settled();
  await page.locator('#install-serves').filter({ hasText: /^Keys and passwords only/ }).waitFor();
  assert.equal(await page.locator('h1').textContent(), 'Installation'); assert(!(await page.locator('#account-panel').isVisible()));
  assert.match(await page.locator('#install-version').textContent(), /^(Not recorded in this build\.|[0-9a-f]{7}( · .+)?)$/);
  assert.match(await page.locator('#command-upgrade').textContent(), /sudo sh scripts\/upgrade\.sh --stage=/); assert(!(await page.locator('#command-build').textContent()).endsWith('--with-rdp'));
  // A phone: one bar naming the page, the content within the first 120 px, no
  // sideways scroll, and the menu behind one button that the keyboard opens,
  // Escape closes and a link leaves.
  await page.setViewportSize({ width: 390, height: 844 });
  const toggle = page.locator('#menu-toggle');
  assert(await toggle.isVisible(), 'no menu button on a phone'); assert.equal(await toggle.getAttribute('aria-expanded'), 'false'); assert.equal(await page.locator('#rail-page').textContent(), 'Installation');
  assert(!(await page.locator('.rail-item[data-page=keys]').isVisible()) && !(await page.locator('#logout').isVisible()) && !(await page.locator('.topbar').isVisible()), 'the phone menu or breadcrumb shows unasked');
  assert((await page.locator('h1').boundingBox()).y <= 120, 'phone content starts below the first 120 px');
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), 'the phone page scrolls sideways');
  await toggle.focus(); await page.keyboard.press('Enter');
  assert.equal(await toggle.getAttribute('aria-expanded'), 'true'); assert(await page.locator('#logout').isVisible(), 'Sign out is not in the phone menu');
  await page.keyboard.press('Tab'); assert.equal(await page.evaluate(() => document.activeElement.dataset.page), 'keys');
  await page.keyboard.press('Escape'); assert.equal(await toggle.getAttribute('aria-expanded'), 'false'); assert.equal(await page.evaluate(() => document.activeElement.id), 'menu-toggle');
  assert(!(await page.locator('.rail-item[data-page=keys]').isVisible()), 'Escape left the phone menu open');
  await toggle.click(); await page.locator('.rail-item[data-page=account]').click(); await page.waitForURL(config.Origin + '/account'); await page.locator('#account-panel').waitFor({ state: 'visible' }); await settled();
  assert.equal(await toggle.getAttribute('aria-expanded'), 'false'); assert.equal(await page.locator('#rail-page').textContent(), 'Account');
  await page.setViewportSize({ width: 1280, height: 1100 });
  await page.locator('.rail-item[data-page=keys]').click(); await page.waitForURL(config.Origin + '/keys'); await page.locator('#records-panel').waitFor({ state: 'visible' }); await settled();
  // Completing sign-in counts as fresh proof for ten minutes; let it lapse.
  // Adding a record needs the ready session only.
  await lapse();
  await page.getByRole('button', { name: 'Add your first key or password', exact: true }).click(); await page.locator('#record-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#record-dialog .segment[aria-pressed=true]').getAttribute('data-kind'), 'password'); assert(!(await page.locator('#key-fields').isVisible()));
  await page.locator('#credential-name').fill('<img src=x onerror=alert(1)>'); await page.locator('#credential-user').fill('fixture'); await page.locator('#credential-password').fill(vaultSecret); await page.locator('#credential button[type=submit]').click(); await page.locator('#notice').filter({ hasText: 'Encrypted and saved.' }).waitFor(); await settled(); assert.equal(await page.locator('#record-dialog').evaluate(el => el.open), false);
  assert.equal(await page.locator('img').count(), 0, 'credential label became markup');
  const metadata = await (await page.request.get(config.Origin + '/api/credentials')).json(); assert.equal(metadata.length, 1); assert(!JSON.stringify(metadata).includes(vaultSecret));
  // Revealing needs a factor from the last ten minutes: the page asks for the
  // phone's code alone, keeps asking after a wrong one, then shows the record.
  assert.equal((await api('/api/credentials/' + metadata[0].id + '/reveal', {})).status(), 428, 'fresh factor bypass');
  await page.getByRole('button', { name: 'Show', exact: true }).click();
  await stepUp(otp(Math.floor(seconds / 30) + 7)); await page.locator('#stepup-error').filter({ hasText: 'not accepted' }).waitFor();
  assert.equal(await page.locator('#stepup-dialog input').count(), 1, 'step-up asked for more than the code'); assert.equal(await page.locator('#secret-dialog').evaluate(el => el.open), false);
  await stepUp(otp()); await page.locator('#secret-dialog').waitFor({ state: 'visible' }); assert.equal(await page.locator('#revealed-secret').inputValue(), vaultSecret); await settled();
  assert.equal(await page.locator('#stepup-dialog').evaluate(el => el.open), false); assert.equal(await page.locator('#stepup-code').inputValue(), '');
  await page.locator('#hide-secret').click(); assert.equal(await page.locator('#revealed-secret').inputValue(), '');
  // Inside the window it does not ask again.
  await page.getByRole('button', { name: 'Show', exact: true }).click(); await page.locator('#secret-dialog').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('#stepup-dialog').evaluate(el => el.open), false); await page.locator('#hide-secret').click();
  if (config.Screenshot) await page.screenshot({ path: config.Screenshot });
  // A failed request cannot claim that the record was deleted.
  await page.route(config.Origin + '/api/credentials/' + metadata[0].id, route => route.fulfill({ status: 503, body: 'synthetic failure' }));
  await page.getByRole('button', { name: 'Delete', exact: true }).click(); await page.locator('#confirm-delete').click(); await page.locator('#notice').filter({ hasText: 'did not go through' }).waitFor(); await settled();
  assert.equal((await (await page.request.get(config.Origin + '/api/credentials')).json()).length, 1);
  await page.unroute(config.Origin + '/api/credentials/' + metadata[0].id);
  // Cancelling the code prompt changes nothing and says so.
  await lapse(); await page.getByRole('button', { name: 'Delete', exact: true }).click(); await page.locator('#confirm-delete').click();
  await page.locator('#stepup-dialog').waitFor({ state: 'visible' }); await page.locator('#stepup-cancel').click(); await page.locator('#notice').filter({ hasText: 'Confirmation cancelled' }).waitFor(); await settled();
  assert.equal((await (await page.request.get(config.Origin + '/api/credentials')).json()).length, 1);
  const cookie = (await context.cookies()).find(c => c.name === '__Host-keybash-session'); assert(cookie?.secure && cookie.httpOnly && cookie.sameSite === 'Strict');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0); assert.equal(await page.evaluate(() => document.cookie), '');
  await page.locator('#logout').click(); await page.waitForURL(config.Origin + '/login'); await login(); await page.locator('#challenge').waitFor({ state: 'visible' }); await settled();
  await alone(); await page.locator('#focus-logout').click(); await page.waitForURL(config.Origin + '/login'); await login(); await page.locator('#challenge').waitFor({ state: 'visible' });
  assert.equal((await page.request.get(config.Origin + '/api/credentials')).status(), 403);
  await fixture('tick'); await page.locator('#factor-code').fill(otp()); await page.locator('#factor button').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();
  await fixture('restart'); assert.equal((await page.request.get(config.Origin + '/api/session')).status(), 401, 'restart retained session');
  await page.goto(config.Origin + '/login'); await login(); await page.locator('#factor-code').fill(otp()); await page.locator('#factor button').click(); await page.locator('#notice').filter({ hasText: 'Not accepted' }).waitFor(); await settled();
  await page.locator('#factor-code').fill(codes[0]); await page.locator('#factor button').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();
  assert.equal((await (await page.request.get(config.Origin + '/api/credentials')).json()).length, 1, 'restart lost vault');
  await page.getByRole('button', { name: 'Delete', exact: true }).click(); await page.locator('#confirm-delete').click(); await page.locator('#notice').filter({ hasText: 'Deleted.' }).waitFor(); await settled();
  assert.equal((await (await page.request.get(config.Origin + '/api/credentials')).json()).length, 0);
  // A key made here: only its public line comes back, as the one command to
  // install it, and its row has no Show.
  await page.locator('#add-record').click(); await page.locator('#record-dialog').waitFor({ state: 'visible' }); await page.locator('#record-dialog .segment[data-kind=generate]').click(); assert(!(await page.locator('#credential').isVisible()));
  await page.locator('#generate-name').fill('Made here'); await page.locator('#generate-user').fill('deploy'); await page.locator('#generate button[type=submit]').click();
  await page.locator('#install-dialog').waitFor({ state: 'visible' }); await settled();
  assert.match(await page.locator('#install-command').textContent(), /^mkdir -p ~\/\.ssh && chmod 700 ~\/\.ssh && echo 'ssh-ed25519 [A-Za-z0-9+/]+=*' >> ~\/\.ssh\/authorized_keys && chmod 600 ~\/\.ssh\/authorized_keys$/);
  await page.locator('#close-install').click();
  const made = page.locator('.record', { hasText: 'Made here' });
  assert.equal(await made.getByRole('button', { name: 'Show', exact: true }).count(), 0, 'a key made here offered Show');
  assert.equal(await made.getByRole('button', { name: 'Add to server', exact: true }).count(), 1);
  assert(!(await page.content()).includes('b3BlbnNzaC1rZXktdjE'), 'the page holds a private key'); // every OpenSSH private key body starts so
  // The administrator invites someone, who chooses their own password with the
  // one-time code and lands where their role allows: an auditor sees Account alone.
  await page.locator('.rail-item[data-page=users]').click(); await page.waitForURL(config.Origin + '/users'); await page.locator('#users-panel').waitFor({ state: 'visible' }); await settled();
  const me = page.locator('.person', { hasText: config.Username });
  assert.equal(await me.locator('.record-badge').textContent(), 'You'); assert.equal(await me.getByRole('button').count(), 0, 'an administrator could change their own account');
  await lapse(); await page.locator('#invite-person').click(); await page.locator('#invite-dialog').waitFor({ state: 'visible' });
  await page.locator('#invite-name').fill('invitee'); await page.locator('#invite-dialog input[value=auditor]').check(); await page.locator('#invite-form button[type=submit]').click();
  await stepUp(otp()); await page.locator('#code-dialog').waitFor({ state: 'visible' }); await settled();
  invite = await page.locator('#person-code').textContent(); assert.match(invite, /^[A-Za-z0-9_-]{43}$/);
  await page.locator('#close-code').click(); await page.waitForFunction(() => document.getElementById('person-code').textContent === '');
  const invited = page.locator('.person', { hasText: 'invitee' });
  assert.equal(await invited.locator('.person-state').textContent(), 'Invited'); assert.equal(await invited.locator('.record-meta').textContent(), 'Auditor');
  await page.locator('#logout').click(); await page.waitForURL(config.Origin + '/login');
  await page.locator('#show-claim').click(); await page.locator('#claim').waitFor({ state: 'visible' }); assert(!(await page.locator('#signin').isVisible()));
  await page.locator('#claim-user').fill('invitee'); await page.locator('#claim-code').fill(invite); await page.locator('#claim-password').fill(inviteePassword); await page.locator('#claim-confirm').fill(inviteePassword); await page.locator('#claim button').click();
  await page.waitForURL(config.Origin + '/'); await page.locator('#enroll').waitFor({ state: 'visible' }); await settled();
  assert(!(await page.locator('#setup-proof').isVisible()), 'the invite was asked for again');
  await page.locator('#begin-enroll').click(); await page.locator('#seed-panel').waitFor({ state: 'visible' }); inviteSeed = await page.locator('#seed').textContent(); assert.match(inviteSeed, /^[A-Z2-7]{32}$/); await settled();
  await page.locator('#enrollment-code').fill(otp(Math.floor(seconds / 30), inviteSeed)); await page.locator('#enrollment button').click(); await page.locator('#recovery').waitFor({ state: 'visible' }); await settled();
  await page.locator('#saved-recovery').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('h1').textContent(), 'Account'); assert.deepEqual(await page.locator('.rail-item:visible').evaluateAll(items => items.map(item => item.dataset.page)), ['account']);
  assert.equal((await page.request.get(config.Origin + '/api/credentials')).status(), 403, 'an auditor reached keys and passwords');
  assert.equal((await page.request.get(config.Origin + '/api/users')).status(), 403, 'an auditor listed accounts');
  await page.locator('#logout').click(); await page.waitForURL(config.Origin + '/login'); await login(); await page.locator('#factor-code').fill(codes[0]); await page.locator('#factor button').click(); await page.locator('#notice').filter({ hasText: 'Not accepted' }).waitFor();
  assert.deepEqual(errors, []); assert.deepEqual(external, []); assert.deepEqual(secretURLs, []);
  console.log('Browser custody: bootstrap, mandatory MFA, phone navigation, code-only step-up, encrypted record UX, invites and roles, restart, replay refusal and failure handling passed');
} catch (error) { console.log(error.code === 'ERR_ASSERTION' ? error.message : error.name); throw new Error('browser custody checks failed'); }
finally { await context.close(); await browser.close(); }
