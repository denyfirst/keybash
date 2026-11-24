import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
const config = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(new URL(config.Origin).hostname, '127.0.0.1');
const browser = await chromium.launch({ headless: true, args: ['--disable-3d-apis'], ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1000 } });
// What the page copies is recorded here, never written to the workstation's clipboard.
await context.addInitScript(() => { globalThis.copiedText = []; Object.defineProperty(navigator, 'clipboard', { value: { writeText(text) { copiedText.push(text); return Promise.resolve(); } } }); });
const page = await context.newPage(); const errors = [], external = [];
page.on('pageerror', error => errors.push(error.name));
page.on('request', request => { if (!request.url().startsWith(config.Origin + '/')) external.push('external request'); });
// What the API answers while accounts are handled, searched for secrets at
// the end. Only then: reading every answer slows the whole run.
const answers = [];
// A body the browser drops when its page moves on is never read; it waits at
// most ten seconds rather than holding the run.
const listen = response => { if (response.url().startsWith(config.Origin + '/api/')) answers.push(Promise.race([response.text(), new Promise(resolve => setTimeout(() => resolve(''), 10000).unref())]).catch(() => '')); };
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
const card = name => page.locator('.server-account', { has: page.locator('.server-account-name', { hasText: new RegExp(`^${name}$`) }) });
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
  // The server from the file moved into the list with no account, so nobody
  // reaches it, and it is managed here like any other.
  assert.equal(await row('Catalog box').locator('.server-accounts').textContent(), 'No accounts yet: nobody can connect.', 'a server from the file came open to people');
  assert.equal(await row('Catalog box').getByRole('link', { name: 'Open', exact: true }).count(), 1, 'a server from the file cannot be managed here');
  assert.match(await page.locator('#server-networks').textContent(), /inside 10\.20\.0\.0\/24/);
  assert(await page.locator('#add-server').isVisible(), 'no Add server button');
  assert.equal(await page.locator('.rail-item[href="/keys"], #new-connection, #add-record').count(), 0, 'the personal path is back');

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

  stage = 'first account';
  // Adding a server leads straight to its own page and its first account.
  await page.locator('#account-dialog').waitFor({ state: 'visible' }); await settled();
  await page.waitForURL(/\/servers\/[a-f0-9]{32}$/); const buildID = page.url().slice(-32);
  assert.equal(await page.locator('h1').textContent(), 'Build box'); assert.equal(await page.locator('#back-link').textContent(), 'Servers');
  assert.equal(await page.locator('#account-title').textContent(), 'Add an account on Build box');
  assert.match(await page.locator('#account-lead').textContent(), /^Build box was added\. Now the account people sign in as: until it has one, nobody can connect\.$/);
  assert.match(await page.locator('#account-user-hint').textContent(), /^The name you type to sign in on Build box, for example root or deploy\. It must already exist there\.$/);
  // alice is the only person who may be put on it, so she is ticked already.
  assert.deepEqual(await page.locator('#account-people .role-option strong').allTextContents(), ['alice (you)']); assert(await page.locator('#account-people input').isChecked());
  assert.deepEqual(await (await page.request.get(config.Origin + '/api/access')).json(), [], 'the administrator reaches a server before an account lists her');
  // Each kind says what it is, the chosen one looks chosen, and the button says what it does.
  const look = kind => page.locator(`#account-kind [data-kind=${kind}]`).evaluate(element => getComputedStyle(element).backgroundColor);
  assert.equal(await page.locator('#account-submit').textContent(), 'Make the key'); assert(await page.locator('#account-secret-field').isHidden(), 'a key made here asked for a password');
  assert.match(await page.locator('#account-kind-hint').textContent(), /Nobody ever sees the key/);
  assert.notEqual(await look('ssh-key'), await look('password'), 'the chosen kind looked like the other');
  await page.locator('#account-kind [data-kind=password]').click();
  assert.equal(await page.locator('#account-submit').textContent(), 'Save the password'); assert(await page.locator('#account-secret-field').isVisible());
  assert.match(await page.locator('#account-kind-hint').textContent(), /^Typed once here and never shown again\. Anyone who already knows it can still sign in without Keybash/);
  assert.notEqual(await look('ssh-key'), await look('password'), 'the chosen kind looked like the other');
  await page.locator('#account-kind [data-kind=ssh-key]').click();
  page.on('response', listen);
  await page.locator('#account-user').fill('deploy'); await page.locator('#account-submit').click();
  await page.locator('#key-dialog').waitFor({ state: 'visible' }); await settled();
  const keyLine = /^mkdir -p ~\/\.ssh && chmod 700 ~\/\.ssh && echo 'restrict,pty ssh-ed25519 [A-Za-z0-9+/]+={0,2} keybash' >> ~\/\.ssh\/authorized_keys && chmod 600 ~\/\.ssh\/authorized_keys$/;
  assert.equal(await page.locator('#key-title').textContent(), 'Now put the key on the server');
  assert.match(await page.locator('#key-lead').textContent(), /^Not on the server yet\. Run this once on Build box, as deploy\./);
  assert.equal(await page.locator('#key-command-head').textContent(), 'Shell on Build box, as deploy');
  const firstKey = await page.locator('#key-command').textContent(); assert.match(firstKey, keyLine);
  // The command's own Copy copies it whole.
  await page.locator('#key-dialog .command-box').first().locator('.copy-chip').click(); await page.waitForFunction(() => copiedText.length === 1); await settled();
  assert.equal(await page.evaluate(() => copiedText[0]), firstKey, 'Copy took other text than the command');
  await page.evaluate(() => { copiedText.length = 0; });
  await page.locator('#key-close').click(); await page.locator('#key-dialog').waitFor({ state: 'hidden' });
  assert.equal(await card('deploy').locator('.server-account-how').textContent(), 'Key made by Keybash · not on the server yet');
  assert.deepEqual(await card('deploy').locator('.chip-name').allTextContents(), ['alice (you)']);
  // Another account on the server needs another name, whatever its case.
  await page.locator('#add-account').click(); await page.locator('#account-dialog').waitFor({ state: 'visible' });
  await page.locator('#account-user').fill('Deploy'); await page.locator('#account-submit').click();
  await sheetNotice('account-dialog').filter({ hasText: /already has an account with that name/ }).waitFor(); await settled();
  await page.locator('#account-cancel').click(); await page.locator('#account-dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('.server-account').count(), 1);

  stage = 'new key';
  // A new key waits beside the current one until the switch.
  await card('deploy').getByRole('button', { name: 'Put the key on the server', exact: true }).click(); await page.locator('#key-dialog').waitFor({ state: 'visible' });
  await page.locator('#key-new').click(); await page.locator('#key-next').waitFor({ state: 'visible' }); await settled();
  const nextKey = await page.locator('#key-next-command').textContent(); assert.match(nextKey, keyLine); assert.notEqual(nextKey, firstKey);
  assert.equal(await page.locator('#key-command').textContent(), firstKey, 'a new key replaced the current one before the switch');
  assert(await page.locator('#key-new').isHidden(), 'a second new key was offered while one waits');
  assert.match(await card('deploy').locator('.server-account-how').textContent(), / · a new key is waiting$/);
  await page.locator('#key-switch').click(); await sheetNotice('key-dialog').filter({ hasText: /^The new key is in use\. The old key is destroyed/ }).waitFor(); await settled();
  assert.equal(await page.locator('#key-command').textContent(), nextKey, 'the switch did not make the new key the one used');
  assert(await page.locator('#key-next').isHidden() && await page.locator('#key-new').isVisible(), 'the sheet still showed a waiting key');
  // A waiting key can be dropped; the current one stays.
  await page.locator('#key-new').click(); await page.locator('#key-next').waitFor({ state: 'visible' }); await settled();
  await page.locator('#key-keep').click(); await sheetNotice('key-dialog').filter({ hasText: /^The new key was destroyed\. The current one stays\.$/ }).waitFor(); await settled();
  assert.equal(await page.locator('#key-command').textContent(), nextKey);
  await page.locator('#key-close').click(); await page.locator('#key-dialog').waitFor({ state: 'hidden' });

  stage = 'narrow pages';
  // At any width the list keeps a server's fingerprint readable on its own
  // page, each action keeps its words on one line, and nothing scrolls sideways.
  for (const width of [390, 820, 1100, 1280]) {
    await page.setViewportSize({ width, height: 1000 });
    assert.deepEqual(await page.locator('#server-card button, .server-account button').evaluateAll(buttons => buttons.filter(b => b.getBoundingClientRect().height > 44).map(b => b.textContent)), [], `an action wrapped its words at ${width}px`);
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `the server's page scrolled sideways at ${width}px`);
    if (width > 390) assert((await page.locator('#server-card .fingerprint').boundingBox()).width >= 180, `the fingerprint was squeezed at ${width}px`);
  }
  await page.setViewportSize({ width: 1280, height: 1000 });
  await page.locator('#back-link').click(); await page.waitForURL(config.Origin + '/servers'); await row('Build box').waitFor(); await settled();
  assert.equal(await row('Build box').locator('.server-accounts').textContent(), 'Account: deploy · 1 person signs in');
  for (const width of [820, 1280]) {
    await page.setViewportSize({ width, height: 1000 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `the list scrolled sideways at ${width}px`);
  }
  await page.setViewportSize({ width: 1280, height: 1000 });

  stage = 'your servers';
  // alice finds it ready on her own page, and sees nothing of it but the
  // account's name.
  await page.locator('.rail-item[data-page=access]').click(); await page.waitForURL(config.Origin + '/'); await settled();
  const accessCard = page.locator('#access .server-card'); await accessCard.waitFor();
  assert.equal(await accessCard.count(), 1);
  assert.equal(await accessCard.locator('.server-name').textContent(), 'Build box');
  assert.equal(await accessCard.locator('.server-kind').textContent(), 'Terminal (SSH)');
  assert.equal(await accessCard.locator('.trust-state').textContent(), 'Ready');
  assert.match(await accessCard.locator('.server-screen').textContent(), /^deploy@Build box ~ \$ /);
  assert.equal(await accessCard.getByRole('button').count(), 0, 'a card offered to change its account');
  const deployID = await accessCard.getAttribute('data-account'); assert.match(deployID, /^[a-f0-9]{32}$/);
  const connect = accessCard.getByRole('link', { name: 'Connect', exact: true });
  assert.equal(await connect.getAttribute('href'), `/remote/ssh/${deployID}`);

  stage = 'card states';
  // A card offers to connect only when ready. The page takes no field it does
  // not show, so a row with another one is refused whole, as are two rows for
  // one account.
  const listed = { account: deployID, server: buildID, name: 'Build box', protocol: 'ssh', username: 'deploy', trust: 'verified' };
  const answerAccess = rows => page.route(config.Origin + '/api/access', route => route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify(rows) }));
  for (const [trust, words, help] of [['stopped', 'Server changed', /shows a different certificate/], ['unavailable', 'Unavailable', /does not open right now/]]) {
    await answerAccess([{ ...listed, trust }]); await page.reload(); await accessCard.waitFor(); await settled();
    assert.equal(await accessCard.locator('.trust-state').textContent(), words);
    assert.match(await accessCard.locator('.server-help').textContent(), help);
    assert.equal(await accessCard.getByRole('link').count(), 0, `a ${trust} card offered to connect`);
    await page.unroute(config.Origin + '/api/access');
  }
  for (const rows of [[{ ...listed, secret: 'synthetic' }], [listed, listed], [{ ...listed, protocol: 'vnc' }]]) {
    await answerAccess(rows); await page.reload(); await settled();
    await page.locator('#notice').filter({ hasText: /./ }).waitFor();
    assert.equal(await accessCard.count(), 0, 'the page showed rows it should refuse');
    await page.unroute(config.Origin + '/api/access');
  }
  await page.reload(); await accessCard.waitFor(); await settled();

  stage = 'terminal';
  const [terminal] = await Promise.all([page.waitForEvent('popup'), connect.click()]);
  terminal.on('pageerror', error => errors.push(error.name)); terminal.on('response', listen);
  terminal.on('request', request => { if (!request.url().startsWith(config.Origin + '/')) external.push('external request'); });
  await terminal.waitForFunction(() => document.title === 'Build box · Keybash');
  assert.equal(await terminal.locator('#tab-name').textContent(), 'deploy@Build box');
  await terminal.locator('#status').filter({ hasText: /^Connected$/ }).waitFor();
  await terminal.locator('.xterm-helper-textarea').focus(); await terminal.keyboard.type('account-key-echo');
  await terminal.waitForFunction(() => document.querySelector('.xterm-rows')?.textContent.includes('account-key-echo'));
  // The key worked once, so its account says it is on the server.
  await page.goto(`${config.Origin}/servers/${buildID}`); await page.locator('#server-panel').waitFor({ state: 'visible' }); await settled();
  assert.equal(await card('deploy').locator('.server-account-how').textContent(), 'Key made by Keybash · on the server');
  assert.equal(await card('deploy').getByRole('button', { name: 'Key line', exact: true }).count(), 1);

  stage = 'remove the account';
  // Removing it asks first; then nobody signs in as it, and the open session ends.
  await card('deploy').getByRole('button', { name: 'Remove', exact: true }).click(); await page.locator('#delete-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#delete-title').textContent(), 'Remove this account?'); assert.equal(await page.locator('#delete-name').textContent(), 'deploy on Build box');
  assert.equal(await page.locator('#confirm-delete').textContent(), 'Remove');
  await page.locator('#confirm-delete').click(); await page.locator('#notice').filter({ hasText: /^deploy on Build box was removed\.$/ }).waitFor(); await settled();
  assert.equal(await page.locator('.server-account').count(), 0); await page.locator('#accounts .empty-state').waitFor();
  await terminal.locator('#notice').filter({ hasText: /^This server, its account or your access to it changed, so this session ended\.$/ }).waitFor();
  await Promise.all(answers); await terminal.close(); // its answers are read while it is open
  assert.equal((await page.request.get(`${config.Origin}/remote/ssh/${deployID}`)).status(), 404, 'a removed account still opened a page');
  // Every OpenSSH private key's body begins with this (base64 of openssh-key-v1).
  assert.doesNotMatch(await page.content(), /b3BlbnNzaC1rZXktdjE/, 'the page held a private key');

  stage = 'remove the server';
  await page.locator('#server-card').getByRole('button', { name: 'Remove', exact: true }).click(); await page.locator('#delete-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#delete-title').textContent(), 'Remove this server?');
  await page.locator('#confirm-delete').click(); await page.waitForURL(config.Origin + '/servers'); await page.locator('#notice').filter({ hasText: /^Build box was removed\.$/ }).waitFor(); await settled();
  assert.equal(await row('Build box').count(), 0, 'the server was not removed');
  page.off('response', listen);

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
  await page.locator('#account-dialog').waitFor({ state: 'visible' }); await settled();
  const deskPath = new URL(page.url()).pathname; assert.match(deskPath, /^\/servers\/[a-f0-9]{32}$/);
  // A desktop takes a password alone.
  assert(await page.locator('#account-kind').isHidden(), 'a desktop offered a key');
  assert(await page.locator('#account-secret-field').isVisible(), 'a desktop did not ask for its password');
  assert.match(await page.locator('#account-kind-hint').textContent(), /^A desktop signs in with a password\. Typed once here/);
  assert.equal(await page.locator('#account-submit').textContent(), 'Save the password');
  await page.locator('#account-cancel').click(); await page.locator('#account-dialog').waitFor({ state: 'hidden' });
  assert.match(await page.locator('#server-card').textContent(), /Certificate until/);
  assert.equal(await page.locator('#server-card .server-state').textContent(), 'Ready');
  assert(await page.locator('#attention').isHidden(), 'a new desktop raised an alarm');

  stage = 'desktop: Windows renews';
  console.log('KB_RENEW');
  await page.goto(config.Origin + '/servers'); await row('Desk').waitFor(); await settled();
  for (let tries = 0; tries < 50 && await page.locator('#attention').isHidden(); tries++) { await page.waitForTimeout(200); await page.reload(); await settled(); await row('Desk').waitFor(); }
  assert.match(await page.locator('#attention-text').textContent(), /^Desk shows a different certificate\. Nobody can connect to it until you check it\.$/);
  assert.equal(await page.locator('#rail-attention').textContent(), '1');
  assert.equal(await row('Desk').locator('.server-state').textContent(), 'Identity changed');
  // Every page says so, with the way to the Servers page.
  await page.locator('.rail-item[data-page=users]').click(); await page.waitForURL(config.Origin + '/users');
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
  await page.locator('#account-dialog').waitFor({ state: 'visible' }); await settled();
  await page.locator('#account-cancel').click(); await page.locator('#account-dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#server-card .server-state').textContent(), 'Not checked');

  stage = 'desktop: check it later';
  await page.locator('#server-card').getByRole('button', { name: 'Check now', exact: true }).click(); await page.locator('#identity-paste').waitFor({ state: 'visible' }); await settled();
  assert(await page.locator('#identity-verify-choice').isHidden(), 'marking a server checked could skip the check');
  await page.locator('#identity-answer').fill(config.Side); await page.locator('#identity-submit').click();
  await page.locator('#identity-dialog').waitFor({ state: 'hidden' }); await settled();
  await page.locator('#notice').filter({ hasText: /^Side is checked now\.$/ }).waitFor();
  assert.equal(await page.locator('#server-card .server-state').textContent(), 'Ready');

  stage = 'desktop: its account';
  const sharedPassword = config.SharedPassword;
  page.on('response', listen);
  await page.goto(config.Origin + deskPath); await page.locator('#server-panel').waitFor({ state: 'visible' }); await settled();
  await page.locator('#add-account').click(); await page.locator('#account-dialog').waitFor({ state: 'visible' });
  await page.locator('#account-user').fill('kbtest'); await page.locator('#account-secret').fill(sharedPassword); await page.locator('#account-submit').click();
  await page.locator('#notice').filter({ hasText: /^kbtest on Desk is ready: the people you ticked can connect now\.$/ }).waitFor(); await settled();
  assert.equal(await page.locator('#account-secret').inputValue(), '', 'the typed password stayed on the page');
  // A refused one is emptied too, though its sheet stays open.
  await page.locator('#add-account').click(); await page.locator('#account-dialog').waitFor({ state: 'visible' });
  await page.locator('#account-user').fill('KBTEST'); await page.locator('#account-secret').fill(sharedPassword); await page.locator('#account-submit').click();
  await sheetNotice('account-dialog').filter({ hasText: /already has an account with that name/ }).waitFor(); await settled();
  assert(await page.locator('#account-dialog').isVisible()); assert.equal(await page.locator('#account-secret').inputValue(), '', 'a refused password stayed in its field');
  await page.locator('#account-cancel').click(); await page.locator('#account-dialog').waitFor({ state: 'hidden' });
  assert.equal(await card('kbtest').locator('.server-account-how').textContent(), 'Password kept by Keybash');
  assert.match(await card('kbtest').locator('.server-account-set').textContent(), /^Set by alice \(you\) on /);
  await card('kbtest').getByRole('button', { name: 'Change password', exact: true }).click(); await page.locator('#secret-dialog').waitFor({ state: 'visible' });
  await page.locator('#secret-new').fill(`${sharedPassword}-2`); await page.locator('#secret-form button[type=submit]').click();
  await page.locator('#notice').filter({ hasText: /^Keybash uses the new password for kbtest on Desk from the next session on\.$/ }).waitFor(); await settled();
  assert.equal(await page.locator('#secret-new').inputValue(), '', 'the new password stayed on the page');

  stage = 'desktop: its card';
  // On the account, alice finds it on her own page. Its desktop starts with
  // the password set last, which the page never had.
  await page.locator('.rail-item[data-page=access]').click(); await page.waitForURL(config.Origin + '/'); await settled();
  const deskCard = page.locator('#access .server-card'); await deskCard.waitFor();
  assert.equal(await deskCard.count(), 1);
  assert.equal(await deskCard.locator('.server-kind').textContent(), 'Desktop (RDP)');
  assert.equal(await deskCard.locator('.server-screen').textContent(), 'kbtest@Desk · desktop');
  const deskID = await deskCard.getAttribute('data-account');
  assert.equal(await deskCard.getByRole('link', { name: 'Connect', exact: true }).getAttribute('href'), `/remote/rdp/${deskID}`);
  const asked = async () => (await page.request.get(config.Origin + '/__fixture/desktop', { headers: { 'X-Fixture-Control': config.Control } })).json();
  assert.equal((await asked()).calls, 0, 'a desktop started before it was opened');
  const [desktop] = await Promise.all([page.waitForEvent('popup'), deskCard.getByRole('link', { name: 'Connect', exact: true }).click()]);
  desktop.on('pageerror', error => errors.push(error.name)); desktop.on('request', request => { if (!request.url().startsWith(config.Origin + '/')) external.push('external request'); });
  await desktop.waitForFunction(() => document.title === 'Desk · Keybash');
  let started; for (let tries = 0; tries < 100 && !(started = await asked()).calls; tries++) await desktop.waitForTimeout(100);
  assert.deepEqual(started, { calls: 1, username: 'kbtest', password: true }, 'the desktop did not start with the account\'s password');
  assert.doesNotMatch(await desktop.content(), new RegExp(sharedPassword), 'the desktop page held the password');
  await desktop.close();

  stage = 'a person\'s own page';
  // Someone invited is given access from their own page: a server, then one
  // of its accounts. Taking them off asks first.
  await page.locator('.rail-item[data-page=users]').click(); await page.waitForURL(config.Origin + '/users'); await settled();
  await page.locator('#invite-person').click(); await page.locator('#invite-dialog').waitFor({ state: 'visible' });
  await page.locator('#invite-name').fill('bob'); await page.locator('#invite-form button[type=submit]').click(); await page.locator('#code-dialog').waitFor({ state: 'visible' }); await settled();
  await page.locator('#close-code').click();
  const bobRow = page.locator('.person', { hasText: 'bob' }); assert.equal(await bobRow.locator('.server-access').textContent(), 'No servers yet');
  await bobRow.getByRole('link', { name: 'bob', exact: true }).click(); await page.locator('#person-panel').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('h1').textContent(), 'bob'); await page.locator('#person-access .empty-state').waitFor();
  await page.locator('#give-access').click(); await page.locator('#give-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#give-title').textContent(), 'Give bob access');
  await page.locator('#give-server').selectOption({ label: 'Desk · Desktop (RDP)' });
  assert.deepEqual(await page.locator('#give-accounts .role-option strong').allTextContents(), ['kbtest']); assert(await page.locator('#give-accounts input').isChecked());
  await page.locator('#give-server').selectOption({ label: 'Side · Desktop (RDP)' });
  assert(await page.locator('#give-none').isVisible(), 'a server with no account offered one'); assert(await page.locator('#give-submit').isDisabled());
  await page.locator('#give-server').selectOption({ label: 'Desk · Desktop (RDP)' }); await page.locator('#give-submit').click();
  await page.locator('#notice').filter({ hasText: /^bob can connect to Desk now\.$/ }).waitFor(); await settled();
  const bobAccess = page.locator('#person-access .access-item'); assert.equal(await bobAccess.count(), 1);
  assert.equal(await bobAccess.locator('.record-meta').textContent(), 'as kbtest · password kept by Keybash');
  await bobAccess.getByRole('button', { name: 'Take off', exact: true }).click(); await page.locator('#delete-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#delete-title').textContent(), 'Take them off this account?'); assert.equal(await page.locator('#delete-name').textContent(), 'bob as kbtest on Desk');
  await page.locator('#confirm-delete').click(); await page.locator('#notice').filter({ hasText: /^Taken off: bob as kbtest on Desk\.$/ }).waitFor(); await settled();
  assert.equal(await bobAccess.count(), 0);
  page.off('response', listen);
  // Nothing the page holds, or any answer it got, carries a secret.
  assert.doesNotMatch(await page.content(), new RegExp(sharedPassword));
  assert(answers.length >= 10, 'the answers were not searched');
  for (const answer of await Promise.all(answers)) assert(!answer.includes(sharedPassword) && !answer.includes('b3BlbnNzaC1rZXktdjE') && !answer.includes('PRIVATE KEY'), 'an answer carried a secret');

  assert.deepEqual(errors, []); assert.deepEqual(external, []);
  console.log('Servers page browser: list, refusals, compare-before-add, the first account, key lines and a new key, narrow pages, your servers and their card states, a terminal and a desktop through accounts, removal, renewal, unchecked desktop, and giving access from a person\'s page passed');
} catch (error) {
  console.log('Servers browser stage:', stage, error.code === 'ERR_ASSERTION' ? error.message : error.name);
  if (process.env.KEYBASH_SERVERS_SCREENSHOT) await page.screenshot({ path: process.env.KEYBASH_SERVERS_SCREENSHOT });
  throw new Error('servers page browser checks failed');
} finally { await context.close(); await browser.close(); }
