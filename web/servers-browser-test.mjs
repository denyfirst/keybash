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
// What the API answers while shared credentials are handled, searched for
// secrets at the end. Only then: reading every answer slows the whole run.
const answers = [];
const listen = response => { if (response.url().startsWith(config.Origin + '/api/')) answers.push(response.text().catch(() => '')); };
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
  assert.match(await row('Build box').locator('.server-who').textContent(), /^Can use it: alice$/);
  // Who may connect and how they sign in are two lines, two questions.
  assert.equal(await row('Build box').locator('.server-sign-in').textContent(), 'Each person signs in with their own key or password.');

  stage = 'narrow list';
  // At any width the fingerprint keeps room to be read, each action keeps its
  // words on one line, and the page does not scroll sideways.
  for (const width of [820, 980, 1100, 1280]) {
    await page.setViewportSize({ width, height: 1000 });
    const print = await row('Build box').locator('.fingerprint').boundingBox();
    assert(print.width >= 180, `the fingerprint was squeezed at ${width}px`);
    // With the room of a wide window, the actions wrap and the fingerprint keeps one line.
    if (width === 1280) assert(print.height < 34, 'the fingerprint wrapped beside the actions at 1280px');
    assert.deepEqual(await row('Build box').locator('.record-actions button').evaluateAll(buttons => buttons.filter(b => b.getBoundingClientRect().height > 44).map(b => b.textContent)), [], `an action wrapped its words at ${width}px`);
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `the page scrolled sideways at ${width}px`);
  }
  await page.setViewportSize({ width: 1280, height: 1000 });

  stage = 'sign-in sheet';
  // Keybash cannot list a server's accounts, so it offers the names alice's own
  // connections to this server sign in as, and none from other servers.
  const buildID = await row('Build box').getAttribute('data-server');
  const answer = (path, body) => page.route(config.Origin + path, route => route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify(body) }));
  await answer('/api/credentials', [{ id: 'a'.repeat(32), name: 'Deploy password', kind: 'password', username: 'deploy', fingerprint: '' }, { id: 'b'.repeat(32), name: 'Elsewhere', kind: 'password', username: 'other', fingerprint: '' }]);
  await answer('/api/connections', [{ id: 'c'.repeat(32), name: 'Mine', target: buildID, credential: 'a'.repeat(32), revision: '1', trust: 'unverified', fingerprint: '' }, { id: 'd'.repeat(32), name: 'Other', target: 'e'.repeat(32), credential: 'b'.repeat(32), revision: '1', trust: 'unverified', fingerprint: '' }]);
  await page.reload(); await row('Build box').waitFor(); await settled();
  await row('Build box').getByRole('button', { name: 'How they sign in', exact: true }).click(); await page.locator('#shared-dialog').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('#shared-title').textContent(), 'How people sign in to Build box');
  assert.match(await page.locator('#shared-lead').textContent(), /^Now each person on the list signs in with their own key or password\. Instead, Keybash can sign them all in/);
  assert.equal(await page.locator('#shared-who').textContent(), 'Who can use it: alice');
  assert.equal(await page.locator('#shared-change-who').textContent(), 'Change who');
  assert.match(await page.locator('#shared-user-hint').textContent(), /^The name you would type to sign in on Build box\. It is an account on that server, not a person in Keybash\.$/);
  assert.deepEqual(await page.locator('#shared-names .name-chip').allTextContents(), ['deploy'], 'the names offered were not those of this server');
  // Each kind says what it is, the chosen one looks chosen, and the button
  // says what it does.
  const look = kind => page.locator(`#shared-kind [data-kind=${kind}]`).evaluate(element => getComputedStyle(element).backgroundColor);
  assert.equal(await page.locator('#shared-submit').textContent(), 'Make the key');
  assert.match(await page.locator('#shared-kind-hint').textContent(), /Nobody ever sees the key/);
  assert.notEqual(await look('ssh-key'), await look('password'), 'the chosen kind looked like the other');
  await page.locator('#shared-kind [data-kind=password]').click();
  assert.equal(await page.locator('#shared-submit').textContent(), 'Save the password');
  assert.match(await page.locator('#shared-kind-hint').textContent(), /^The account’s own password, typed once and never shown again\. Anyone who already knows it can still sign in without Keybash/);
  assert.notEqual(await look('ssh-key'), await look('password'), 'the chosen kind looked like the other');
  await page.locator('#shared-kind [data-kind=ssh-key]').click();
  await page.locator('#shared-names .name-chip').click();
  assert.equal(await page.locator('#shared-user').inputValue(), 'deploy', 'a name picked was not filled in');
  // Who may connect is one step away, for the same server.
  await page.locator('#shared-change-who').click(); await page.locator('#access-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#access-title').textContent(), 'Who can use Build box?');
  assert(await page.locator('#shared-dialog').isHidden(), 'the sign-in sheet stayed open under the list');
  await page.locator('#access-cancel').click(); await page.locator('#access-dialog').waitFor({ state: 'hidden' });
  await page.unroute(config.Origin + '/api/credentials'); await page.unroute(config.Origin + '/api/connections');
  await page.reload(); await row('Build box').waitFor(); await settled();

  stage = 'shared key';
  page.on('response', listen);
  await row('Build box').getByRole('button', { name: 'How they sign in', exact: true }).click(); await page.locator('#shared-dialog').waitFor({ state: 'visible' }); await settled();
  assert(await page.locator('#shared-names').isHidden(), 'names were offered without a connection to the server');
  assert(await page.locator('#shared-secret-field').isHidden(), 'a key made here asked for a password');
  await page.locator('#shared-user').fill('deploy'); await page.locator('#shared-submit').click();
  await page.locator('#shared-manage').waitFor({ state: 'visible' }); await settled();
  const sharedLine = /^mkdir -p ~\/\.ssh && chmod 700 ~\/\.ssh && echo 'restrict,pty ssh-ed25519 [A-Za-z0-9+/]+={0,2} keybash-shared' >> ~\/\.ssh\/authorized_keys && chmod 600 ~\/\.ssh\/authorized_keys$/;
  const firstKey = await page.locator('#shared-command').textContent(); assert.match(firstKey, sharedLine);
  assert.match(await sheetNotice('shared-dialog').textContent(), /^Key made\. Add its line on Build box/);
  assert.equal(await row('Build box').locator('.server-sign-in').textContent(), 'Keybash signs them in as deploy, with a key it made · not on the server yet');
  assert.match(await page.locator('#shared-summary').textContent(), /^Keybash signs them in as deploy, with a key it made\. Set by alice on /);
  assert.match(await page.locator('#shared-lead').textContent(), /^Keybash signs everyone on the list in with this\./);
  // The command's own Copy copies it whole.
  await page.locator('#shared-key > .command-box .copy-chip').click(); await page.waitForFunction(() => copiedText.length === 1); await settled();
  assert.equal(await page.evaluate(() => copiedText[0]), firstKey, 'Copy took other text than the command');
  await page.evaluate(() => { copiedText.length = 0; });
  // A new key waits beside the current one until the switch.
  await page.locator('#shared-new').click(); await page.locator('#shared-next-box').waitFor({ state: 'visible' }); await settled();
  const nextKey = await page.locator('#shared-next-command').textContent(); assert.match(nextKey, sharedLine); assert.notEqual(nextKey, firstKey);
  assert.equal(await page.locator('#shared-command').textContent(), firstKey, 'a new key replaced the current one before the switch');
  assert(await page.locator('#shared-new').isHidden(), 'a second new key was offered while one waits');
  assert.match(await row('Build box').locator('.server-sign-in').textContent(), / · a new key is waiting$/);
  await page.locator('#shared-switch').click(); await sheetNotice('shared-dialog').filter({ hasText: /uses the new key now/ }).waitFor(); await settled();
  assert.equal(await page.locator('#shared-command').textContent(), nextKey, 'the switch did not make the new key the one used');
  assert(await page.locator('#shared-next-box').isHidden() && await page.locator('#shared-new').isVisible(), 'the sheet still showed a waiting key');
  // A waiting key can be dropped; the current one stays.
  await page.locator('#shared-new').click(); await page.locator('#shared-next-box').waitFor({ state: 'visible' }); await settled();
  await page.locator('#shared-keep').click(); await sheetNotice('shared-dialog').filter({ hasText: /^The new key was destroyed\. The current one stays\.$/ }).waitFor(); await settled();
  assert.equal(await page.locator('#shared-command').textContent(), nextKey);
  await page.locator('#shared-close').click(); await page.locator('#shared-dialog').waitFor({ state: 'hidden' });

  stage = 'shared card';
  // Everyone on the list finds it ready on their Connections page, and sees
  // nothing of it but its user name.
  await page.locator('.rail-item[data-page=connections]').click(); await page.waitForURL(config.Origin + '/'); await settled();
  const sharedCard = page.locator('.server-card[data-shared]'); await sharedCard.waitFor();
  assert.equal(await sharedCard.count(), 1);
  assert.equal(await sharedCard.locator('.server-name').textContent(), 'Build box');
  assert.equal(await sharedCard.locator('.server-kind').textContent(), 'Terminal (SSH) · Set up by your administrator');
  assert.equal(await sharedCard.locator('.trust-state').textContent(), 'Ready');
  assert.match(await sharedCard.locator('.server-screen').textContent(), /^deploy@Build box ~ \$ /);
  assert.equal(await sharedCard.getByRole('button').count(), 0, 'a shared card offered to change it');
  assert(await page.locator('#first-steps').isHidden(), 'the first steps showed beside a shared server');
  const buildBox = await sharedCard.getAttribute('data-shared');
  const connect = sharedCard.getByRole('link', { name: 'Connect', exact: true });
  assert.equal(await connect.getAttribute('href'), `/remote/shared/ssh/${buildBox}`);

  stage = 'shared card states';
  // A card offers to connect only when ready. The page takes no field it does
  // not show, so a row with another one is refused whole, as are two rows for
  // one server.
  const listed = { server: buildBox, name: 'Build box', protocol: 'ssh', username: 'deploy', trust: 'verified' };
  const answerShared = rows => page.route(config.Origin + '/api/shared', route => route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify(rows) }));
  for (const [trust, words, help] of [['stopped', 'Server changed', /shows a different certificate/], ['unavailable', 'Unavailable', /does not open right now/]]) {
    await answerShared([{ ...listed, trust }]); await page.reload(); await sharedCard.waitFor(); await settled();
    assert.equal(await sharedCard.locator('.trust-state').textContent(), words);
    assert.match(await sharedCard.locator('.server-help').textContent(), help);
    assert.equal(await sharedCard.getByRole('link').count(), 0, `a ${trust} shared card offered to connect`);
    await page.unroute(config.Origin + '/api/shared');
  }
  for (const rows of [[{ ...listed, secret: 'synthetic' }], [listed, listed]]) {
    await answerShared(rows); await page.reload(); await settled();
    await page.locator('#notice').filter({ hasText: /./ }).waitFor();
    assert.equal(await sharedCard.count(), 0, 'the page showed shared rows it should refuse');
    await page.unroute(config.Origin + '/api/shared');
  }
  await page.reload(); await sharedCard.waitFor(); await settled();

  stage = 'shared terminal';
  const [terminal] = await Promise.all([page.waitForEvent('popup'), connect.click()]);
  terminal.on('pageerror', error => errors.push(error.name)); terminal.on('response', listen);
  terminal.on('request', request => { if (!request.url().startsWith(config.Origin + '/')) external.push('external request'); });
  await terminal.waitForFunction(() => document.title === 'Build box · Keybash');
  await terminal.locator('#status').filter({ hasText: /^Connected$/ }).waitFor();
  await terminal.locator('.xterm-helper-textarea').focus(); await terminal.keyboard.type('shared-key-echo');
  await terminal.waitForFunction(() => document.querySelector('.xterm-rows')?.textContent.includes('shared-key-echo'));
  // The key worked once, so the Servers page says it is in use.
  await page.locator('.rail-item[data-page=servers]').click(); await page.waitForURL(config.Origin + '/servers'); await row('Build box').waitFor(); await settled();
  assert.equal(await row('Build box').locator('.server-sign-in').textContent(), 'Keybash signs them in as deploy, with a key it made · in use');

  stage = 'stop sharing';
  // Stopping asks first; then the server has none, and the open session ends.
  await row('Build box').getByRole('button', { name: 'How they sign in', exact: true }).click(); await page.locator('#shared-dialog').waitFor({ state: 'visible' }); await settled();
  await page.locator('#shared-stop').click(); await page.locator('#delete-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#delete-title').textContent(), 'Stop signing people in to this server?');
  assert.equal(await page.locator('#confirm-delete').textContent(), 'Stop signing them in');
  await page.locator('#confirm-delete').click(); await page.locator('#notice').filter({ hasText: /^Keybash no longer signs anyone in to Build box\. People on its list need their own key or password\.$/ }).waitFor(); await settled();
  assert.equal(await row('Build box').locator('.server-sign-in').textContent(), 'Each person signs in with their own key or password.', 'a stopped shared key still shows');
  await terminal.locator('#notice').filter({ hasText: /^This server, this connection or your access to it changed, so this session ended\.$/ }).waitFor();
  await terminal.close();
  assert.equal((await page.request.get(`${config.Origin}/remote/shared/ssh/${buildBox}`)).status(), 404, 'a stopped shared key still opened a page');
  // Every OpenSSH private key's body begins with this (base64 of openssh-key-v1).
  assert.doesNotMatch(await page.content(), /b3BlbnNzaC1rZXktdjE/, 'the page held a private key');
  page.off('response', listen);

  stage = 'connection form';
  await page.locator('.rail-item[data-page=connections]').click(); await page.waitForURL(config.Origin + '/'); await settled();
  const options = await page.locator('#connection-target option').allTextContents();
  assert(options.includes('Build box · SSH'), 'the server given to alice is not offered');
  assert(!options.includes('Catalog box · SSH'), 'a server nobody gave alice is offered');
  assert.equal(await page.locator('.server-card[data-shared]').count(), 0, 'a stopped shared key still shows on Connections');

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

  stage = 'desktop: shared password';
  const sharedPassword = config.SharedPassword;
  page.on('response', listen);
  await row('Desk').getByRole('button', { name: 'How they sign in', exact: true }).click(); await page.locator('#shared-dialog').waitFor({ state: 'visible' }); await settled();
  assert(await page.locator('#shared-kind').isHidden(), 'a desktop offered a key');
  assert(await page.locator('#shared-secret-field').isVisible(), 'a desktop did not ask for its password');
  assert.match(await page.locator('#shared-kind-hint').textContent(), /^A desktop signs in with a password\. The account’s own password/);
  assert.equal(await page.locator('#shared-submit').textContent(), 'Save the password');
  // Nobody is on Desk's list yet, and the sheet says so.
  assert.equal(await page.locator('#shared-who').textContent(), 'Nobody can use it yet.');
  assert.equal(await page.locator('#shared-change-who').textContent(), 'Choose who');
  await page.locator('#shared-user').fill('kbtest'); await page.locator('#shared-secret').fill(sharedPassword); await page.locator('#shared-submit').click();
  await page.locator('#shared-password-form').waitFor({ state: 'visible' }); await settled();
  assert.equal(await page.locator('#shared-secret').inputValue(), '', 'the typed password stayed on the page');
  assert.match(await page.locator('#shared-summary').textContent(), /^Keybash signs them in as kbtest, with a password it keeps\. Set by alice on /);
  assert.equal(await row('Desk').locator('.server-sign-in').textContent(), 'Keybash signs them in as kbtest, with a password it keeps.');
  await page.locator('#shared-password').fill(`${sharedPassword}-2`); await page.locator('#shared-password-form button[type=submit]').click();
  await sheetNotice('shared-dialog').filter({ hasText: /^Keybash uses the new password from now on\.$/ }).waitFor(); await settled();
  assert.equal(await page.locator('#shared-password').inputValue(), '', 'the new password stayed on the page');
  await page.locator('#shared-close').click(); await page.locator('#shared-dialog').waitFor({ state: 'hidden' });

  stage = 'desktop: shared card';
  // Put on Desk's list, alice finds it on her Connections page. Its desktop
  // starts with the password set last, which the page never had.
  await row('Desk').getByRole('button', { name: 'Who can use it', exact: true }).click(); await page.locator('#access-dialog').waitFor({ state: 'visible' }); await settled();
  await page.locator('#access-people label').filter({ hasText: 'alice' }).locator('input').check(); await page.locator('#access-form button[type=submit]').click();
  await page.locator('#access-dialog').waitFor({ state: 'hidden' }); await settled();
  await page.locator('.rail-item[data-page=connections]').click(); await page.waitForURL(config.Origin + '/'); await settled();
  const deskCard = page.locator('.server-card[data-shared]'); await deskCard.waitFor();
  assert.equal(await deskCard.count(), 1);
  assert.equal(await deskCard.locator('.server-kind').textContent(), 'Desktop (RDP) · Set up by your administrator');
  assert.equal(await deskCard.locator('.server-screen').textContent(), 'kbtest@Desk · desktop');
  const deskID = await deskCard.getAttribute('data-shared');
  assert.equal(await deskCard.getByRole('link', { name: 'Connect', exact: true }).getAttribute('href'), `/remote/shared/rdp/${deskID}`);
  const asked = async () => (await page.request.get(config.Origin + '/__fixture/desktop', { headers: { 'X-Fixture-Control': config.Control } })).json();
  assert.equal((await asked()).calls, 0, 'a desktop started before it was opened');
  const [desktop] = await Promise.all([page.waitForEvent('popup'), deskCard.getByRole('link', { name: 'Connect', exact: true }).click()]);
  desktop.on('pageerror', error => errors.push(error.name)); desktop.on('response', listen); desktop.on('request', request => { if (!request.url().startsWith(config.Origin + '/')) external.push('external request'); });
  await desktop.waitForFunction(() => document.title === 'Desk · Keybash');
  let started; for (let tries = 0; tries < 100 && !(started = await asked()).calls; tries++) await desktop.waitForTimeout(100);
  assert.deepEqual(started, { calls: 1, username: 'kbtest', password: true }, 'the desktop did not start with the shared password');
  assert.doesNotMatch(await desktop.content(), new RegExp(sharedPassword), 'the desktop page held the password');
  await desktop.close();
  page.off('response', listen);
  // Nothing the page holds, or any answer it got, carries the password.
  assert.doesNotMatch(await page.content(), new RegExp(sharedPassword));
  assert(answers.length >= 10, 'the answers were not searched');
  for (const answer of await Promise.all(answers)) assert(!answer.includes(sharedPassword) && !answer.includes('b3BlbnNzaC1rZXktdjE') && !answer.includes('PRIVATE KEY'), 'an answer carried a shared secret');

  assert.deepEqual(errors, []); assert.deepEqual(external, []);
  console.log('Servers page browser: list, refusals, compare-before-add, access, connection form, removal, desktop, renewal, unchecked desktop, the narrow list, the sign-in sheet, shared key and shared password, and their cards and sessions passed');
} catch (error) {
  console.log('Servers browser stage:', stage, error.code === 'ERR_ASSERTION' ? error.message : error.name);
  if (process.env.KEYBASH_SERVERS_SCREENSHOT) await page.screenshot({ path: process.env.KEYBASH_SERVERS_SCREENSHOT });
  throw new Error('servers page browser checks failed');
} finally { await context.close(); await browser.close(); }
