import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
const config = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(new URL(config.Origin).hostname, '127.0.0.1');
const browser = await chromium.launch({ headless: true, args: ['--disable-3d-apis'], ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true, viewport: { width: 1280, height: 900 } });
const page = await context.newPage(); const errors = [], external = [];
context.on('page', opened => { opened.on('pageerror', error => errors.push(error.name)); });
page.on('pageerror', error => errors.push(error.name));
// Only web requests count: a browser's own pages, such as Edge's downloads
// panel after a download, are not the page's.
context.on('request', request => { const url = request.url(); if (/^(https?|wss?):/.test(url) && !url.startsWith(config.Origin + '/')) external.push(url); });
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
const fixture = async path => {
  const response = await context.request.post(config.Origin + path, { headers: { 'X-Fixture-Control': config.Control } });
  assert.equal(response.status(), 200, `fixture ${path}`);
  return response.json();
};
let stage = 'bootstrap';
let files;
try {
  await page.goto(config.Origin + '/login'); await page.locator('#setup-code').fill(config.Code); await page.locator('#setup-user').fill('alice'); await page.locator('#setup-password').fill(config.Password); await page.locator('#bootstrap button').click();
  await page.waitForURL(config.Origin + '/'); await settled();
  await page.locator('#begin-enroll').click(); await page.locator('#seed-panel').waitFor({ state: 'visible' }); const seed = await page.locator('#seed').textContent(); await settled();
  await page.locator('#enrollment-code').fill(otp(seed, Math.floor(Date.now() / 30000))); await page.locator('#enrollment button').click(); await page.locator('#recovery').waitFor({ state: 'visible' }); await settled();
  await page.locator('#saved-recovery').click(); await page.locator('#vault').waitFor({ state: 'visible' }); await settled();

  stage = 'the card';
  const { account } = await fixture('/__fixture/account');
  assert.match(account, /^[a-f0-9]{32}$/);
  await page.goto(config.Origin + '/'); await settled();
  const card = page.locator(`.server-card[data-account="${account}"]`);
  await card.waitFor();
  const link = card.locator('a.files-link');
  assert.equal(await link.getAttribute('href'), `/remote/files/${account}`);
  assert.deepEqual([await link.getAttribute('target'), await link.getAttribute('rel')], ['_blank', 'noopener']);
  assert.equal((await link.textContent()).trim(), 'Files');
  [files] = await Promise.all([context.waitForEvent('page'), link.click()]);
  await files.waitForFunction(() => document.body.dataset.stage === 'ready');
  await files.locator('#rows tr').first().waitFor();

  stage = 'the folder';
  assert.equal(await files.locator('#server-account').textContent(), 'deploy@catalog.invalid'.replace('catalog.invalid', await files.evaluate(() => document.getElementById('server-account').textContent.split('@')[1])));
  assert.equal(await files.locator('#mode').textContent(), 'Upload and download');
  assert(await files.locator('#readonly-note').isHidden(), 'the download-only note shows on a full server');
  const row = name => files.locator('#rows tr').filter({ has: files.locator('.name-line, .name-open', { hasText: new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`) }) });
  await row('docs').waitFor(); await row('notes.txt').waitFor();
  // A name with a direction character shows it as a mark, never as text that turns.
  const tricky = files.locator('#rows tr', { has: files.locator('.ctl', { hasText: 'U+202E' }) });
  assert.equal(await tricky.count(), 1, 'the hidden character is not shown');
  assert.equal(await tricky.locator('.name-line').evaluate(el => [...el.textContent].some(c => c === '‮')), false, 'the hidden character reached the text');
  // A name that is not text is listed with no action.
  const unreadable = files.locator('#rows tr', { has: files.locator('.name-unreadable') });
  assert.equal(await unreadable.count(), 1);
  assert.equal(await unreadable.locator('button').count(), 0, 'an unreadable name offers an action');
  assert.equal(await unreadable.locator('input[type=checkbox]').isDisabled(), true);

  stage = 'moving around';
  await row('docs').locator('.name-open').click();
  await row('readme.md').waitFor();
  assert.match(await files.locator('#crumbs').textContent(), /docs/);
  await files.keyboard.press('Backspace');
  await row('notes.txt').waitFor();
  await row('docs').focus(); await files.keyboard.press('Enter');
  await row('readme.md').waitFor();
  await files.locator('#crumbs button.crumb-home').click();
  await row('notes.txt').waitFor();

  stage = 'a new folder';
  await files.locator('#new-folder').click(); await files.locator('#name-dialog').waitFor({ state: 'visible' });
  await files.locator('#name-input').fill('a/b'); await files.locator('#name-save').click();
  assert.match(await files.locator('#name-hint').textContent(), /slash/);
  assert(await files.locator('#name-dialog').isVisible(), 'a refused name closed the sheet');
  await files.locator('#name-input').fill('reports'); await files.locator('#name-save').click();
  await row('reports').waitFor();
  await row('reports').locator('.name-open').click();
  await files.waitForFunction(() => document.getElementById('empty').hidden === false);

  stage = 'upload and download';
  const body = 'Hello from the Files page, '.repeat(3000);
  await files.locator('#upload-input').setInputFiles({ name: 'hello.txt', mimeType: 'text/plain', buffer: Buffer.from(body) });
  await row('hello.txt').waitFor();
  await files.locator('.transfer[data-state="done"]').first().waitFor();
  const [download] = await Promise.all([files.waitForEvent('download'), row('hello.txt').locator('.act-download').click()]);
  assert.equal(download.suggestedFilename(), 'hello.txt');
  assert.equal(readFileSync(await download.path(), 'utf8'), body, 'the downloaded bytes differ');

  stage = 'replace';
  await files.locator('#upload-input').setInputFiles({ name: 'hello.txt', mimeType: 'text/plain', buffer: Buffer.from('second') });
  await files.locator('#replace-dialog').waitFor({ state: 'visible' });
  await files.locator('#replace-confirm').click();
  await files.waitForFunction(() => document.querySelectorAll('.transfer[data-state="done"]').length >= 3);
  const [again] = await Promise.all([files.waitForEvent('download'), row('hello.txt').locator('.act-download').click()]);
  assert.equal(readFileSync(await again.path(), 'utf8'), 'second', 'the replace did not take');

  stage = 'rename and delete';
  await row('hello.txt').locator('.act-rename').click(); await files.locator('#name-dialog').waitFor({ state: 'visible' });
  await files.locator('#name-input').fill('greeting.txt'); await files.locator('#name-save').click();
  await row('greeting.txt').waitFor();
  assert.equal(await row('hello.txt').count(), 0, 'the old name stayed');
  await row('greeting.txt').locator('.act-delete').click(); await files.locator('#delete-dialog').waitFor({ state: 'visible' });
  await files.locator('#delete-confirm').click();
  await files.waitForFunction(() => document.getElementById('empty').hidden === false);

  stage = 'download only';
  await fixture('/__fixture/download-only');
  await files.locator('#ended').waitFor({ state: 'visible' });
  assert.match(await files.locator('#notice').textContent(), /changed/, 'the page did not say why it ended');
  await files.reload();
  await files.waitForFunction(() => document.body.dataset.stage === 'ready');
  assert.equal(await files.locator('#mode').textContent(), 'Download only');
  assert(await files.locator('#readonly-note').isVisible(), 'no download-only note');
  for (const id of ['#upload', '#new-folder']) assert(await files.locator(id).isHidden(), `${id} shows on a download-only server`);
  await row('notes.txt').waitFor();
  assert(await row('notes.txt').locator('.act-download').isVisible(), 'no download on a download-only server');
  assert(await row('notes.txt').locator('.act-delete').isHidden(), 'delete shows on a download-only server');

  assert.deepEqual(errors, []); assert.deepEqual(external, []);
  console.log('Files page browser: the card, hidden and unreadable names, moving around, a refused name, a new folder, upload and download, replace, rename, delete, and download only passed');
} catch (error) {
  console.log('Files browser stage:', stage, error.code === 'ERR_ASSERTION' ? error.message : error.message?.split('\n')[0] ?? error.name);
  if (process.env.KEYBASH_FILES_SCREENSHOT) await (files ?? page).screenshot({ path: process.env.KEYBASH_FILES_SCREENSHOT });
  throw new Error('files page browser checks failed');
} finally { await context.close(); await browser.close(); }
