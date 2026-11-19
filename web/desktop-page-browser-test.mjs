import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The desktop page on IronRDP against a test proxy (desktop_browser_test.go).
const config = JSON.parse(readFileSync(0, 'utf8'));
const origin = new URL(config.Origin);
assert.equal(origin.protocol, 'https:'); assert.equal(origin.hostname, '127.0.0.1');
assert.match(config.Record, /^[a-f0-9]{32}$/);
const browser = await chromium.launch({ headless: true, ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 900 } });
await context.addCookies([{ name: config.Cookie, value: config.Value, url: config.Origin }]);
await context.addInitScript(() => {
  globalThis.clipboardCalls = 0;
  Object.defineProperty(navigator, 'clipboard', { value: { readText() { clipboardCalls++; throw new Error('disabled'); }, writeText() { clipboardCalls++; throw new Error('disabled'); } } });
  globalThis.policyViolations = [];
  document.addEventListener('securitypolicyviolation', event => policyViolations.push(event.violatedDirective));
});
const page = await context.newPage();
const errors = [], outbound = [], addresses = [], sockets = [];
page.on('pageerror', error => errors.push(error.name + ': ' + error.message));
page.on('request', r => {
  const url = r.url();
  if (!url.startsWith(config.Origin + '/') && !url.startsWith('blob:' + config.Origin + '/')) outbound.push('external request');
  if (url.includes('?') || url.includes('#')) addresses.push(url);
});
page.on('websocket', socket => sockets.push(socket.url()));
const desktop = `${config.Origin}/remote/rdp/${config.Record}`;
const notice = async words => {
  await page.locator('#notice').filter({ hasText: words }).waitFor({ timeout: 30000 });
  assert.equal(await page.locator('#status').textContent(), 'Session ended');
  assert.equal(await page.locator('#reconnect').isVisible(), true);
};
let stage = 'open';
try {
  // 1. Windows refuses the stored password: the gateway's close says so.
  await page.goto(desktop);
  stage = 'the gateway\'s ending';
  await notice('The server did not accept the user name or password saved for this connection.');
  assert.deepEqual(sockets, [config.Origin.replace('https:', 'wss:') + '/api/remote/desktop']);
  assert.equal(await page.evaluate(() => typeof WebAssembly === 'object' && performance.getEntriesByType('resource').some(e => e.name.endsWith('/vendor/ironrdp/ironrdp_web_bg.wasm'))), true);

  // 2. A desktop that never answers: the page says so after 20 seconds.
  stage = 'the start limit';
  const opened = Date.now();
  await page.locator('#reconnect').click();
  await page.locator('#status').filter({ hasText: 'Connecting' }).waitFor();
  await notice('The desktop did not start within 20 seconds. Connect again to try once more.');
  assert.ok(Date.now() - opened >= 19000, 'the page gave up early');

  // 3. The server now shows another certificate: nothing starts, and the page says why.
  stage = 'a changed server';
  assert.equal((await page.request.post(config.Origin + '/__fixture/server-changed', { headers: { 'X-Fixture-Control': config.Control } })).status(), 204);
  await page.locator('#reconnect').click();
  await notice('This server now shows a different certificate, so Keybash did not connect and sent it no password.');

  stage = 'what the page touched';
  assert.equal(sockets.length, 3);
  assert.ok(sockets.every(url => url === config.Origin.replace('https:', 'wss:') + '/api/remote/desktop'), 'a socket went elsewhere');
  assert.equal(await page.evaluate(() => clipboardCalls), 0, 'the clipboard was touched unasked');
  assert.deepEqual(await page.evaluate(() => policyViolations), []);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.deepEqual(errors, []); assert.deepEqual(outbound, []); assert.deepEqual(addresses, []);
  console.log('Desktop page browser: module, proof, endings, start limit and changed server passed');
} catch (error) {
  console.log('Desktop page stage:', stage, error.code === 'ERR_ASSERTION' ? error.message : error.name, errors);
  if (process.env.KEYBASH_DESKTOP_PAGE_SCREENSHOT) await page.screenshot({ path: process.env.KEYBASH_DESKTOP_PAGE_SCREENSHOT });
  throw new Error('desktop page browser checks failed');
} finally {
  await context.close(); await browser.close();
}
