import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The terminal drawn on the GPU: WebGL 2 from the browser's software GPU, so
// the same run works on a machine without one. Output reaches the terminal
// (selected and copied back), and when the GPU drops the drawing the page's
// own text takes over with the same output, in the same session.
const config = JSON.parse(readFileSync(0, 'utf8'));
const url = new URL(config.Origin);
assert.equal(url.protocol, 'https:');
assert.equal(url.hostname, '127.0.0.1');
if (typeof config.Code !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(config.Code)) throw new Error('invalid lab input');
const browser = await chromium.launch({ headless: true, args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'],
  ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 850 } });
// What Copy writes stays here, never on the workstation's clipboard.
await context.addInitScript(() => {
  globalThis.copied = [];
  Object.defineProperty(navigator, 'clipboard', { value: { async readText() { return ''; }, async writeText(text) { copied.push(text); } } });
});
const page = await context.newPage();
const errors = [], outbound = [];
page.on('pageerror', error => errors.push(error.name + ': ' + error.message));
page.on('request', request => { if (!request.url().startsWith(config.Origin + '/')) outbound.push('unexpected origin'); });
let stage = 'open';
try {
  await page.goto(config.Origin);
  await page.locator('#code').fill(config.Code);
  await page.getByRole('button', { name: 'Open session' }).click();
  await page.locator('#status').filter({ hasText: /^Connected$/ }).waitFor();
  stage = 'drawn on the GPU';
  const gl = await page.evaluate(() => !!document.createElement('canvas').getContext('webgl2'));
  assert(gl, 'this browser offers no WebGL 2, so the GPU path cannot be tested here');
  assert.equal(await page.evaluate(() => document.body.dataset.renderer), 'gpu', 'WebGL 2 was offered but the terminal is not drawn on the GPU');
  assert((await page.locator('.xterm-screen canvas').count()) >= 1, 'no GPU canvas');
  assert.equal(await page.locator('.xterm-rows').count(), 0, 'the page text drew the terminal too');

  stage = 'output reaches the terminal';
  const mark = 'gpu-drawn-7351';
  await page.locator('.xterm-helper-textarea').focus();
  await page.keyboard.insertText(mark);
  // Nothing in the page shows the text the GPU draws, so select the whole
  // screen and copy it: the copy comes from the terminal's own buffer.
  const copyScreen = async () => {
    const box = await page.locator('.xterm-screen').boundingBox();
    await page.mouse.move(box.x + 2, box.y + 2); await page.mouse.down();
    await page.mouse.move(box.x + box.width - 2, box.y + box.height - 2, { steps: 10 }); await page.mouse.up();
    await page.getByRole('button', { name: 'Copy', exact: true }).click();
    return page.evaluate(() => copied.at(-1) ?? '');
  };
  let text = '';
  for (let tries = 0; tries < 20 && !text.includes(mark); tries++) { await page.waitForTimeout(250); text = await copyScreen(); }
  assert(text.includes(mark), 'typed text did not reach the GPU-drawn terminal');

  stage = 'the GPU drops the drawing';
  await page.evaluate(() => {
    const canvas = document.querySelector('.xterm-screen canvas:not(.xterm-link-layer)');
    canvas.getContext('webgl2').getExtension('WEBGL_lose_context').loseContext();
  });
  await page.waitForFunction(() => document.body.dataset.renderer === undefined, undefined, { timeout: 15000 });
  await page.locator('.xterm-rows').filter({ hasText: mark }).waitFor({ timeout: 10000 });
  assert.equal(await page.locator('#status').textContent(), 'Connected', 'losing the GPU ended the session');
  await page.locator('.xterm-helper-textarea').focus();
  await page.keyboard.insertText('-after');
  await page.locator('.xterm-rows').filter({ hasText: mark + '-after' }).waitFor({ timeout: 10000 });

  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.deepEqual(errors, []); assert.deepEqual(outbound, []);
  console.log('Terminal on the GPU: drawn with WebGL 2, output in the terminal, page text after the GPU dropped it');
} catch (error) {
  console.log('GPU terminal test stage:', stage, errors);
  throw error;
} finally {
  await context.close(); await browser.close();
}
