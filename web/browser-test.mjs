import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const config = JSON.parse(readFileSync(0, 'utf8'));
const url = new URL(config.Origin);
assert.equal(url.protocol, 'https:');
assert.equal(url.hostname, '127.0.0.1');
if (typeof config.Code!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(config.Code)) throw new Error('invalid lab input');
// Isolated synthetic fixture certificate only; no user/system trust changes.
const browser = await chromium.launch({ headless: true, ...(process.env.KEYBASH_BROWSER_CHANNEL ? { channel: process.env.KEYBASH_BROWSER_CHANNEL } : {}) });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 850 } });
const page = await context.newPage();
const outbound = [], errors = [];
page.on('request', request => { if (!request.url().startsWith(config.Origin + '/')) outbound.push('unexpected origin'); });
page.on('pageerror', () => errors.push('browser script failure'));
await context.addInitScript(() => {
  // Deterministic permission/OSC test, without reading or overwriting the
  // workstation's real clipboard. Linux CI also exercises the native API.
  globalThis.labClipboard = { text: 'clipboard-sentinel', writes: 0, denied: false };
  if (navigator.platform.includes('Win')) {
    Object.defineProperty(navigator, 'clipboard', { value: {
      async readText() { if (labClipboard.denied) throw new Error('permission denied'); return labClipboard.text; },
      async writeText(text) { if (labClipboard.denied) throw new Error('permission denied'); labClipboard.text = text; labClipboard.writes++; }
    } });
  }
});
async function visible(text) {
  await page.locator('.xterm-rows').filter({ hasText: text }).waitFor({ timeout: 10000 });
}
async function paste(text) {
  await page.locator('#terminal').evaluate((element, text) => {
    const data = new DataTransfer(); data.setData('text/plain', text);
    element.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: data }));
  }, text);
}
async function command(text) {
  await page.locator('.xterm-helper-textarea').focus();
  await page.keyboard.insertText(text); await page.keyboard.press('Enter');
}
async function selectAndCopy(text) {
  const box=await page.locator('.xterm-rows > div').filter({hasText:text}).first().boundingBox();
  assert(box);
  await page.mouse.move(box.x+1,box.y+box.height/2);
  await page.mouse.down();
  await page.mouse.move(box.x+text.length*8,box.y+box.height/2,{steps:8});
  await page.mouse.up();
  await page.getByRole('button',{name:'Copy',exact:true}).click();
}
try {
  await page.goto(config.Origin);
  await page.locator('#code').fill(config.Code);
  await page.getByRole('button', { name: 'Open session' }).click();
  await page.locator('#status').filter({ hasText: 'Connected' }).waitFor();
  await visible(config.Mode === 'linux' ? 'keybash-lab>' : '');
  assert.equal(await page.locator('#code').inputValue(), '');
  const cookies = await context.cookies();
  assert(cookies.some(cookie => cookie.name === '__Host-keybash-lab' && cookie.httpOnly && cookie.secure && cookie.sameSite === 'Strict'));
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);

  if (config.Mode === 'linux') {
    await command("printf '\\u0259\\u0131\\u00f6\\u00fc\\u00e7\\u015f\\u011f\\n'");
    await visible('əıöüçşğ');
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await selectAndCopy('əıöüçşğ');
    assert((await page.evaluate(()=>navigator.clipboard.readText())).includes('əıöüçşğ'));
    await page.evaluate(() => navigator.clipboard.writeText('clipboard-sentinel'));
    await command("printf '\\033]52;c;YXR0YWNr\\a'");
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'clipboard-sentinel');
    await command("printf '%s\\n' '<img src=x onerror=alert(1)>'");
    await visible('<img src=x onerror=alert(1)>');
    assert.equal(await page.locator('#terminal img').count(), 0);
  } else {
    await paste('Azərbaycan əıöüçşğ'); await visible('Azərbaycan');
    await selectAndCopy('Azərbaycan əıöüçşğ');
    assert((await page.evaluate(()=>labClipboard.text)).includes('Azərbaycan'));
    if (process.env.KEYBASH_SCREENSHOT) await page.screenshot({ path: process.env.KEYBASH_SCREENSHOT, fullPage: true });
    await page.locator('.xterm-helper-textarea').focus();
    await page.keyboard.insertText('\x1b]52;c;YXR0YWNr\x07');
    assert.equal(await page.evaluate(() => labClipboard.writes), 1);
    await paste('<img src=x onerror=alert(1)>'); await visible('<img');
    assert.equal(await page.locator('#terminal img').count(), 0);
  }
  await paste('PASTE_REVIEW_ONE\nPASTE_REVIEW_TWO');
  await page.locator('#paste-review').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#paste-preview').inputValue(), 'PASTE_REVIEW_ONE\nPASTE_REVIEW_TWO');
  assert(!(await page.locator('.xterm-rows').innerText()).includes('PASTE_REVIEW_ONE'));
  // Close/reopen in one task: the old queued close must not clear the new
  // review. Unsafe-looking input remains a review decision, including bidi.
  await page.evaluate(() => {
    document.getElementById('cancel-paste').click();
    const data = new DataTransfer(); data.setData('text/plain', 'hidden\u202e\x1b[201~');
    document.getElementById('terminal').dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: data }));
  });
  assert(!(await page.locator('.xterm-rows').innerText()).includes('PASTE_REVIEW_ONE'));
  await page.locator('#paste-review').waitFor({ state: 'visible' });
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert((await page.locator('#paste-preview').inputValue()).includes('\\u202e'));
  await page.getByRole('button', { name: 'Cancel' }).click();
  await paste('a'.repeat(32769));
  await page.locator('#notice').filter({ hasText: '32 KiB' }).waitFor();

  if (config.Mode === 'linux') {
    // Native clipboard in a fresh headless Linux browser, never the user's OS.
    await page.evaluate(() => navigator.clipboard.writeText("printf 'KB_%s\\n' 'PASTE'"));
    await page.getByRole('button', { name: 'Paste', exact: true }).click();
    await page.waitForTimeout(100);
    assert(!(await page.locator('.xterm-rows').innerText()).includes('KB_PASTE'));
    await page.locator('.xterm-helper-textarea').focus(); await page.keyboard.press('Enter');
    await visible('KB_PASTE');
    await paste("printf 'KB_%s\\n' 'MULTILINE'\nprintf 'KB_%s\\n' 'END'");
    await page.getByRole('button', { name: 'Send to terminal' }).click();
    // Bash bracketed paste does not execute until explicit Enter.
    assert(!(await page.locator('.xterm-rows').innerText()).includes('KB_MULTILINE'));
    await page.locator('.xterm-helper-textarea').focus(); await page.keyboard.press('Enter');
    await visible('KB_MULTILINE'); await visible('KB_END');
    await page.setViewportSize({ width: 1450, height: 900 });
    await page.waitForTimeout(200);
    await command('stty size');
    const size = (await page.locator('#size').innerText()).split(' × ').map(Number);
    await visible(`${size[1]} ${size[0]}`);
    await command("stty -echo; bash --noprofile --norc -c 'printf \"KB_%s\\n\" INTERRUPT; exec sleep 30'");
    await visible('KB_INTERRUPT');
    await page.locator('.xterm-helper-textarea').focus(); await page.keyboard.press('Control+c');
    await command("printf 'KB_%s\\n' 'AFTER_INTERRUPT'"); await visible('KB_AFTER_INTERRUPT');
  } else {
    await paste('APPROVED_ONE\nAPPROVED_TWO');
    await page.getByRole('button', { name: 'Send to terminal' }).click();
    await visible('APPROVED_ONE'); await visible('APPROVED_TWO');
    await page.evaluate(() => { labClipboard.denied = true; });
    await page.getByRole('button', { name: 'Paste', exact: true }).click();
    await page.locator('#clipboard-panel').waitFor({ state: 'visible' });
    await page.locator('#clipboard-text').fill('FALLBACK_PANEL');
    await page.getByRole('button', { name: 'Review paste' }).click(); await visible('FALLBACK_PANEL');
  }
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await page.locator('#status').filter({ hasText: 'Not connected' }).waitFor();
  await page.waitForTimeout(100);
  assert(!(await context.cookies()).some(cookie => cookie.name === '__Host-keybash-lab'));
  assert.equal(await page.locator('#terminal').innerText(),'');
  assert.deepEqual(outbound, []); assert.deepEqual(errors, []);
  console.log(`Browser lab passed (${config.Mode === 'linux' ? 'Linux Bash PTY + Chromium' : 'synthetic SSH + Edge; clipboard mocked'})`);
} finally { await context.close(); await browser.close(); }
