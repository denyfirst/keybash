import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const config=JSON.parse(readFileSync(0,'utf8'));
const url=new URL(config.Origin);
assert.equal(url.protocol,'https:');assert.equal(url.hostname,'127.0.0.1');
const browser=await chromium.launch({headless:true,...(process.env.KEYBASH_BROWSER_CHANNEL?{channel:process.env.KEYBASH_BROWSER_CHANNEL}:{})});
const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1400,height:1000},...(config.Native?{permissions:['clipboard-read','clipboard-write']}:{})});
await context.addInitScript(({native})=>{
  globalThis.clipState={mode:'allow',text:'untouched',reads:0,writes:0,resolve:null};
  const originalRead=navigator.clipboard?.readText.bind(navigator.clipboard);
  const originalWrite=navigator.clipboard?.writeText.bind(navigator.clipboard);
  globalThis.testClipboardRead=()=>native?originalRead():Promise.resolve(clipState.text);
  globalThis.testClipboardWrite=text=>native?originalWrite(text):Promise.resolve(clipState.text=text);
  Object.defineProperty(navigator,'clipboard',{value:{
    readText(){clipState.reads++;if(clipState.mode==='pending')return new Promise(resolve=>clipState.resolve=resolve);if(clipState.mode==='deny')return Promise.reject(new Error('denied'));return testClipboardRead();},
    writeText(text){clipState.writes++;if(clipState.mode==='deny')return Promise.reject(new Error('denied'));return testClipboardWrite(text);}
  }});
},{native:config.Native});
const page=await context.newPage(),errors=[],outbound=[];
page.on('pageerror',e=>errors.push(e.name+': '+e.message));
page.on('request',r=>{if(!r.url().startsWith(config.Origin+'/'))outbound.push('external request');});
try{
  await page.goto(config.Origin);await page.locator('#code').fill(config.Code);await page.getByRole('button',{name:'Open session',exact:true}).click();
  await page.locator('#status').filter({hasText:/^Connected$/}).waitFor();
  const remote=config.Native?'Remote Azərbaycan 🔑':'Remote Azərbaycan 🔑 <img src=x onerror=alert(1)>';
  // Text the remote copied waits behind Copy, marked, never written here unasked.
  await page.waitForFunction(()=>!document.getElementById('copy').disabled&&document.getElementById('copy').dataset.new==='',undefined,{timeout:10000});
  assert.deepEqual(await page.evaluate(()=>[clipState.reads,clipState.writes]),[0,0]);
  await page.locator('#copy').click();
  await page.waitForFunction(()=>clipState.writes===1);
  assert.equal(await page.evaluate(()=>testClipboardRead()),remote);
  assert.equal(await page.locator('#copy').getAttribute('data-new'),null,'copying kept the mark');
  // Paste: several lines are shown first, and go only when sent.
  const local='Local Azərbaycan 🔑\nline';
  await page.evaluate(text=>testClipboardWrite(text),local);
  await page.locator('#paste').click();
  await page.locator('#paste-review').waitFor();
  assert.equal(await page.locator('#paste-text').inputValue(),local);
  assert.equal(await page.locator('#paste-preview').textContent(),local);
  await page.locator('#paste-send').click();
  await page.locator('#paste-review').waitFor({state:'hidden'});
  assert.equal(await page.locator('#paste-text').inputValue(),'');
  // Screen size from the bar's own menu.
  await page.locator('#screen').click();await page.locator('#screen-menu').waitFor();
  assert.equal(await page.locator('#screen-menu [data-size="fit"]').getAttribute('aria-checked'),'true');
  await page.locator('#screen-menu [data-size="1280x720"]').click();
  await page.locator('#screen-menu').waitFor({state:'hidden'});
  await page.waitForFunction(()=>document.getElementById('size').textContent==='1280 × 720',undefined,{timeout:10000});
  await page.waitForFunction(()=>[...document.querySelectorAll('#display canvas')].some(c=>c.width>=1280&&c.height>=720));
  assert.equal(await page.locator('#screen-choice').textContent(),'1280 × 720');
  assert.equal(await page.locator('#screen-menu [data-size="1280x720"]').getAttribute('aria-checked'),'true');
  // Without clipboard permission: the text to select, and a box to paste into.
  await page.evaluate(()=>{clipState.mode='deny';});
  await page.locator('#copy').click();
  await page.locator('#notice').filter({hasText:'No clipboard permission'}).waitFor();
  await page.locator('#copy-panel').waitFor();
  assert.equal(await page.locator('#remote-text').inputValue(),remote);
  await page.locator('#copy-panel button[value=close]').click();await page.locator('#copy-panel').waitFor({state:'hidden'});
  await page.locator('#paste').click();
  await page.locator('#paste-review').waitFor();
  assert.equal(await page.locator('#paste-text').evaluate(e=>e===document.activeElement),true);
  await page.locator('#paste-text').fill('🔑'.repeat(10000));
  await page.locator('#paste-send').click();
  await page.locator('#notice').filter({hasText:'The text was not sent'}).waitFor();
  await page.locator('#cancel-paste').click();await page.locator('#paste-review').waitFor({state:'hidden'});
  // A read still pending when the session ends sends nothing.
  await page.evaluate(()=>{clipState.mode='pending';});
  await page.locator('#paste').click();
  await page.waitForFunction(()=>typeof clipState.resolve==='function');
  await page.locator('#disconnect').click();
  await page.evaluate(()=>clipState.resolve('late-local-text-must-not-send'));
  assert.equal(await page.locator('#paste-review').evaluate(e=>e.open),false,'a late read opened the review');
  assert.equal(await page.locator('#paste-text').inputValue(),'');assert.equal(await page.locator('#remote-text').inputValue(),'');
  for (const id of ['screen','copy','paste']) assert.equal(await page.locator('#'+id).isDisabled(),true,id+' outlived the session');
  assert.equal(await page.locator('#display').evaluate(e=>e.childElementCount),0);
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
  console.log(`RDP workspace: ${config.Native?'actual headless OS':'isolated mocked'} clipboard, explicit Unicode paste, refusal/fallback, resize and stale-read revocation passed`);
}catch(error){console.log('Workspace test state:',await page.locator('#status').textContent(),await page.locator('#notice').textContent(),errors);throw error;}
finally{await context.close();await browser.close();}
