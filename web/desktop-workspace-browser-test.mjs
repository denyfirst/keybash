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
  await page.goto(config.Origin);await page.locator('#code').fill(config.Code);await page.getByRole('button',{name:'Sessiyanı aç',exact:true}).click();
  await page.locator('#status').filter({hasText:'Sessiya açıldı'}).waitFor();
  const remote=config.Native?'Remote Azərbaycan 🔑':'Remote Azərbaycan 🔑 <img src=x onerror=alert(1)>';
  await page.waitForFunction(expected=>document.getElementById('remote-text').value===expected,remote,{timeout:10000});
  assert.equal(await page.locator('#copy-remote').isEnabled(),true);
  assert.deepEqual(await page.evaluate(()=>[clipState.reads,clipState.writes]),[0,0]);
  await page.locator('#copy-remote').click();
  await page.waitForFunction(()=>clipState.writes===1);
  assert.equal(await page.evaluate(()=>testClipboardRead()),remote);
  const local='Local Azərbaycan 🔑\nline';
  await page.evaluate(text=>testClipboardWrite(text),local);
  await page.locator('#paste-local').click();
  await page.waitForFunction(expected=>document.getElementById('paste-text').value===expected,local);
  assert.equal(await page.locator('#paste-preview').textContent(),local);
  await page.locator('#paste-send').click();
  assert.equal(await page.locator('#paste-text').inputValue(),'');
  await page.locator('#resolution').selectOption('1280x720');
  await page.waitForFunction(()=>document.getElementById('size').textContent==='1280 × 720',undefined,{timeout:10000});
  await page.waitForFunction(()=>[...document.querySelectorAll('#display canvas')].some(c=>c.width>=1280&&c.height>=720));
  await page.evaluate(()=>{clipState.mode='deny';});
  await page.locator('#copy-remote').click();
  await page.locator('#notice').filter({hasText:'Clipboard icazəsi yoxdur'}).waitFor();
  assert.equal(await page.locator('#remote-text').inputValue(),remote);
  await page.locator('#paste-local').click();
  assert.equal(await page.locator('#paste-text').evaluate(e=>e===document.activeElement),true);
  await page.locator('#paste-text').fill('🔑'.repeat(10000));
  await page.locator('#paste-send').click();
  await page.locator('#notice').filter({hasText:'Mətn ötürülmədi'}).waitFor();
  await page.evaluate(()=>{clipState.mode='pending';});
  await page.locator('#paste-local').click();
  await page.waitForFunction(()=>typeof clipState.resolve==='function');
  await page.locator('#disconnect').click();
  await page.evaluate(()=>clipState.resolve('late-local-text-must-not-send'));
  assert.equal(await page.locator('#paste-text').inputValue(),'');assert.equal(await page.locator('#remote-text').inputValue(),'');
  assert.equal(await page.locator('#resolution').isDisabled(),true);
  assert.equal(await page.locator('#display').evaluate(e=>e.childElementCount),0);
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
  console.log(`RDP workspace: ${config.Native?'actual headless OS':'isolated mocked'} clipboard, explicit Unicode paste, refusal/fallback, resize and stale-read revocation passed`);
}catch(error){console.log('Workspace test state:',await page.locator('#status').textContent(),await page.locator('#notice').textContent(),errors);throw error;}
finally{await context.close();await browser.close();}
