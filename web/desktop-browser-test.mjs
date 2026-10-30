import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const config=JSON.parse(readFileSync(0,'utf8'));
const url=new URL(config.Origin);
assert.equal(url.protocol,'https:'); assert.equal(url.hostname,'127.0.0.1');
assert.match(config.Code,/^[A-Za-z0-9_-]{43}$/);
const browser=await chromium.launch({headless:true,...(process.env.KEYBASH_BROWSER_CHANNEL?{channel:process.env.KEYBASH_BROWSER_CHANNEL}:{})});
const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1400,height:1000}});
const page=await context.newPage();
const errors=[],outbound=[];
page.on('pageerror',error=>errors.push(error.name+': '+error.message));
page.on('request',r=>{if(!r.url().startsWith(config.Origin+'/'))outbound.push('external request')});
await context.addInitScript(()=>{
  globalThis.clipboardCalls=0;
  Object.defineProperty(navigator,'clipboard',{value:{readText(){clipboardCalls++;throw new Error('disabled')},writeText(){clipboardCalls++;throw new Error('disabled')}}});
});
try {
  await page.goto(config.Origin);
  await page.locator('#code').fill(config.Code);
  await page.getByRole('button',{name:'Open session',exact:true}).click();
  await page.locator('#status').filter({hasText:'Connected'}).waitFor({timeout:10000});
  assert.equal(await page.locator('#code').inputValue(),'');
  await page.waitForFunction(()=>{
    const canvases=[...document.querySelectorAll('#display canvas')];
    return canvases.some(canvas=>canvas.width>=1024&&canvas.height>=768&&canvas.getContext('2d').getImageData(500,500,1,1).data[0]>=150);
  },undefined,{timeout:10000});
  await page.locator('#desktop').focus();
  await page.keyboard.press('a'); await page.keyboard.press('ArrowLeft');
  await page.keyboard.down('Shift');
  await page.locator('#special').focus();
  await page.keyboard.up('Shift');
  await page.getByRole('button',{name:'Ctrl+Alt+Del',exact:true}).click();
  const box=await page.locator('#display').boundingBox(); assert(box);
  await page.mouse.move(box.x+120,box.y+120,{steps:3});
  await page.mouse.down(); await page.mouse.up();
  if(config.Native) await page.waitForFunction(()=>{
    return [...document.querySelectorAll('#display canvas')].some(canvas=>{
      if(canvas.width<1024||canvas.height<768) return false;
      const data=canvas.getContext('2d').getImageData(130,120,40,40).data;
      for(let i=0;i<data.length;i+=4) if(data[i+3]&&Math.abs(data[i]-160)>15) return true;
      return false;
    });
  },undefined,{timeout:10000});
  await page.waitForTimeout(150);
  const cookies=await context.cookies();
  assert(cookies.some(c=>c.name==='__Host-keybash-lab'&&c.secure&&c.httpOnly&&c.sameSite==='Strict'));
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length+clipboardCalls),0);
  if(config.Screenshot) await page.screenshot({path:config.Screenshot});
  await page.getByRole('button',{name:'Disconnect',exact:true}).click();
  await page.waitForFunction(()=>document.getElementById('display').childElementCount===0);
  await page.keyboard.press('b');
  assert.equal(await page.locator('#special').isDisabled(),true);
  assert.deepEqual(errors,[]); assert.deepEqual(outbound,[]);
  console.log('Browser RDP: validated desktop pixels, focused input, local assets and logout passed');
} catch (error) {
  console.log('Desktop test state:',await page.locator('#status').textContent(),errors);
  if(config.Screenshot) await page.screenshot({path:config.Screenshot});
  throw error;
} finally { await context.close(); await browser.close(); }
