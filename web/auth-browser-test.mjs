import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const config=JSON.parse(readFileSync(0,'utf8'));
const url=new URL(config.Origin);
assert.equal(url.protocol,'https:'); assert.equal(url.hostname,'127.0.0.1');
const browser=await chromium.launch({headless:true,...(process.env.KEYBASH_BROWSER_CHANNEL?{channel:process.env.KEYBASH_BROWSER_CHANNEL}:{})});
const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1200,height:1000}});
const page=await context.newPage();
const errors=[], external=[], secretURL=[];
page.on('pageerror',error=>errors.push(error.name));
page.on('request',r=>{
  if(!r.url().startsWith(config.Origin+'/')) external.push('external');
  if([config.Password,config.Replacement].some(secret=>r.url().includes(secret)||r.url().includes(encodeURIComponent(secret)))) secretURL.push('secret');
});
async function login(password) {
  await page.locator('#username').fill(config.Username);
  await page.locator('#password').fill(password);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
}
try {
  await page.goto(config.Origin+'/');
  await page.waitForURL(config.Origin+'/login');
  if(config.Screenshot) await page.screenshot({path:config.Screenshot});
  await login('Incorrect synthetic password');
  await page.locator('#notice').filter({hasText:'not accepted'}).waitFor();
  assert.equal(await page.locator('#password').inputValue(),'');
  assert.equal((await context.cookies()).length,0);
  await login(config.Password);
  await Promise.race([page.waitForURL(config.Origin+'/'),page.waitForFunction(()=>document.getElementById('notice')?.textContent)]);
  assert.equal(page.url(),config.Origin+'/','valid password UI login refused');
  await page.locator('#account').filter({hasText:config.Username}).waitFor();
  const cookie=(await context.cookies()).find(c=>c.name==='__Host-keybash-session');
  assert(cookie?.secure&&cookie.httpOnly&&cookie.sameSite==='Strict');
  assert(!await page.evaluate(()=>document.cookie.includes('__Host-keybash-session')));
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  // An uncertain sign-out must leave a retry action and must not claim success.
  await page.route(config.Origin+'/api/session',route=>route.request().method()==='DELETE'?route.fulfill({status:503,body:'synthetic refusal'}):route.continue());
  await page.getByRole('button',{name:'Sign out',exact:true}).click();
  await Promise.race([page.locator('#notice').filter({hasText:'Sign-out was not confirmed'}).waitFor(),page.waitForURL(config.Origin+'/login')]);
  assert.equal(page.url(),config.Origin+'/','uncertain logout claimed success');
  assert.equal(page.url(),config.Origin+'/');
  assert.equal(await page.locator('#logout').isEnabled(),true);
  await page.unroute(config.Origin+'/api/session');
  await page.locator('#current').fill(config.Password);
  await page.locator('#replacement').fill(config.Replacement);
  await page.locator('#confirm').fill(config.Replacement);
  await page.getByRole('button',{name:'Change password',exact:true}).click();
  await page.waitForURL(config.Origin+'/login');
  assert.equal((await context.cookies()).filter(c=>c.name==='__Host-keybash-session').length,0);
  await login(config.Password);
  await page.locator('#notice').filter({hasText:'not accepted'}).waitFor();
  await login(config.Replacement);
  await page.waitForURL(config.Origin+'/');
  await page.locator('#logout').waitFor({state:'visible'});
  await page.waitForFunction(()=>!document.getElementById('logout').disabled);
  // A malformed account reply cannot enable operations or reflect server text.
  await page.route(config.Origin+'/api/session',route=>route.request().method()==='GET'?route.fulfill({status:200,headers:{'Content-Type':'application/json; charset=utf-8'},body:'{"username":"<img src=x>","csrf":"bad"}'}):route.continue());
  await page.reload();
  await page.locator('#notice').filter({hasText:'The session could not be checked'}).waitFor();
  assert.equal(await page.locator('#logout').isDisabled(),true);
  assert.equal(await page.locator('img').count(),0);
  await page.unroute(config.Origin+'/api/session');
  await page.reload();
  await page.waitForFunction(()=>!document.getElementById('logout').disabled);
  await page.getByRole('button',{name:'Sign out',exact:true}).click();
  await page.waitForURL(config.Origin+'/login');
  assert.equal((await page.request.get(config.Origin+'/api/session')).status(),401);
  await page.goto(config.Origin+'/');
  await page.waitForURL(config.Origin+'/login');
  assert.equal(await page.locator('#password').inputValue(),'');
  assert.deepEqual(errors,[]); assert.deepEqual(external,[]); assert.deepEqual(secretURL,[]);
  console.log('Browser identity: password login/change/logout, cookie policy, protected page and failure handling passed');
} catch(error) {
  // Failed Playwright fill call logs can include the supplied fixture password.
  console.log(error.code==='ERR_ASSERTION'?error.message:error.name);
  throw new Error('browser identity checks failed');
} finally { await context.close(); await browser.close(); }
