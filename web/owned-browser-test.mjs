import {chromium} from 'playwright';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHmac} from 'node:crypto';
import {checkBarFits} from './bar-fit-check.mjs';
const config=JSON.parse(readFileSync(0,'utf8'));assert.equal(new URL(config.Origin).hostname,'127.0.0.1');
// SSH: the desktop page has its own browser test (desktop-page-browser-test.mjs).
assert.equal(config.Mode,'ssh');
// WebGL off: these steps read the text the page draws, the GPU renderer's
// fallback; terminal-gpu-browser-test.mjs covers the GPU itself.
const browser=await chromium.launch({headless:true,args:['--disable-3d-apis'],...(process.env.KEYBASH_BROWSER_CHANNEL?{channel:process.env.KEYBASH_BROWSER_CHANNEL}:{})});
const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1400,height:1000}});const page=await context.newPage(),account=await context.newPage();const errors=[],outbound=[],urls=[];
context.on('page',p=>p.on('pageerror',e=>errors.push(e.name)));page.on('pageerror',e=>errors.push(e.name));account.on('pageerror',e=>errors.push(e.name));
// A blob: URL of the page's own origin is in memory (the pointer image), not the network.
context.on('request',r=>{if(!r.url().startsWith(config.Origin+'/')&&!r.url().startsWith('blob:'+config.Origin+'/'))outbound.push('external');if([config.Password,config.Secret,config.Code].some(s=>r.url().includes(s)||r.url().includes(encodeURIComponent(s))))urls.push('secret URL');});
// Every answer the API gives, searched for the account's password at the end.
const answers=[];account.on('response',r=>{if(r.url().startsWith(config.Origin+'/api/'))answers.push(r.text().catch(()=>''));});
function otp(seed,counter){const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of seed)bits+=alphabet.indexOf(c).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g).map(b=>parseInt(b,2)));const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(counter));const h=createHmac('sha1',key).update(b).digest();return ((h.readUInt32BE(h[19]&15)&0x7fffffff)%1000000).toString().padStart(6,'0');}
async function settle(){await account.waitForFunction(()=>!document.getElementById('logout')?.disabled);}
const serverName='Owned remote',username='synthetic-user';
let stage="bootstrap";
try{
 await account.goto(config.Origin+'/login');await account.locator('#setup-code').fill(config.Code);await account.locator('#setup-user').fill('alice');await account.locator('#setup-password').fill(config.Password);await account.locator('#bootstrap button').click();await account.waitForURL(config.Origin+'/');await settle();
 assert.equal((await account.request.get(config.Origin+'/api/access')).status(),403);
 await account.locator('#begin-enroll').click();await account.locator('#seed-panel').waitFor({state:'visible'});const seed=await account.locator('#seed').textContent();await settle();
 const counter=Math.floor(Date.now()/30000);await account.locator('#enrollment-code').fill(otp(seed,counter));await account.locator('#enrollment button').click();await account.locator('#recovery').waitFor({state:'visible'});await settle();const initialProof=(await account.locator('#recovery-codes').inputValue()).split('\n')[0];assert.match(initialProof,/^[A-Za-z0-9_-]{22}$/);await account.locator('#saved-recovery').click();await account.locator('#vault').waitFor({state:'visible'});await settle();
 // Nobody may use a server until an administrator puts them on one of its
 // accounts, the administrator included: until then nothing is offered.
 stage="your servers, empty";assert.equal(await account.locator('.rail-item[aria-current=page]').getAttribute('data-page'),'access');assert.deepEqual(await(await account.request.get(config.Origin+'/api/access')).json(),[],'a server was offered before anyone was put on it');
 await account.locator('#access .empty-state').waitFor();assert.equal(await account.locator('#access .server-card').count(),0);assert.equal(await account.locator('.rail-item[href="/keys"], #new-connection, #add-record').count(),0,'the personal path is back');
 stage="the server's page";await account.getByRole('link',{name:'Open Servers',exact:true}).click();await account.waitForURL(config.Origin+'/servers');await account.locator('#servers-panel').waitFor({state:'visible'});await settle();
 const row=account.locator('.server-row',{has:account.locator('.record-name',{hasText:new RegExp(`^${serverName}$`)})});await row.locator('.server-accounts').filter({hasText:/^No accounts yet/}).waitFor();
 await row.getByRole('link',{name:'Open',exact:true}).click();await account.waitForURL(config.Origin+'/servers/'+config.Target);await account.locator('#server-panel').waitFor({state:'visible'});await settle();
 assert.equal(await account.locator('h1').textContent(),serverName);assert.equal(await account.locator('#server-card .fingerprint').textContent(),config.Fingerprint);await account.locator('#accounts .empty-state').waitFor();
 // A key made here: only its line comes back, with restrict,pty, as the one command to run on the server.
 stage="a key made here";await account.locator('#add-account').click();await account.locator('#account-dialog').waitFor({state:'visible'});
 assert.equal(await account.locator('#account-people input[type=checkbox]').count(),1);assert.equal(await account.locator('#account-people input').isChecked(),true,'someone alone here was not ticked');assert.equal(await account.locator('#account-kind .segment[aria-pressed=true]').getAttribute('data-kind'),'ssh-key');assert(!(await account.locator('#account-secret').isVisible()));
 await account.locator('#account-user').fill('deploy');await account.locator('#account-submit').click();await account.locator('#key-dialog').waitFor({state:'visible'});await settle();
 assert.match(await account.locator('#key-command').textContent(),/^\[ "\$\(id -un\)" = 'deploy' \] \|\| \{ echo 'Sign in as deploy, then run this again\.' >&2; false; \} && mkdir -p ~\/\.ssh && chmod 700 ~\/\.ssh && printf '\\n%s\\n' 'restrict,pty ssh-ed25519 [A-Za-z0-9+/]+=* keybash' >> ~\/\.ssh\/authorized_keys && chmod 600 ~\/\.ssh\/authorized_keys$/);
 assert(!(await account.content()).includes('b3BlbnNzaC1rZXktdjE'),'the page holds a private key');// every OpenSSH private key body starts so
 await account.locator('#key-close').click();const keyCard=account.locator('.server-account',{has:account.locator('.server-account-name',{hasText:/^deploy$/})});assert.equal(await keyCard.locator('.server-account-how').textContent(),'Key kept by Keybash');assert.equal(await keyCard.locator('.account-state').textContent(),'Not set up yet');
 // Removing an account asks first; Cancel keeps it.
 await keyCard.getByRole('button',{name:'Remove',exact:true}).click();await account.locator('#delete-dialog').waitFor();assert.equal(await account.locator('#delete-title').textContent(),'Remove this account?');assert.equal(await account.locator('#delete-name').textContent(),`deploy on ${serverName}`);
 await account.locator('#cancel-delete').click();await account.locator('#delete-dialog').waitFor({state:'hidden'});await settle();assert.equal(await keyCard.count(),1,'cancel removed the account');
 await keyCard.getByRole('button',{name:'Remove',exact:true}).click();await account.locator('#confirm-delete').click();await account.locator('#notice').filter({hasText:`deploy on ${serverName} was removed.`}).waitFor();await settle();assert.equal(await keyCard.count(),0);
 // A password: typed once, emptied from the page, and never in any answer.
 stage="a password";await account.locator('#add-account').click();await account.locator('#account-dialog').waitFor({state:'visible'});await account.locator('#account-kind .segment[data-kind=password]').click();
 await account.locator('#account-user').fill(username);await account.locator('#account-secret').fill(config.Secret);assert.equal(await account.locator('#account-submit').textContent(),'Save the password');await account.locator('#account-submit').click();
 await account.locator('#notice').filter({hasText:`${username} on ${serverName} is ready`}).waitFor();await settle();assert.equal(await account.locator('#account-secret').inputValue(),'');
 const card=account.locator('.server-account',{has:account.locator('.server-account-name',{hasText:new RegExp(`^${username}$`)})});assert.equal(await card.locator('.server-account-how').textContent(),'Password kept by Keybash');assert.deepEqual(await card.locator('.chip-name').allTextContents(),['alice (you)']);
 assert(!(await account.content()).includes(config.Secret),'the page kept the password');
 stage="your servers";await account.locator('.rail-item[data-page=access]').click();await account.waitForURL(config.Origin+'/');await account.locator('#access .server-card').waitFor();await settle();
 const access=account.locator('#access .server-card');assert.equal(await access.count(),1);assert.equal(await access.locator('.server-name').textContent(),serverName);assert.equal(await access.locator('.server-screen .who').textContent(),username);assert.equal(await access.locator('.trust-state').textContent(),'Ready');
 if(config.Control){
  // The server's key changes and an administrator accepts it: the card stays
  // ready, with the new identity, for everyone on its accounts.
  stage='changed server identity';const changed=await account.request.post(config.Origin+'/__fixture/trust-change',{headers:{'X-Fixture-Control':config.Control}});assert.equal(changed.status(),204);
  await account.goto(config.Origin+'/servers/'+config.Target);await account.locator('#server-panel').waitFor({state:'visible'});await settle();assert.equal(await account.locator('#server-card .fingerprint').textContent(),config.UpdatedFingerprint);
  await account.goto(config.Origin+'/');await account.locator('#access .server-card[data-trust=verified]').waitFor();await settle();
 }
 stage="open remote";const connectLink=account.getByRole('link',{name:'Connect',exact:true});const href=await connectLink.getAttribute('href');assert.match(href,/^\/remote\/ssh\/[a-f0-9]{32}$/);assert.equal(await connectLink.getAttribute('target'),'_blank','connect did not open its own tab');assert.equal(await connectLink.getAttribute('rel'),'noopener');await page.goto(config.Origin+href);
 stage="session chrome";await page.waitForFunction(name=>document.title===`${name} · Keybash`,serverName);assert.equal(await page.locator('#tab-name').textContent(),`${username}@${serverName}`);
 // The session tab is the session alone: full width, nothing that leads away from it. Another session comes from Connect again, never from the session page.
 assert.equal(await page.locator('a[href="/"], #rail, #rail-toggle').count(),0,'the session page leads away from its session');assert(await page.locator('.session').evaluate(el=>el.clientWidth>=innerWidth*0.9),'the session is not full width');
 assert.equal(await page.locator('#new-session').count(),0,'the session page offers a second session');
 stage="remote ready";await page.locator('#status').filter({hasText:/^Connected$/}).waitFor();stage="the bar at every width";await checkBarFits(page,'SSH','Not connected');stage="SSH input";await page.locator('.xterm-helper-textarea').focus();await page.keyboard.type('owned-ssh-input');await page.waitForFunction(()=>document.querySelector('.xterm-rows')?.textContent.includes('owned-ssh-input'));stage="SSH full screen";await page.locator('#fullscreen').click();await page.waitForFunction(()=>document.fullscreenElement?.classList.contains('session'));assert.equal(await page.locator('#fullscreen').textContent(),'Exit full screen');stage="SSH full-screen bar";const barShown=()=>page.evaluate(()=>document.querySelector('.session').classList.contains('bar-shown'));const [fullWidth,fullHeight]=await page.evaluate(()=>[innerWidth,innerHeight]);await page.mouse.move(fullWidth/2,fullHeight/2);await page.waitForFunction(()=>!document.querySelector('.session').classList.contains('bar-shown'),null,{timeout:6000});await page.mouse.move(fullWidth-10,1);await page.mouse.move(fullWidth-6,0);await page.waitForTimeout(600);assert.equal(await barShown(),false,'the top edge opened the bar');await page.locator('.bar-handle').hover();await page.waitForFunction(()=>document.querySelector('.session').classList.contains('bar-shown'),null,{timeout:3000});await page.waitForTimeout(300);assert.equal(await page.evaluate(()=>{const bar=document.querySelector('.bar');return[[4,4],[innerWidth-4,4]].some(([x,y])=>bar.contains(document.elementFromPoint(x,y)));}),false,'the open bar covers a top corner');await page.locator('#fullscreen').click();await page.waitForFunction(()=>!document.fullscreenElement);assert.equal(await page.locator('#fullscreen').textContent(),'Full screen');
 if(config.CapacityTest){
  stage='capacity refusal';const blocked=await context.newPage();await blocked.goto(config.Origin+href);await blocked.locator('#notice').filter({hasText:/.+/}).waitFor();assert.ok((await blocked.locator('#notice').textContent()).includes('The server is at its session limit.'),'capacity busy message missing');assert.equal(await blocked.locator('#status').textContent(),'Not connected');
  stage='existing session survives busy';await page.locator('.xterm-helper-textarea').focus();await page.keyboard.type('capacity-existing-survives');await page.waitForFunction(()=>document.querySelector('.xterm-rows')?.textContent.includes('capacity-existing-survives'));await blocked.close();
 }
 // Taking yourself off the account ends the open session, and its page says why in fixed words.
 stage='taken off';await account.bringToFront();await account.goto(config.Origin+'/servers/'+config.Target);await account.locator('#server-panel').waitFor({state:'visible'});await settle();
 await card.getByRole('button',{name:'Change who',exact:true}).click();await account.locator('#people-dialog').waitFor({state:'visible'});await account.locator('#people-choices input').uncheck();await account.locator('#people-form button[type=submit]').click();
 await account.locator('#notice').filter({hasText:`Saved who signs in as ${username} on ${serverName}.`}).waitFor();await settle();assert.deepEqual(await card.locator('.chip-name').allTextContents(),[]);
 await page.locator('#notice').filter({hasText:/^This server, its account or your access to it changed, so this session ended\.$/}).waitFor();
 assert.equal((await account.request.post(config.Origin+'/api/remote/open',{headers:{Origin:config.Origin,'X-Keybash-Request':'1','X-Keybash-CSRF':(await(await account.request.get(config.Origin+'/api/session')).json()).csrf},data:{account:href.slice(-32)}})).status(),401,'someone taken off still opened the account');
 assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
 await account.locator('#logout').click();await account.waitForURL(config.Origin+'/login');await page.waitForFunction(()=>document.getElementById('terminal').childElementCount===0);
 for(const answer of await Promise.all(answers))assert(!answer.includes(config.Secret),'an answer carried the account\'s password');
 assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);assert.deepEqual(urls,[]);console.log('Owned remote browser: bootstrap/MFA/server account/key line/password/your servers/input/taken off/logout passed for '+config.Mode);
}catch(error){console.log('Owned browser stage:',stage,error.code==='ERR_ASSERTION'?error.message:error.name);if(process.env.KEYBASH_OWNED_SCREENSHOT)await account.screenshot({path:process.env.KEYBASH_OWNED_SCREENSHOT});throw new Error('owned remote browser checks failed');}finally{await context.close();await browser.close();}
