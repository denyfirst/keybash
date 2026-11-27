export const ownedRemote = Boolean(document.body.dataset.ownedRemote);
async function json(path, method='GET', body, csrf='') {
  const response=await fetch(path,{method,headers:{'Content-Type':'application/json','X-Keybash-Request':'1','X-Keybash-CSRF':csrf},body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(15000)});
  if(response.status===503&&response.headers.get('X-Keybash-Capacity')==='full')throw Object.assign(new Error('capacity'),{code:'capacity'});
  if(response.status===429)throw Object.assign(new Error('rate'),{code:'rate'});
  if(!response.ok||response.headers.get('Content-Type')!=='application/json; charset=utf-8')throw new Error('refused');
  const reader=response.body.getReader();let length=0;const parts=[];
  while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>8192){await reader.cancel();throw new Error('response limit');}parts.push(value);}
  const bytes=new Uint8Array(length);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
export const identityChangedMessage='This server now shows a different certificate, so Keybash did not connect and sent it no password. Your administrator can see this and has to check it.';
// Why a session ended, as the gateway names it with one fixed word. Only these
// words are shown, each as its own text; anything else says nothing.
const endings={
 idle:'Keybash signed you out after 15 minutes without use, so this session ended. Sign in again to reconnect.',
 expired:'Your sign-in reached its 8-hour limit, so this session ended. Sign in again to reconnect.',
 'signed-out':'You were signed out of Keybash, so this session ended.',
 'access-changed':'This server, its account or your access to it changed, so this session ended.',
 credentials:'The server did not accept the account’s name or password. Your administrator can check it on the server’s page.',
 key:'The server did not accept the account’s key: its line is not on the server yet, or there is no such account there. Your administrator can check it on the server’s page.',
 account:'The server refused this account. It may be locked, disabled or expired, or not allowed to sign in remotely.',
 'taken-over':'The same account was opened from another connection, which took this session over.',
 'remote-ended':'The remote computer ended the session: it was signed out or disconnected, or reached its own time limit.',
 unreachable:'The server could not be reached, or it refused the connection.',
 'not-responding':'The remote side stopped responding, so this session ended.',
 refused:'Keybash ended this session because the server sent something it does not accept.',
 unrecorded:'Keybash could not write its activity record, so it did not go on with this session. Your administrator can see this.'
};
export function endingMessage(word){return typeof word==='string'&&Object.hasOwn(endings,word)?endings[word]:null;}
export function endedMessage(data){
 const match=typeof data==='string'&&data.length<=64?/^\{"type":"ended","reason":"([a-z-]{1,16})"\}$/.exec(data):null;
 return match?endingMessage(match[1]):null;
}
export function remoteErrorMessage(error){if(error?.code==='capacity')return 'The server is at its session limit. Close an open session, or try again in a moment.';if(error?.code==='rate')return 'Too many connection attempts. Wait a moment and try again.';return 'The connection was refused. If your session ended, sign in again.';}
// Full screen also asks the browser for the keyboard where it can (Chrome,
// Edge), so Esc, the Windows key and Alt+Tab reach the remote; the browser
// then says to hold Esc to leave. Elsewhere Esc leaves as usual.
export async function enterFullscreen(element){
 await element.requestFullscreen();
 try{await navigator.keyboard?.lock?.();}catch{}
}
export function watchFullscreen(button,changed=()=>{}){
 document.addEventListener('fullscreenchange',()=>{const on=Boolean(document.fullscreenElement);if(!on)navigator.keyboard?.unlock?.();const label=button.querySelector('.label')??button;label.textContent=on?'Exit full screen':'Full screen';button.title=label.textContent;changed(on);});
}
// What a terminal and a desktop page share around the session. In full screen
// the bar steps aside into a small tab at the top centre. Resting the pointer
// on the tab, or pressing it, brings the bar down from there; the rest of the
// top edge stays the remote's, so its title bars and corner buttons are never
// covered. The bar also comes back while it has focus or a menu is open.
// Short messages fade; once the session has ended its reason stays, with
// Connect again for an owned session.
// The bar keeps one line at any width. When its parts do not fit, the least
// needed step out first, each step keeping the ones before it: the wordmark
// and the size; the labels of full screen and Ctrl+Alt+Del, then of copy and
// paste, then every label; last the status word (its dot stays) and the kind.
// A tool keeps its name for screen readers and in its title. The connection's
// name keeps a few letters before anything steps out. The bar fits again
// whenever its width or its words change.
const handleRest=180,fitSteps=['fit-1','fit-2','fit-3','fit-4','fit-5'],nameRoom=80;
export function sessionChrome(){
 const session=document.querySelector('.session'),bar=session.querySelector('.bar'),handle=session.querySelector('.bar-handle'),notice=document.getElementById('notice'),reconnect=document.getElementById('reconnect');
 let hideTimer=0,restTimer=0,noticeTimer=0;
 const start=bar.querySelector('.bar-start'),tools=bar.querySelector('.tools'),name=bar.querySelector('.session-name');
 const over=el=>el.scrollWidth>el.clientWidth+1;
 const fits=()=>!over(bar)&&!over(start)&&!over(tools)&&(!name||name.clientWidth>=Math.min(name.scrollWidth,nameRoom));
 const fit=()=>{bar.classList.remove(...fitSteps);for(const step of fitSteps){if(fits())return;bar.classList.add(step);}};
 new ResizeObserver(fit).observe(session);
 new MutationObserver(fit).observe(bar,{childList:true,characterData:true,subtree:true,attributes:true,attributeFilter:['hidden']});
 document.fonts?.ready.then(fit);
 fit();
 const full=()=>session.classList.contains('full');
 const show=()=>{clearTimeout(hideTimer);clearTimeout(restTimer);session.classList.add('bar-shown');};
 const hide=(delay=900)=>{clearTimeout(hideTimer);hideTimer=setTimeout(()=>{if(full()&&!bar.matches(':hover, :focus-within')&&!session.querySelector('.menu:not([hidden])'))session.classList.remove('bar-shown');},delay);};
 session.addEventListener('pointermove',event=>{if(full()&&!bar.contains(event.target)&&event.target!==handle)hide();});
 handle.addEventListener('pointerenter',()=>{if(!full())return;clearTimeout(restTimer);restTimer=setTimeout(show,handleRest);});
 handle.addEventListener('pointerleave',()=>clearTimeout(restTimer));
 handle.addEventListener('click',show);
 bar.addEventListener('focusin',()=>{if(full())show();});
 bar.addEventListener('focusout',()=>{if(full())hide();});
 document.addEventListener('fullscreenchange',()=>{const on=document.fullscreenElement===session;session.classList.toggle('full',on);if(on){show();hide(2500);}else{clearTimeout(hideTimer);session.classList.remove('bar-shown');}});
 const ended=()=>document.body.classList.contains('ended');
 new MutationObserver(()=>{clearTimeout(noticeTimer);const said=notice.textContent!=='';notice.classList.toggle('shown',said);if(said&&!ended())noticeTimer=setTimeout(()=>notice.classList.remove('shown'),6000);}).observe(notice,{childList:true,characterData:true,subtree:true});
 reconnect.addEventListener('click',()=>location.reload());
 return {end(){if(ended())return;document.body.classList.add('ended');clearTimeout(noticeTimer);notice.classList.toggle('shown',notice.textContent!=='');reconnect.hidden=!ownedRemote;}};
}
// The server's own name, for the tab title, so several open sessions are told
// apart: as which account, on which server (ADR 0010). A missing or oversized
// list keeps the generic title.
export async function nameSession(kind){
 const account=document.body.dataset.account;
 try{const rows=await json('/api/access');const row=Array.isArray(rows)?rows.find(item=>item?.account===account):null;
  if(typeof row?.name!=='string'||!row.name||row.name.length>160||typeof row.username!=='string'||!row.username||row.username.length>128)return;
  document.title=`${row.name} · ${kind}`;document.getElementById('tab-name').textContent=`${row.username}@${row.name}`;
 }catch{}
}
// How this account's desktops open on a scaled screen, kept with the account
// on the server ("auto", "smooth" or "sharp"); the page stores nothing itself.
export async function savePicture(picture){
 const session=await json('/api/session');if(session.stage!=='ready'||!/^[A-Za-z0-9_-]{43}$/.test(session.csrf??''))throw new Error('session refused');
 const response=await fetch('/api/preferences/picture',{method:'POST',headers:{'Content-Type':'application/json','X-Keybash-Request':'1','X-Keybash-CSRF':session.csrf},body:JSON.stringify({picture}),credentials:'same-origin',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(15000)});
 if(response.status!==204)throw new Error('refused');
}
export async function remoteProof(){
 const account=document.body.dataset.account;if(!/^[a-f0-9]{32}$/.test(account??''))throw new Error('invalid account');
 const session=await json('/api/session');if(session.stage!=='ready'||!/^[A-Za-z0-9_-]{43}$/.test(session.csrf??''))throw new Error('session refused');
 const data=await json('/api/remote/open','POST',{account},session.csrf);if(!/^[A-Za-z0-9_-]{43}$/.test(data.lease??''))throw new Error('lease refused');
 return {csrf:session.csrf,lease:data.lease};
}
