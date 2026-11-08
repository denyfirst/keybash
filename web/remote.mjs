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
 'access-changed':'This server, this connection or your access to it changed, so this session ended.',
 credentials:'The server did not accept the user name or password saved for this connection.',
 account:'The server refused this account. It may be locked, disabled or expired, or not allowed to sign in remotely.',
 'taken-over':'The same account was opened from another connection, which took this session over.',
 'remote-ended':'The remote computer ended the session: it was signed out or disconnected, or reached its own time limit.',
 unreachable:'The server could not be reached, or it refused the connection.',
 'not-responding':'The remote side stopped responding, so this session ended.',
 refused:'Keybash ended this session because the server sent something it does not accept.'
};
export function endedMessage(data){
 const match=typeof data==='string'&&data.length<=64?/^\{"type":"ended","reason":"([a-z-]{1,16})"\}$/.exec(data):null;
 return match&&Object.hasOwn(endings,match[1])?endings[match[1]]:null;
}
export function remoteErrorMessage(error){if(error?.code==='capacity')return 'The server is at its session limit. Close an open session, or try again in a moment.';if(error?.code==='rate')return 'Too many connection attempts. Wait a moment and try again.';return 'The connection was refused. If your session ended, sign in again.';}
// Another session to the same server opens in its own tab, as Connect does,
// so each tab stays one session that closing it ends. SSH only: a second RDP
// sign-in as the same user takes over the first desktop instead.
export function offerNewSession(){
 const record=document.body.dataset.connection,link=document.getElementById('new-session');
 if(!link||document.body.dataset.ownedRemote!=='ssh'||!/^[a-f0-9]{32}$/.test(record??''))return;
 link.href=`/remote/ssh/${record}`;link.hidden=false;
}
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
// the bar steps aside and comes back at the top edge, from its handle, or
// while it has focus or a menu is open. Short messages fade; once the session
// has ended its reason stays, with Connect again for an owned session.
export function sessionChrome(){
 const session=document.querySelector('.session'),bar=session.querySelector('.bar'),notice=document.getElementById('notice'),reconnect=document.getElementById('reconnect');
 let hideTimer=0,noticeTimer=0;
 const full=()=>session.classList.contains('full');
 const show=()=>{clearTimeout(hideTimer);session.classList.add('bar-shown');};
 const hide=(delay=900)=>{clearTimeout(hideTimer);hideTimer=setTimeout(()=>{if(full()&&!bar.matches(':hover, :focus-within')&&!session.querySelector('.menu:not([hidden])'))session.classList.remove('bar-shown');},delay);};
 session.addEventListener('pointermove',event=>{if(!full())return;if(event.clientY<=6)show();else if(!bar.contains(event.target))hide();});
 session.querySelector('.bar-handle').addEventListener('click',show);
 bar.addEventListener('focusin',()=>{if(full())show();});
 bar.addEventListener('focusout',()=>{if(full())hide();});
 document.addEventListener('fullscreenchange',()=>{const on=document.fullscreenElement===session;session.classList.toggle('full',on);if(on){show();hide(2500);}else{clearTimeout(hideTimer);session.classList.remove('bar-shown');}});
 const ended=()=>document.body.classList.contains('ended');
 new MutationObserver(()=>{clearTimeout(noticeTimer);const said=notice.textContent!=='';notice.classList.toggle('shown',said);if(said&&!ended())noticeTimer=setTimeout(()=>notice.classList.remove('shown'),6000);}).observe(notice,{childList:true,characterData:true,subtree:true});
 reconnect.addEventListener('click',()=>location.reload());
 return {end(){if(ended())return;document.body.classList.add('ended');clearTimeout(noticeTimer);notice.classList.toggle('shown',notice.textContent!=='');reconnect.hidden=!ownedRemote;}};
}
// The connection's own name, for the tab title, so several open sessions are
// told apart. A missing or oversized list keeps the generic title.
export async function nameSession(kind){
 const record=document.body.dataset.connection;
 try{const rows=await json('/api/connections');const row=Array.isArray(rows)?rows.find(item=>item?.id===record):null;
  if(typeof row?.name!=='string'||!row.name||row.name.length>160)return;
  document.title=`${row.name} · ${kind}`;document.getElementById('tab-name').textContent=row.name;
 }catch{}
}
export async function remoteProof(){
 const record=document.body.dataset.connection;if(!/^[a-f0-9]{32}$/.test(record??''))throw new Error('invalid connection');
 const session=await json('/api/session');if(session.stage!=='ready'||!/^[A-Za-z0-9_-]{43}$/.test(session.csrf??''))throw new Error('session refused');
 const data=await json('/api/remote/open','POST',{connection:record},session.csrf);if(!/^[A-Za-z0-9_-]{43}$/.test(data.lease??''))throw new Error('lease refused');
 return {csrf:session.csrf,lease:data.lease};
}
