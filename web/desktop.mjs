import { Guacamole } from './vendor/guacamole.mjs';
import { workspaceControls } from './desktop-workspace.mjs';
import { ownedRemote, remoteProof, remoteErrorMessage, identityChangedMessage, endedMessage, enterFullscreen, watchFullscreen, nameSession, sessionChrome } from './remote.mjs';

const $ = id => document.getElementById(id);
let client, keyboard, socket, pendingMouse, mouseFrame, stopped = true, retired = false;
const encoder = new TextEncoder();
let sendWorkspace;
const chrome = sessionChrome();
const controls = workspaceControls({ $,
  live: () => !stopped, client: () => client,
  send: (...values) => sendWorkspace?.(...values), resetKeyboard: () => keyboard?.reset()
});
function end() {
  controls.end();
  if (stopped) return;
  stopped = true;
  sendWorkspace = null;
  cancelAnimationFrame(mouseFrame); pendingMouse = null;
  keyboard?.reset(); client?.disconnect(); socket?.close();
  $('display').replaceChildren();
  for (const id of ['disconnect','special','fullscreen']) $(id).disabled = true;
  if (document.fullscreenElement) void document.exitFullscreen().catch(()=>{});
  $('status').textContent = 'Session ended'; $('status').classList.remove('connected');
  if (!$('notice').textContent) $('notice').textContent = 'Session ended.';
  chrome.end();
}
// The picture fits the space the desktop has, whatever the window or screen.
function fit() {
  if (!client || stopped) return;
  const width = $('desktop').clientWidth, height = $('desktop').clientHeight;
  const display = client.getDisplay();
  // At most 1/scale: a scaled screen's desktop has scale remote pixels per CSS pixel.
  display.scale(Math.min(1/controls.scale(), width/Math.max(1,display.getWidth()), height/Math.max(1,display.getHeight())));
  controls.resize();
}
function begin(proof=null) {
  const tunnel = new Guacamole.Tunnel();
  const parser = new Guacamole.Parser();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let sequence = 0;
  parser.oninstruction = (op, args) => {
    if (stopped) return;
    if (op === 'keybash') { if (!controls.feature(args)) end(); return; }
    if (op === 'keybash-clipboard') { if (!controls.receive(args)) end(); return; }
    if (op === 'keybash-clipboard-large') { if (!controls.tooLarge(args)) end(); return; }
    tunnel.oninstruction?.(op,args);
  };
  tunnel.connect = () => {
    socket = new WebSocket(`${location.origin.replace('https:', 'wss:')}${ownedRemote?'/api/remote/socket':'/lab/socket'}`);
    socket.binaryType = 'arraybuffer';
    let ready=!ownedRemote;const timer=setTimeout(end,15000);
    socket.onopen = () => {
      if (stopped) return;
      // The desktop opens at the space it has, not at a fixed 1024 by 768.
      if (proof) { socket.send(JSON.stringify({ ...proof, size: controls.startSize() })); proof = null; }
      else { clearTimeout(timer); tunnel.setState(Guacamole.Tunnel.State.OPEN); }
    };
    socket.addEventListener('close',()=>clearTimeout(timer));
    socket.onerror = end; socket.onclose = end;
    socket.onmessage = event => {
      if(!ready){if(event.data==='{"type":"identity-changed"}'){$('notice').textContent=identityChangedMessage;end();return;}if(event.data!=='{"type":"ready"}'){end();return;}ready=true;clearTimeout(timer);if(!stopped)tunnel.setState(Guacamole.Tunnel.State.OPEN);return;}
      if (stopped) return;
      if (typeof event.data === 'string') { const why = endedMessage(event.data); if (why) $('notice').textContent = why; end(); return; }
      try {
        if (!(event.data instanceof ArrayBuffer) || event.data.byteLength < 5 || event.data.byteLength > 8196) throw new Error('frame');
        const number = new DataView(event.data).getUint32(0);
        if (number !== ++sequence) throw new Error('sequence');
        parser.receive(decoder.decode(new Uint8Array(event.data,4), {stream:true}));
        // Chunk credit bounds the tunnel queue. Guacamole's sync response
        // separately waits for its display tasks/images to finish rendering.
        if (!stopped) socket.send(JSON.stringify({type:'ack',sequence:number}));
      } catch { end(); }
    };
  };
  tunnel.disconnect = () => { tunnel.setState(Guacamole.Tunnel.State.CLOSED); socket?.close(); };
  tunnel.sendMessage = (...values) => {
    if (stopped || socket?.readyState !== WebSocket.OPEN) return;
    if (values[0] === 'disconnect') { socket.close(); return; }
    if (!['mouse','key','sync','ack','nop'].includes(values[0]) && !(controls.enabled && ['clipboard','blob','end','size'].includes(values[0]))) { end(); return; }
    const data = values.map(String).map(value => `${Array.from(value).length}.${value}`).join(',')+';';
    const encoded = encoder.encode(data);
    if (encoded.length > (controls.enabled ? 8192 : 1024) || socket.bufferedAmount > 65536) { end(); return; }
    socket.send(encoded);
  };
  sendWorkspace = (...values) => tunnel.sendMessage(...values);
  client = new Guacamole.Client(tunnel);
  const display = client.getDisplay();
  display.onresize = (width,height) => { $('size').textContent = `${width} × ${height}`; fit(); };
  $('display').replaceChildren(display.getElement());
  keyboard = new Guacamole.Keyboard($('desktop'));
  keyboard.onkeydown = key => {
    if (stopped || document.activeElement !== $('desktop')) return true;
    const handled = controls.key(key, keyboard.modifiers);
    if (handled !== undefined) return handled;
    client.sendKeyEvent(1,key); return false;
  };
  keyboard.onkeyup = key => { if (!stopped) client.sendKeyEvent(0,key); };
  $('desktop').onblur = () => { if (!stopped) keyboard.reset(); };
  const mouse = new Guacamole.Mouse(display.getElement());
  mouse.onEach(['mousedown','mouseup'], event => {
    if (!stopped) { $('desktop').focus(); client.sendMouseState(event.state,true); }
  });
  mouse.on('mousemove', event => {
    if (stopped) return;
    const state = event.state;
    state.x = Math.max(0, Math.min((display.getWidth()-1)*display.getScale(),state.x));
    state.y = Math.max(0, Math.min((display.getHeight()-1)*display.getScale(),state.y));
    pendingMouse = state;
    if (!mouseFrame) mouseFrame = requestAnimationFrame(() => {
      mouseFrame = 0;
      if (!stopped && pendingMouse) client.sendMouseState(pendingMouse,true);
      pendingMouse = null;
    });
  });
  client.onerror = end;
  client.onstatechange = state => {
    if (state === Guacamole.Client.State.CONNECTED && !stopped) {
      $('status').textContent = 'Connected'; $('status').classList.add('connected'); fit(); $('desktop').focus();
      for (const id of ['disconnect','special','fullscreen']) $(id).disabled = false;
    }
  };
  client.connect('');
}
$('login').addEventListener('submit', async event => {
  event.preventDefault();
  const code = $('code').value; $('code').value = '';
  if (!stopped || code.length !== 43) return;
  try {
    const result = await fetch('/lab/grant',{method:'POST',headers:{'Content-Type':'text/plain','X-Keybash-Lab':'1'},body:code});
    if (!result.ok) { $('notice').textContent='Sign-in refused.'; return; }
    $('login-panel').hidden=true; stopped=false; begin();
  } catch { $('notice').textContent='The session could not be opened.'; end(); }
});
$('disconnect').addEventListener('click', () => {
  end();
  if(!ownedRemote)void fetch('/lab/logout',{method:'POST',headers:{'X-Keybash-Lab':'1'}}).catch(()=>{});
});
$('special').addEventListener('click', () => {
  if (stopped) return;
  for (const key of [0xffe3,0xffe9,0xffff]) client.sendKeyEvent(1,key);
  for (const key of [0xffff,0xffe9,0xffe3]) client.sendKeyEvent(0,key);
  $('desktop').focus();
});
$('fullscreen').addEventListener('click', () => {
  if (document.fullscreenElement) void document.exitFullscreen().catch(()=>{});
  else if (!stopped) void enterFullscreen(document.querySelector('.session')).then(() => $('desktop').focus()).catch(()=>{});
});
watchFullscreen($('fullscreen'));
new ResizeObserver(fit).observe($('desktop'));
window.addEventListener('pagehide', ()=>{retired=true;end();});
window.addEventListener('pageshow',event=>{if(event.persisted)location.reload();});
if(ownedRemote){$('login-panel').hidden=true;void nameSession('Keybash');void remoteProof().then(proof=>{if(!retired){stopped=false;begin(proof);}}).catch(error=>{$('notice').textContent=remoteErrorMessage(error);chrome.end();});}
