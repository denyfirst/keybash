import { Guacamole } from './vendor/guacamole.mjs';
import { ownedRemote, remoteProof, remoteErrorMessage } from './remote.mjs';

const $ = id => document.getElementById(id);
let client, keyboard, socket, pendingMouse, mouseFrame, stopped = true, retired = false;
const encoder = new TextEncoder();
function end() {
  if (stopped) return;
  stopped = true;
  cancelAnimationFrame(mouseFrame); pendingMouse = null;
  keyboard?.reset(); client?.disconnect(); socket?.close();
  $('display').replaceChildren();
  for (const id of ['disconnect','special','fullscreen']) $(id).disabled = true;
  $('status').textContent = 'Sessiya bitdi';
}
function fit() {
  if (!client || stopped) return;
  const width = $('desktop').clientWidth;
  const height = document.fullscreenElement ? window.innerHeight : Math.min(window.innerHeight * 0.72, 768);
  client.getDisplay().scale(Math.min(1, width/1024, height/768));
}
function begin(proof=null) {
  const tunnel = new Guacamole.Tunnel();
  const parser = new Guacamole.Parser();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let sequence = 0, bytes = 0;
  parser.oninstruction = (op, args) => { if (!stopped) tunnel.oninstruction?.(op,args); };
  tunnel.connect = () => {
    socket = new WebSocket(`${location.origin.replace('https:', 'wss:')}${ownedRemote?'/api/remote/socket':'/lab/socket'}`);
    socket.binaryType = 'arraybuffer';
    let ready=!ownedRemote;const timer=setTimeout(end,15000);
    socket.onopen = () => { if (!stopped) {if(proof){socket.send(JSON.stringify(proof));proof=null;}else{clearTimeout(timer);tunnel.setState(Guacamole.Tunnel.State.OPEN);}} };
    socket.addEventListener('close',()=>clearTimeout(timer));
    socket.onerror = end; socket.onclose = end;
    socket.onmessage = event => {
      if(!ready){if(event.data!=='{"type":"ready"}'){end();return;}ready=true;clearTimeout(timer);if(!stopped)tunnel.setState(Guacamole.Tunnel.State.OPEN);return;}
      if (stopped) return;
      try {
        if (!(event.data instanceof ArrayBuffer) || event.data.byteLength < 5 || event.data.byteLength > 8196) throw new Error('frame');
        const number = new DataView(event.data).getUint32(0);
        bytes += event.data.byteLength - 4;
        if (number !== ++sequence || bytes > 8*1024*1024) throw new Error('quota');
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
    if (!['mouse','key','sync','ack','nop'].includes(values[0])) { end(); return; }
    const data = values.map(String).map(value => `${Array.from(value).length}.${value}`).join(',')+';';
    const encoded = encoder.encode(data);
    if (encoded.length > 1024 || socket.bufferedAmount > 32768) { end(); return; }
    socket.send(encoded);
  };
  client = new Guacamole.Client(tunnel);
  const display = client.getDisplay();
  $('display').replaceChildren(display.getElement());
  keyboard = new Guacamole.Keyboard($('desktop'));
  keyboard.onkeydown = key => {
    if (stopped || document.activeElement !== $('desktop')) return true;
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
    state.x = Math.max(0, Math.min(1023*display.getScale(),state.x));
    state.y = Math.max(0, Math.min(767*display.getScale(),state.y));
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
      $('status').textContent = 'Sessiya açıldı'; fit(); $('desktop').focus();
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
    if (!result.ok) { $('notice').textContent='Giriş rədd edildi.'; return; }
    $('login-panel').hidden=true; stopped=false; begin();
  } catch { $('notice').textContent='Sessiya açıla bilmədi.'; end(); }
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
  if (!stopped) void $('desktop').requestFullscreen().catch(()=>{});
});
window.addEventListener('resize', fit);
document.addEventListener('fullscreenchange', fit);
window.addEventListener('pagehide', ()=>{retired=true;end();});
window.addEventListener('pageshow',event=>{if(event.persisted)location.reload();});
if(ownedRemote){$('login-panel').hidden=true;void remoteProof().then(proof=>{if(!retired){stopped=false;begin(proof);}}).catch(error=>{$('notice').textContent=remoteErrorMessage(error);});}
