import { inspectPaste, decodeOutput, MAX_INPUT } from './paste.mjs';
import { ownedRemote, remoteProof, remoteErrorMessage, offerNewSession, enterFullscreen, watchFullscreen, nameSession } from './remote.mjs';

const $ = id => document.getElementById(id);
const encoder = new TextEncoder();
const term = new globalThis.Terminal({ cols: 100, rows: 30, scrollback: 1500, fontSize: 13,
  fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace', allowProposedApi: false,
  linkHandler: { activate() {} }, theme: { background: '#0c0d0f', foreground: '#cdd1de', cursor: '#e5e7eb', selectionBackground: '#444753' } });
term.open($('terminal'));
term.parser.registerOscHandler(52, () => true); // Remote output never writes the local clipboard.
term.parser.registerOscHandler(8, () => true);  // No remotely supplied clickable hyperlinks.
term.write(ownedRemote ? '\x1b[2mConnecting…\x1b[0m\r\n' : '\x1b[2mKeybash terminal lab\r\nEnter the one-time sign-in code to open a session.\x1b[0m\r\n');
let socket = null, expected = 1, pendingPaste = '', connected = false;
let retired = false;
function retireTerminal() {
  if (retired) return;
  retired = true; term.dispose(); $('terminal').replaceChildren();
}
function notice(text) { $('notice').textContent = text; }
function clearPaste() { pendingPaste = ''; $('paste-preview').value = ''; }
function updateState(active) {
  connected = active;
  $('status').textContent = active ? 'Connected' : 'Not connected';
  $('status').classList.toggle('connected', active);
  for (const id of ['copy', 'paste', 'fullscreen', 'disconnect']) $(id).disabled = !active;
  if (!active && document.fullscreenElement) void document.exitFullscreen().catch(() => {});
}
function sendInput(data) {
  if (!connected || socket?.readyState !== WebSocket.OPEN) return;
  const bytes = encoder.encode(data);
  if (bytes.byteLength > MAX_INPUT || socket.bufferedAmount > 65536) { notice('Input limit exceeded.'); return; }
  socket.send(bytes);
}
term.onData(sendInput);
function requestPaste(text) {
  if (!connected) return;
  const inspection = inspectPaste(text);
  if (!inspection.allowed) { notice('A paste can be at most 32 KiB.'); return; }
  notice('');
  if (inspection.review) {
    pendingPaste = text;
    $('paste-preview').value = inspection.preview;
    $('paste-review').showModal();
    $('cancel-paste').focus();
  } else { term.paste(text); term.focus(); }
}
// Capture before xterm's textarea listener so Ctrl+V cannot bypass review.
$('terminal').addEventListener('paste', event => {
  event.preventDefault(); event.stopImmediatePropagation();
  requestPaste(event.clipboardData?.getData('text/plain') ?? '');
}, true);
$('confirm-paste').addEventListener('click', () => {
  const text = pendingPaste;
  $('paste-review').close(); clearPaste();
  if (connected) { term.paste(text); term.focus(); }
});
$('paste-review').addEventListener('close', () => {
  // A queued close event may arrive after a new review has opened.
  if (!$('paste-review').open) clearPaste();
});
function panel(text, copy) {
  if (!connected) return;
  $('clipboard-text').value = text;
  $('clipboard-text').readOnly = copy;
  $('panel-paste').hidden = copy;
  $('clipboard-help').textContent = copy ? 'Select the text and copy it with your browser.' : 'Paste the text here; after the review it goes to the terminal.';
  $('clipboard-panel').showModal(); $('clipboard-text').focus();
  if (copy) $('clipboard-text').select();
}
async function copySelection() {
  if (!connected) return;
  const selection = term.getSelection();
  if (!connected || !selection) return;
  if (!inspectPaste(selection).allowed) { notice('The selection is too large to copy.'); return; }
  try { await navigator.clipboard.writeText(selection); notice('Text copied.'); }
  catch { panel(selection, true); }
}
$('copy').addEventListener('click', copySelection);
$('paste').addEventListener('click', async () => {
  try { requestPaste(await navigator.clipboard.readText()); }
  catch { panel('', false); }
});
$('panel-paste').addEventListener('click', () => {
  const text = $('clipboard-text').value;
  $('clipboard-panel').close(); $('clipboard-text').value = ''; requestPaste(text);
});
$('clipboard-panel').addEventListener('close', () => {
  if (!$('clipboard-panel').open) $('clipboard-text').value = '';
});
term.attachCustomKeyEventHandler(event => {
  if (event.type === 'keydown' && ((event.ctrlKey && event.shiftKey) || event.metaKey) && event.key.toLowerCase() === 'c' && term.hasSelection()) {
    event.preventDefault(); void copySelection(); return false;
  }
  return true; // Plain Ctrl+C retains remote interrupt behavior.
});
function resize() {
  if (!connected || socket?.readyState !== WebSocket.OPEN) return;
  const columns = Math.max(20, Math.min(500, Math.floor(($('terminal').clientWidth - 46) / 7.83)));
  const rows = Math.max(5, Math.min(200, Math.floor(($('terminal').clientHeight - 46) / 15)));
  term.resize(columns, rows);
  $('size').textContent = `${columns} × ${rows}`;
  socket.send(JSON.stringify({ type: 'resize', columns, rows }));
}
let resizeTimer;
new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(resize, 120); }).observe($('terminal'));
function connect(proof=null) {
  expected = 1;
  socket = new WebSocket(`${location.origin.replace('https:', 'wss:')}${ownedRemote?'/api/remote/socket':'/lab/socket'}`);
  socket.binaryType = 'arraybuffer';
  const activate = () => { term.reset(); updateState(true); resize(); term.focus(); notice(''); };
  const timer=setTimeout(()=>socket.close(),15000);
  socket.onopen = () => {if(proof){socket.send(JSON.stringify(proof));proof=null;}else{clearTimeout(timer);activate();}};
  socket.onmessage = event => {
    if(ownedRemote&&!connected){if(event.data!=='{"type":"ready"}'){socket.close();return;}clearTimeout(timer);activate();return;}
    if (!connected || retired) return;
    try {
      // Each frame is acknowledged after xterm has parsed it; the server keeps
      // at most a small window unacknowledged, so long output stays bounded.
      const frame = decodeOutput(event.data, expected++);
      term.write(frame.bytes, () => {
        if (connected && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'ack', sequence: frame.sequence }));
      });
    } catch { socket.close(1008, 'invalid output'); }
  };
  socket.onclose = () => {
    clearTimeout(timer);
    updateState(false); clearPaste();
    retireTerminal();
    for (const id of ['paste-review', 'clipboard-panel']) if ($(id).open) $(id).close();
    $('clipboard-text').value = ''; notice('Session closed.');
  };
  socket.onerror = () => notice('The connection could not be opened.');
}
$('login').addEventListener('submit', async event => {
  event.preventDefault();
  const code = $('code').value;
  $('code').value = '';
  try {
    const response = await fetch('/lab/grant', { method: 'POST', headers: { 'Content-Type': 'text/plain', 'X-Keybash-Lab': '1' }, body: code, credentials: 'same-origin' });
    if (!response.ok) throw new Error('refused');
    $('login-panel').hidden = true; connect();
  } catch { notice('The sign-in code was not accepted.'); }
});
$('disconnect').addEventListener('click', async () => {
  updateState(false); clearPaste(); retireTerminal();
  socket?.close();
  if(!ownedRemote)try { await fetch('/lab/logout', { method: 'POST', headers: { 'X-Keybash-Lab': '1' }, credentials: 'same-origin', signal: AbortSignal.timeout(5000) }); } catch {}
});
watchFullscreen($('fullscreen'), () => { if (!retired) term.focus(); });
$('fullscreen').addEventListener('click', () => {
  if (document.fullscreenElement) void document.exitFullscreen().catch(() => {});
  else if (connected) void enterFullscreen(document.querySelector('.session')).catch(() => notice('The browser did not allow full screen.'));
});
window.addEventListener('pagehide',()=>{socket?.close();retireTerminal();clearPaste();});
window.addEventListener('pageshow',event=>{if(event.persisted)location.reload();});
if(ownedRemote){$('login-panel').hidden=true;offerNewSession();void nameSession('Keybash');void remoteProof().then(proof=>{if(!retired)connect(proof);}).catch(error=>notice(remoteErrorMessage(error)));}
