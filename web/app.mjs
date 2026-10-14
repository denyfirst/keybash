import { inspectPaste, decodeOutput, MAX_INPUT } from './paste.mjs';

const $ = id => document.getElementById(id);
const encoder = new TextEncoder();
const term = new globalThis.Terminal({ cols: 100, rows: 30, scrollback: 1500, fontSize: 13,
  fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace', allowProposedApi: false,
  linkHandler: { activate() {} }, theme: { background: '#0c0d0f', foreground: '#cdd1de', cursor: '#e5e7eb', selectionBackground: '#444753' } });
term.open($('terminal'));
term.parser.registerOscHandler(52, () => true); // Remote output never writes the local clipboard.
term.parser.registerOscHandler(8, () => true);  // No remotely supplied clickable hyperlinks.
term.write('\x1b[2mKeybash terminal lab\r\nSessiyanı açmaq üçün birdəfəlik giriş kodunu daxil et.\x1b[0m\r\n');
let socket = null, expected = 1, pendingPaste = '', connected = false;
let retired = false;
let outputBytes=0;
function retireTerminal() {
  if (retired) return;
  retired = true; term.dispose(); $('terminal').replaceChildren();
}
function notice(text) { $('notice').textContent = text; }
function clearPaste() { pendingPaste = ''; $('paste-preview').value = ''; }
function updateState(active) {
  connected = active;
  $('status').textContent = active ? 'Qoşulub' : 'Bağlı deyil';
  $('status').classList.toggle('connected', active);
  for (const id of ['copy', 'paste', 'disconnect']) $(id).disabled = !active;
}
function sendInput(data) {
  if (!connected || socket?.readyState !== WebSocket.OPEN) return;
  const bytes = encoder.encode(data);
  if (bytes.byteLength > MAX_INPUT || socket.bufferedAmount > 65536) { notice('Giriş limiti aşıldı.'); return; }
  socket.send(bytes);
}
term.onData(sendInput);
function requestPaste(text) {
  if (!connected) return;
  const inspection = inspectPaste(text);
  if (!inspection.allowed) { notice('Paste ən çox 32 KiB ola bilər.'); return; }
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
  $('clipboard-help').textContent = copy ? 'Mətni seçib brauzerin copy funksiyasından istifadə et.' : 'Mətni buraya paste et; yoxlamadan sonra terminala göndər.';
  $('clipboard-panel').showModal(); $('clipboard-text').focus();
  if (copy) $('clipboard-text').select();
}
async function copySelection() {
  if (!connected) return;
  const selection = term.getSelection();
  if (!connected || !selection) return;
  if (!inspectPaste(selection).allowed) { notice('Copy limiti aşıldı.'); return; }
  try { await navigator.clipboard.writeText(selection); notice('Mətn kopyalandı.'); }
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
function connect() {
  expected = 1;
  socket = new WebSocket(`${location.origin.replace('https:', 'wss:')}/lab/socket`);
  socket.binaryType = 'arraybuffer';
  socket.onopen = () => { term.reset(); updateState(true); resize(); term.focus(); notice(''); };
  socket.onmessage = event => {
    if (!connected || retired) return;
    try {
      const frame = decodeOutput(event.data, expected++);
      outputBytes+=frame.bytes.byteLength;
      if(outputBytes>8*1024*1024) throw new Error('output quota');
      term.write(frame.bytes, () => {
        if (connected && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'ack', sequence: frame.sequence }));
      });
    } catch { socket.close(1008, 'invalid output'); }
  };
  socket.onclose = () => {
    updateState(false); clearPaste();
    retireTerminal();
    for (const id of ['paste-review', 'clipboard-panel']) if ($(id).open) $(id).close();
    $('clipboard-text').value = ''; notice('Sessiya bağlandı.');
  };
  socket.onerror = () => notice('Bağlantı açıla bilmədi.');
}
$('login').addEventListener('submit', async event => {
  event.preventDefault();
  const code = $('code').value;
  $('code').value = '';
  try {
    const response = await fetch('/lab/grant', { method: 'POST', headers: { 'Content-Type': 'text/plain', 'X-Keybash-Lab': '1' }, body: code, credentials: 'same-origin' });
    if (!response.ok) throw new Error('refused');
    $('login-panel').hidden = true; connect();
  } catch { notice('Giriş kodu qəbul edilmədi.'); }
});
$('disconnect').addEventListener('click', async () => {
  updateState(false); clearPaste(); retireTerminal();
  socket?.close();
  try { await fetch('/lab/logout', { method: 'POST', headers: { 'X-Keybash-Lab': '1' }, credentials: 'same-origin', signal: AbortSignal.timeout(5000) }); } catch {}
});
