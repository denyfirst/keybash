import { inspectPaste } from './paste.mjs';

// One instance belongs to one desktop. No timers/polling read the OS clipboard.
export function workspaceControls({ $, live, client, send, resetKeyboard }) {
  const encoder = new TextEncoder();
  let enabled = false, remoteText = '', generation = 0, resizeTimer, lastSize = '';
  const buttons = ['copy-remote', 'paste-local', 'paste-send', 'resolution'];
  const usable = () => enabled && live();
  const valid = text => typeof text === 'string' && text.isWellFormed() && !text.includes('\0') && inspectPaste(text).allowed;
  function prepare(text) {
    if (!valid(text)) { $('notice').textContent = 'The text must be at most 32 KiB of valid Unicode.'; return false; }
    $('paste-text').value = text;
    $('paste-preview').textContent = inspectPaste(text).preview;
    return true;
  }
  function paste() {
    if (!usable()) return;
    const text = $('paste-text').value;
    if (!valid(text)) { $('notice').textContent = 'The text was not sent: too large or not valid Unicode.'; return; }
    resetKeyboard();
    send('clipboard', '0', 'text/plain');
    const bytes = encoder.encode(text);
    for (let offset = 0; offset < bytes.length; offset += 4096) {
      send('blob', '0', btoa(String.fromCharCode(...bytes.subarray(offset, offset + 4096))));
    }
    send('end', '0');
    // Ordinary remote paste after the complete text, never an appended Enter.
    for (const key of [0xffe3, 118]) client().sendKeyEvent(1, key);
    for (const key of [118, 0xffe3]) client().sendKeyEvent(0, key);
    $('paste-text').value = ''; $('paste-preview').textContent = '';
    $('desktop').focus();
  }
  async function copy() {
    if (!usable()) return;
    const epoch = generation, text = remoteText;
    try {
      await navigator.clipboard.writeText(text);
      if (usable() && epoch === generation) $('notice').textContent = 'Text from the remote copied.';
    } catch {
      if (usable() && epoch === generation) {
        $('remote-text').value = text; $('remote-text').focus(); $('remote-text').select();
        $('notice').textContent = 'No clipboard permission. Select the text and press Ctrl+C.';
      }
    }
  }
  function requestSize() {
    if (!usable()) return;
    const selected = $('resolution').value;
    let [w, h] = selected === 'fit' ? [$('desktop').clientWidth, window.innerHeight * 0.72] : selected.split('x').map(Number);
    if (document.fullscreenElement && selected === 'fit') [w, h] = [window.innerWidth, window.innerHeight];
    w = Math.max(64, Math.min(1920, Math.floor(w / 2) * 2));
    h = Math.max(64, Math.min(1080, Math.floor(h / 2) * 2));
    if (!Number.isInteger(w) || !Number.isInteger(h)) return;
    const size = `${w}x${h}`;
    if (size !== lastSize) { lastSize = size; send('size', w, h); }
  }
  function resize() { clearTimeout(resizeTimer); if (usable()) resizeTimer = setTimeout(requestSize, 350); }
  $('paste-text').addEventListener('input', () => {
    const check = inspectPaste($('paste-text').value);
    $('paste-preview').textContent = check.allowed ? check.preview : 'The text is over 32 KiB.';
  });
  $('paste-send').addEventListener('click', paste);
  $('copy-remote').addEventListener('click', () => void copy());
  $('resolution').addEventListener('change', resize);
  $('paste-local').addEventListener('click', async () => {
    if (!usable()) return;
    const epoch = generation;
    try {
      const text = await navigator.clipboard.readText();
      if (usable() && epoch === generation && prepare(text)) $('paste-send').focus();
    } catch {
      if (usable() && epoch === generation) {
        $('paste-text').focus(); $('notice').textContent = 'No clipboard permission. Paste the text into the panel with Ctrl+V.';
      }
    }
  });
  document.addEventListener('paste', event => {
    if (!usable() || document.activeElement !== $('desktop')) return;
    event.preventDefault();
    const text = event.clipboardData?.getData('text/plain');
    if (!prepare(text)) return;
    if (!inspectPaste(text).review) paste();
    else { $('paste-send').focus(); $('notice').textContent = 'Review the text, then send it. No Enter is added.'; }
  });
  return {
    get enabled() { return enabled; },
    feature(args) {
      if (enabled || args.length !== 3 || args.join('|') !== '1|text|display-update') return false;
      enabled = true;
      for (const id of buttons) $(id).disabled = !live();
      resize(); return true;
    },
    receive(args) {
      if (!usable() || args.length !== 1 || !valid(args[0])) return false;
      remoteText = args[0]; $('remote-text').value = remoteText; return true;
    },
    key(key, modifiers) {
      if (!usable()) return undefined;
      if (modifiers.ctrl && modifiers.shift && (key === 67 || key === 99)) { void copy(); return false; }
      if (modifiers.ctrl && key === 118) return true; // browser paste event
      return undefined;
    },
    resize,
    end() {
      generation++; enabled = false; remoteText = ''; lastSize = ''; clearTimeout(resizeTimer);
      for (const id of ['paste-text', 'remote-text']) $(id).value = '';
      $('paste-preview').textContent = '';
      for (const id of buttons) $(id).disabled = true;
    }
  };
}
