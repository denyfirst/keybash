import { inspectPaste } from './paste.mjs';

// One instance belongs to one desktop. No timers/polling read the OS clipboard,
// and text the remote copied reaches this computer's clipboard only on a click.
export function workspaceControls({ $, live, client, send, resetKeyboard }) {
  const encoder = new TextEncoder();
  let enabled = false, remoteText = '', generation = 0, resizeTimer, lastSize = '', screen = 'fit';
  const buttons = ['screen', 'copy', 'paste'];
  const usable = () => enabled && live();
  const valid = text => typeof text === 'string' && text.isWellFormed() && !text.includes('\0') && inspectPaste(text).allowed;
  const close = id => { if ($(id).open) $(id).close(); };

  // Paste: one line goes at once; several lines, or hidden characters, are
  // shown first, as in a terminal. Nothing is sent before the person says so.
  function deliver(text) {
    if (!usable()) return;
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
    $('desktop').focus();
  }
  function review(text) {
    if (!usable()) return;
    $('paste-text').value = text;
    $('paste-preview').textContent = text ? inspectPaste(text).preview : '';
    if (!$('paste-review').open) $('paste-review').showModal();
    (text ? $('paste-send') : $('paste-text')).focus();
  }
  function paste(text) {
    if (!usable()) return;
    if (!valid(text)) { $('notice').textContent = 'The text must be at most 32 KiB of valid Unicode.'; return; }
    if (inspectPaste(text).review) review(text);
    else deliver(text);
  }
  async function copy() {
    if (!usable() || !remoteText) return;
    const epoch = generation, text = remoteText;
    try {
      await navigator.clipboard.writeText(text);
      if (usable() && epoch === generation) { delete $('copy').dataset.new; $('notice').textContent = 'Copied from the remote.'; }
    } catch {
      if (usable() && epoch === generation) {
        delete $('copy').dataset.new;
        $('remote-text').value = text; $('copy-panel').showModal(); $('remote-text').focus(); $('remote-text').select();
        $('notice').textContent = 'No clipboard permission. Select the text and press Ctrl+C.';
      }
    }
  }

  // Screen size: Fit follows the space the desktop has; a fixed size stays.
  const menu = $('screen-menu'), toggle = $('screen');
  function closeMenu() { if (!menu.hidden) { menu.hidden = true; toggle.setAttribute('aria-expanded', 'false'); } }
  function choose(size) {
    screen = size;
    for (const item of menu.querySelectorAll('[data-size]')) item.setAttribute('aria-checked', String(item.dataset.size === size));
    $('screen-choice').textContent = size === 'fit' ? 'Fit to window' : size.replace('x', ' × ');
    // A fixed size is its own label; Fit shows the size it has now.
    $('size').hidden = size !== 'fit';
    closeMenu(); resize(); $('desktop').focus();
  }
  function requestSize() {
    if (!usable()) return;
    // Fit asks the remote for exactly the space the desktop has here.
    let [w, h] = screen === 'fit' ? [$('desktop').clientWidth, $('desktop').clientHeight] : screen.split('x').map(Number);
    w = Math.max(200, Math.min(1920, Math.floor(w / 2) * 2));
    h = Math.max(200, Math.min(1080, Math.floor(h / 2) * 2));
    if (!Number.isInteger(w) || !Number.isInteger(h)) return;
    const size = `${w}x${h}`;
    if (size !== lastSize) { lastSize = size; send('size', w, h); }
  }
  function resize() { clearTimeout(resizeTimer); if (usable()) resizeTimer = setTimeout(requestSize, 350); }

  toggle.addEventListener('click', () => {
    if (!usable()) return;
    if (!menu.hidden) { closeMenu(); return; }
    menu.hidden = false; toggle.setAttribute('aria-expanded', 'true');
    (menu.querySelector('[aria-checked="true"]') ?? menu.querySelector('[data-size]')).focus();
  });
  menu.addEventListener('click', event => { const item = event.target.closest('[data-size]'); if (item && usable()) choose(item.dataset.size); });
  menu.addEventListener('keydown', event => {
    const items = [...menu.querySelectorAll('[data-size]')], at = items.indexOf(document.activeElement);
    if (event.key === 'Escape') { event.preventDefault(); closeMenu(); toggle.focus(); }
    else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); items[(at + (event.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length].focus(); }
  });
  document.addEventListener('pointerdown', event => { if (!menu.contains(event.target) && !toggle.contains(event.target)) closeMenu(); });
  $('copy').addEventListener('click', () => void copy());
  $('paste').addEventListener('click', async () => {
    if (!usable()) return;
    const epoch = generation;
    try {
      const text = await navigator.clipboard.readText();
      if (usable() && epoch === generation) paste(text);
    } catch {
      if (usable() && epoch === generation) { review(''); $('notice').textContent = 'No clipboard permission. Paste the text into the box with Ctrl+V.'; }
    }
  });
  $('paste-text').addEventListener('input', () => {
    const check = inspectPaste($('paste-text').value);
    $('paste-preview').textContent = check.allowed ? check.preview : 'The text is over 32 KiB.';
  });
  $('paste-send').addEventListener('click', () => {
    const text = $('paste-text').value;
    if (!valid(text)) { $('notice').textContent = 'The text was not sent: too large or not valid Unicode.'; return; }
    // Cleared now: the dialog's close event comes later, as a task of its own.
    $('paste-text').value = ''; $('paste-preview').textContent = '';
    close('paste-review'); deliver(text);
  });
  $('paste-review').addEventListener('close', () => { if (!$('paste-review').open) { $('paste-text').value = ''; $('paste-preview').textContent = ''; } });
  $('copy-panel').addEventListener('close', () => { if (!$('copy-panel').open) $('remote-text').value = ''; });
  // Ctrl+V on the desktop.
  document.addEventListener('paste', event => {
    if (!usable() || document.activeElement !== $('desktop')) return;
    event.preventDefault();
    paste(event.clipboardData?.getData('text/plain') ?? '');
  });
  return {
    get enabled() { return enabled; },
    feature(args) {
      if (enabled || args.length !== 3 || args.join('|') !== '1|text|display-update') return false;
      enabled = true;
      for (const id of buttons) $(id).disabled = !live();
      $('copy').disabled = !remoteText;
      resize(); return true;
    },
    receive(args) {
      if (!usable() || args.length !== 1 || !valid(args[0])) return false;
      remoteText = args[0];
      // Never written to this computer's clipboard unasked: a dot says it waits.
      $('copy').disabled = !remoteText;
      if (remoteText) $('copy').dataset.new = ''; else delete $('copy').dataset.new;
      return true;
    },
    tooLarge(args) {
      if (!usable() || args.length !== 0) return false;
      $('notice').textContent = 'Text copied on the remote is over 32 KiB, so it was not passed here.';
      return true;
    },
    key(key, modifiers) {
      if (!usable()) return undefined;
      if (modifiers.ctrl && modifiers.shift && (key === 67 || key === 99)) { void copy(); return false; }
      if (modifiers.ctrl && key === 118) return true; // browser paste event
      return undefined;
    },
    // The size the desktop opens at: the space it has, before anything connects.
    startSize() {
      const w = Math.max(200, Math.min(1920, Math.floor($('desktop').clientWidth / 2) * 2));
      const h = Math.max(200, Math.min(1080, Math.floor($('desktop').clientHeight / 2) * 2));
      lastSize = `${w}x${h}`;
      return lastSize;
    },
    resize,
    end() {
      generation++; enabled = false; remoteText = ''; lastSize = ''; clearTimeout(resizeTimer);
      closeMenu(); close('paste-review'); close('copy-panel'); delete $('copy').dataset.new;
      for (const id of ['paste-text', 'remote-text']) $(id).value = '';
      $('paste-preview').textContent = '';
      for (const id of buttons) $(id).disabled = true;
    }
  };
}
