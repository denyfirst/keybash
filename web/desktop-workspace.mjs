import { inspectPaste } from './paste.mjs';

// A scaled screen (125 to 200%) gets its own pixels: the desktop is asked for at
// the screen's device pixels and the matching DPI, and shown at 1/scale, so one
// remote pixel is one screen pixel and text is as sharp as on the screen itself.
// Windows fixes its DPI for a session, so the scale is chosen when the desktop
// opens and kept. The server allows full HD times the scale, and these exact
// scales only (identity.DesktopBounds).
export const desktopScales = [1, 1.25, 1.5, 1.75, 2];

// The Windows scale nearest the screen's, 100% for anything unusable.
export function nearestScale(ratio) {
  if (!Number.isFinite(ratio) || ratio <= 0) return 1;
  return desktopScales.reduce((best, s) => Math.abs(s - ratio) < Math.abs(best - ratio) ? s : best, 1);
}

// Device pixels for a space of w by h CSS pixels at scale: even, at least 200,
// at most full HD times the scale.
export function scaledSize(w, h, scale) {
  const even = (n, most) => Math.max(200, Math.min(most, Math.floor(n * scale / 2) * 2));
  return [even(w, 1920 * scale), even(h, 1080 * scale)];
}

// What the page tells the server it opens at: "1600x900" at 100%, "2880x1800@192" scaled.
export function startSizeField(w, h, scale) {
  return scale === 1 ? `${w}x${h}` : `${w}x${h}@${Math.round(96 * scale)}`;
}

// One instance belongs to one desktop. No timers/polling read the OS clipboard,
// and text the remote copied reaches this computer's clipboard only on a click.
export function workspaceControls({ $, live, client, send, resetKeyboard }) {
  const encoder = new TextEncoder();
  let enabled = false, remoteText = '', generation = 0, resizeTimer, lastSize = '', screen = 'fit', copyAsked = 0;
  const buttons = ['screen', 'copy', 'paste'];
  const usable = () => enabled && live();
  const valid = text => typeof text === 'string' && text.isWellFormed() && !text.includes('\0') && inspectPaste(text).allowed;
  const close = id => { if ($(id).open) $(id).close(); };

  let scale = 1; // chosen when the desktop opens (startSize)
  const deviceSize = (w, h) => scaledSize(w, h, scale);

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
  // asked: the person's own Ctrl+C on the desktop, not a click. If the browser
  // does not let that write the clipboard, the dot on Copy says the text waits.
  async function copy(asked = false) {
    if (!usable() || !remoteText) return;
    const epoch = generation, text = remoteText;
    try {
      await navigator.clipboard.writeText(text);
      if (usable() && epoch === generation) { delete $('copy').dataset.new; $('notice').textContent = asked ? 'Copied to this computer too.' : 'Copied from the remote.'; }
    } catch {
      if (asked) return;
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
    // A fixed size is in the screen's own units, like Fit, so it looks the same size at any scale.
    const [w, h] = deviceSize(...(screen === 'fit' ? [$('desktop').clientWidth, $('desktop').clientHeight] : screen.split('x').map(Number)));
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
      // Never written to this computer's clipboard unasked: a dot says it
      // waits. A copy that follows the person's own Ctrl+C on the desktop is
      // what they asked for, so it comes here as on any computer.
      $('copy').disabled = !remoteText;
      if (remoteText) $('copy').dataset.new = ''; else delete $('copy').dataset.new;
      if (remoteText && Date.now() - copyAsked < 5000) { copyAsked = 0; void copy(true); }
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
      // Ctrl+C still goes to the remote; it also lets the next copy, within
      // five seconds, come to this computer.
      if (modifiers.ctrl && !modifiers.alt && (key === 67 || key === 99)) copyAsked = Date.now();
      if (modifiers.ctrl && key === 118) return true; // browser paste event
      return undefined;
    },
    // The size the desktop opens at: the space it has, before anything connects,
    // in device pixels with the DPI of the screen's scale ("2880x1800@192").
    startSize() {
      scale = nearestScale(window.devicePixelRatio || 1);
      const [w, h] = deviceSize($('desktop').clientWidth, $('desktop').clientHeight);
      lastSize = `${w}x${h}`;
      return startSizeField(w, h, scale);
    },
    // Remote pixels per CSS pixel: the desktop is shown at 1/scale.
    scale: () => scale,
    resize,
    end() {
      generation++; enabled = false; remoteText = ''; lastSize = ''; copyAsked = 0; clearTimeout(resizeTimer);
      closeMenu(); close('paste-review'); close('copy-panel'); delete $('copy').dataset.new;
      for (const id of ['paste-text', 'remote-text']) $(id).value = '';
      $('paste-preview').textContent = '';
      for (const id of buttons) $(id).disabled = true;
    }
  };
}
