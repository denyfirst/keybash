// What the desktop page (remote-desktop.mjs) computes about the picture, the
// pointer and pasted text: pure functions, so node tests cover them.
//
// A scaled screen (125 to 200%) gets its own pixels: the desktop is asked for at
// the screen's device pixels and the matching scale, and shown at 1/scale, so one
// remote pixel is one screen pixel and text is as sharp as on the screen itself.
// Windows fixes its scale for a session, so the scale is chosen when the desktop
// opens and kept. The proxy allows full HD times the scale, and these exact
// scales only (rdp-proxy/src/policy.rs).
export const desktopScales = [1, 1.25, 1.5, 1.75, 2];

// A desktop that connected but shows no picture. Windows' session manager
// sometimes stalls when a desktop arrives soon after another to the same
// account ended (its event 36, "CsrConnected ... EvCsrInitialized"). Ending it
// does not help: Windows ends the stalled connection itself after up to a
// minute, and a desktop opened before then stalls too. The one opened after
// has always drawn. So after pictureWait the page says it is waiting; when
// Windows ends a desktop that never drew, the page opens it again once, after
// reopenWait, marked in the address; the second time, and at pictureLimit, it
// says so.
export const pictureWait = 5000;
export const pictureLimit = 75000;
export const reopenWait = 3000;
export const againMark = '#again';
export function endWithoutPicture(pictured, word, again) {
  if (pictured || word !== 'remote-ended') return 'end';
  return again ? 'say' : 'reopen';
}

// The Windows scale nearest the screen's, 100% for anything unusable.
export function nearestScale(ratio) {
  if (!Number.isFinite(ratio) || ratio <= 0) return 1;
  return desktopScales.reduce((best, s) => Math.abs(s - ratio) < Math.abs(best - ratio) ? s : best, 1);
}

// On a scaled screen the person picks the picture. "sharp": the screen's own
// pixels and scale, as above. "smooth": the desktop at 100% in CSS pixels,
// enlarged by the browser: the same size on screen, softer text, and a quarter
// of the pixels at 200%, so it moves faster. With no choice yet the page picks
// smooth on the sharpest screens (175% and up), where the saving is largest.
export function pictureScale(picture, ratio) {
  const sharp = nearestScale(ratio);
  if (picture === 'sharp') return sharp;
  if (picture === 'smooth') return 1;
  return sharp >= 1.75 ? 1 : sharp;
}

// Device pixels for a space of w by h CSS pixels at scale: the width a multiple
// of 4 and the height even, at least 200, at most full HD times the scale, all
// within what the proxy allows.
export function scaledSize(w, h, scale) {
  const step = (n, most, by) => Math.max(200, Math.min(most, Math.floor(n * scale / by) * by));
  return [step(w, 1920 * scale, 4), step(h, 1080 * scale, 2)];
}

// A refilling allowance: at most burst at once, then perSecond.
export function rateLimiter(perSecond, burst, now = () => performance.now()) {
  let tokens = burst, at = now();
  return () => {
    const t = now();
    tokens = Math.min(burst, tokens + (t - at) * perSecond / 1000);
    at = t;
    if (tokens < 1) return false;
    tokens -= 1;
    return true;
  };
}

// Pastes: the first goes at once, however soon after the page opened; later
// ones at least half a second apart, and a burst of 8 then one a second.
export function pastePacer(now = () => performance.now()) {
  const allowance = rateLimiter(1, 8, now);
  let last = -Infinity;
  return () => {
    const t = now();
    if (t - last < 500 || !allowance()) return false;
    last = t;
    return true;
  };
}

// The CSS cursor that makes Windows' pointer the browser's own, so it moves
// with the hand at once instead of being a second picture a frame behind.
// The image keeps its remote pixels (sharp at 200%), shown at the desktop's
// scale (CSS pixels per remote pixel), with the hotspot in CSS pixels.
export function pointerCursor(url, hotspotX, hotspotY, scale) {
  const ratio = Math.round(1 / scale * 1000) / 1000;
  return `image-set(url("${url}") ${ratio}x) ${Math.round(hotspotX * scale)} ${Math.round(hotspotY * scale)}, default`;
}

// Windows' text has CRLF line ends; a textarea and other systems give LF.
export function windowsLines(text) {
  return text.replace(/\r\n|\r|\n/g, '\r\n');
}
