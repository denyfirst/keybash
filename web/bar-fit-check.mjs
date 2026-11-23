import assert from 'node:assert/strict';

// The session bar keeps one line at every width (sessionChrome in remote.mjs):
// none of its parts overlaps another or leaves the bar, the connection's name
// keeps a few letters wider than a phone, and a wide bar shows everything
// again. `longer` is a status word the page really uses. It is set without a
// resize, so the bar has to fit again when its words change.
const room = 80;

// Runs in the page. With no widths it checks the bar as the window is; with
// widths it narrows the session to each in turn, so the steps run quickly.
async function inPage({ widths, longer, room }) {
  const session = document.querySelector('.session'), bar = session.querySelector('.bar');
  const status = document.getElementById('status'), name = bar.querySelector('.session-name'), before = status.textContent;
  // The page's own observers were made first, so they have run when these answer.
  const resized = () => new Promise(done => { const seen = new ResizeObserver(() => { seen.disconnect(); done(); }); seen.observe(session); });
  const settled = () => new Promise(done => setTimeout(done));
  const problems = [];
  const measure = said => {
    const outer = bar.getBoundingClientRect(), label = `${Math.round(outer.width)} px${said}`;
    const parts = [...bar.querySelectorAll('.session-mark, #status, .session-name, .session-kind, .tools > *')]
      .map(el => ({ part: el.id || el.className, box: el.getBoundingClientRect() }))
      .filter(({ box }) => box.width > 0);
    for (const { part, box } of parts) if (box.left < outer.left - 0.5 || box.right > outer.right + 0.5) problems.push(`${label}: ${part} leaves the bar`);
    for (let i = 0; i < parts.length; i++) for (let j = i + 1; j < parts.length; j++) {
      const a = parts[i].box, b = parts[j].box;
      if (a.left < b.right - 0.5 && b.left < a.right - 0.5) problems.push(`${label}: ${parts[i].part} overlaps ${parts[j].part}`);
    }
    if (outer.width > 760 && name.clientWidth < Math.min(name.scrollWidth, room)) problems.push(`${label}: the name has no room`);
  };
  const check = async () => {
    await resized(); measure('');
    if (!longer) return;
    status.textContent = longer; await settled(); measure(` saying "${longer}"`);
    status.textContent = before; await settled();
  };
  if (!widths) await check();
  else {
    for (const width of widths) { session.style.width = `${width}px`; await check(); }
    session.style.removeProperty('width'); await resized(); measure('');
  }
  return { problems, steps: [...bar.classList].filter(c => c.startsWith('fit-')).length };
}

export async function checkBarFits(page, what, longer) {
  const { width: was, height } = page.viewportSize(), problems = [];
  // Up to a phone's width the window itself narrows: the page's phone rules follow it.
  for (const width of [320, 360, 400, 480, 560, 640, 700, 760]) {
    await page.setViewportSize({ width, height });
    problems.push(...(await page.evaluate(inPage, { widths: null, longer, room })).problems);
  }
  // Wider, the session narrows 10 px at a time inside the page, then widens again.
  await page.setViewportSize({ width: 1600, height });
  const narrower = []; for (let width = 1600; width >= 770; width -= 10) narrower.push(width);
  problems.push(...(await page.evaluate(inPage, { widths: narrower, longer, room })).problems);
  const back = await page.evaluate(inPage, { widths: narrower.filter(width => width % 40 === 0).reverse(), longer: null, room });
  problems.push(...back.problems);
  assert.deepEqual(problems, [], `${what} bar`);
  assert.equal(back.steps, 0, `${what} bar: a wide window does not show everything again`);
  await page.setViewportSize({ width: was, height });
}
