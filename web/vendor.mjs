import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const root = new URL('./', import.meta.url);
const pkg = JSON.parse(await readFile(new URL('node_modules/@xterm/xterm/package.json', root)));
if (pkg.version !== '6.0.0' || Object.keys(pkg.dependencies ?? {}).length) throw new Error('unexpected xterm graph');
await mkdir(new URL('vendor/', root), { recursive: true });
const manifest = { package: '@xterm/xterm', version: pkg.version, files: {} };
for (const [source, destination] of [['lib/xterm.js', 'xterm.js'], ['css/xterm.css', 'xterm.css'], ['LICENSE', 'xterm-LICENSE.txt']]) {
  const bytes = await readFile(new URL(`node_modules/@xterm/xterm/${source}`, root));
  await writeFile(new URL(`vendor/${destination}`, root), bytes);
  manifest.files[destination] = createHash('sha256').update(bytes).digest('hex');
}
await writeFile(new URL('vendor/manifest.json', root), JSON.stringify(manifest, null, 2) + '\n');
