import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const root = new URL('./', import.meta.url);
const pkg = JSON.parse(await readFile(new URL('node_modules/@xterm/xterm/package.json', root)));
if (pkg.version !== '6.0.0' || Object.keys(pkg.dependencies ?? {}).length) throw new Error('unexpected xterm graph');
// The GPU renderer, released with xterm 6.0.0; it depends on nothing.
const webgl = JSON.parse(await readFile(new URL('node_modules/@xterm/addon-webgl/package.json', root)));
if (webgl.version !== '0.19.0' || Object.keys(webgl.dependencies ?? {}).length || Object.keys(webgl.peerDependencies ?? {}).length) throw new Error('unexpected xterm WebGL graph');
await mkdir(new URL('vendor/', root), { recursive: true });
const manifest = { package: '@xterm/xterm', version: pkg.version, files: {}, addons: { '@xterm/addon-webgl': webgl.version } };
for (const [module, source, destination] of [
  ['xterm', 'lib/xterm.js', 'xterm.js'], ['xterm', 'css/xterm.css', 'xterm.css'], ['xterm', 'LICENSE', 'xterm-LICENSE.txt'],
  ['addon-webgl', 'lib/addon-webgl.js', 'xterm-addon-webgl.js'], ['addon-webgl', 'LICENSE', 'xterm-addon-webgl-LICENSE.txt'],
]) {
  const bytes = await readFile(new URL(`node_modules/@xterm/${module}/${source}`, root));
  await writeFile(new URL(`vendor/${destination}`, root), bytes);
  manifest.files[destination] = createHash('sha256').update(bytes).digest('hex');
}
await writeFile(new URL('vendor/manifest.json', root), JSON.stringify(manifest, null, 2) + '\n');
