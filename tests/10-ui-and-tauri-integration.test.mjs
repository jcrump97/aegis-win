import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const mainRs = fs.readFileSync('src-tauri/src/main.rs', 'utf8');
const apiTs = fs.readFileSync('src/ui/api.ts', 'utf8');

test('Tauri wiring: every command the UI calls is registered, and every registered command exists', () => {
  const handler = mainRs.match(/generate_handler!\[([\s\S]*?)\]/);
  assert.ok(handler, 'main.rs must register commands with generate_handler!');
  const registered = new Set(handler[1].split(',').map((s) => s.trim()).filter(Boolean));
  const called = [...apiTs.matchAll(/call<[^>]*>\('([a-z_]+)'/g)].map((m) => m[1]);
  assert.ok(called.length >= 20, 'api.ts should wrap every command');
  for (const cmd of called) assert.ok(registered.has(cmd), `UI calls '${cmd}' but main.rs does not register it`);
  for (const cmd of registered) {
    assert.match(mainRs, new RegExp(`#\\[tauri::command\\]\\s*async fn ${cmd}\\(`), `registered command '${cmd}' must be an async #[tauri::command]`);
  }
});

test('Tauri wiring: portable data folder, WebView2 profile inside it, and a strict CSP', () => {
  assert.match(mainRs, /join\("data"\)/, 'state lives in ./data next to the exe');
  assert.match(mainRs, /\.data_directory\(data_dir\.join\("webview"\)\)/, 'WebView2 profile must stay in ./data');
  const conf = JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json', 'utf8'));
  assert.deepEqual(conf.app.windows, [], 'the window is built in setup() so it can set the data directory');
  const csp = conf.app.security.csp;
  assert.match(csp, /default-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-eval|https?:\/\/(?!ipc\.localhost)/, 'no eval and no remote origins');
  const capability = JSON.parse(fs.readFileSync('src-tauri/capabilities/default.json', 'utf8'));
  assert.deepEqual(capability.windows, ['main']);
});

test('UI: no CDN scripts, no demo PIN, and data is never written with innerHTML', () => {
  const html = fs.readFileSync('index.html', 'utf8');
  assert.doesNotMatch(html, /<script[^>]+src="https?:/, 'all code is bundled locally');
  assert.match(html, /src="\/src\/ui\/main\.ts"/);
  for (const file of fs.readdirSync('src/ui').filter((f) => f.endsWith('.ts'))) {
    const src = fs.readFileSync(`src/ui/${file}`, 'utf8');
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/, `${file} must build DOM with textContent`);
    assert.doesNotMatch(src, /localStorage|sessionStorage/, `${file} must not persist anything in the webview`);
    assert.doesNotMatch(src, /\b(482910|246810)\b/, `${file} must not contain a demo PIN`);
  }
});

test('Tauri Build Scaffold: build.rs embeds the asInvoker manifest, Windows icon exists, and lockfiles are committed', () => {
  // Without build.rs + icon.ico, `tauri dev` / `tauri build` cannot compile on Windows.
  const buildRs = fs.readFileSync('src-tauri/build.rs', 'utf8');
  assert.match(buildRs, /app_manifest\(include_str!\("app\.manifest"\)\)/);
  assert.ok(fs.statSync('src-tauri/icons/icon.ico').size > 0, 'Missing src-tauri/icons/icon.ico');

  // A custom manifest replaces Tauri's default, so it must keep the Common Controls v6 dependency.
  const manifestXml = fs.readFileSync('src-tauri/app.manifest', 'utf8');
  assert.match(manifestXml, /requestedExecutionLevel level="asInvoker" uiAccess="false"/);
  assert.match(manifestXml, /Microsoft\.Windows\.Common-Controls/);

  // Reproducible builds: pin both the npm and Cargo dependency trees.
  assert.ok(fs.existsSync('package-lock.json'), 'Missing package-lock.json');
  assert.ok(fs.existsSync('Cargo.lock'), 'Missing Cargo.lock');
});

test('UI: LLM answers parse a safe Markdown subset into plain data', async () => {
  // Compile the TypeScript module with esbuild (already installed with Vite) so this runs on any Node version.
  const { transformSync } = await import('esbuild');
  const { code } = transformSync(fs.readFileSync('src/ui/markdown.ts', 'utf8'), { loader: 'ts', format: 'esm' });
  const { parseMarkdown } = await import(`data:text/javascript,${encodeURIComponent(code)}`);

  const blocks = parseMarkdown('## Cause\nThe **disk** is full.\n\n1. Run `cleanmgr`\n2. Restart\n\n- *one*\n  continued\n\n```\n<script>x</script>\n```');
  assert.deepEqual(blocks, [
    { kind: 'heading', level: 2, inlines: [{ kind: 'text', text: 'Cause' }] },
    { kind: 'paragraph', inlines: [{ kind: 'text', text: 'The ' }, { kind: 'strong', text: 'disk' }, { kind: 'text', text: ' is full.' }] },
    { kind: 'list', ordered: true, items: [[{ kind: 'text', text: 'Run ' }, { kind: 'code', text: 'cleanmgr' }], [{ kind: 'text', text: 'Restart' }]] },
    { kind: 'list', ordered: false, items: [[{ kind: 'em', text: 'one' }, { kind: 'text', text: ' continued' }]] },
    { kind: 'code', text: '<script>x</script>' },
  ]);
  // Arithmetic and stray asterisks stay literal text.
  assert.deepEqual(parseMarkdown('5 * 3 * 2'), [{ kind: 'paragraph', inlines: [{ kind: 'text', text: '5 * 3 * 2' }] }]);
  // The renderer must build elements, never parse HTML.
  const render = fs.readFileSync('src/ui/render.ts', 'utf8');
  assert.match(render, /markdown\(answer\.text\)/, 'LLM answers go through the Markdown renderer');
});
