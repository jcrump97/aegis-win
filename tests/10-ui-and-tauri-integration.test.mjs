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

test('UI: the monitor screen starts monitors only through the PIN-gated tool, and labels AI text', () => {
  const monitors = fs.readFileSync('src/ui/monitors.ts', 'utf8');
  const main = fs.readFileSync('src/ui/main.ts', 'utf8');
  // One place starts a monitor: the Start button of a rule AegisWin has just checked and described.
  assert.equal(monitors.match(/run\('activate_monitor'/g)?.length, 1, 'activate_monitor is called from one place');
  assert.match(monitors, /function proposalView[\s\S]*?deps\.run\('activate_monitor', args, start\)/);
  // Every tool call goes through invokeTool, which asks for the PIN when the gate needs it.
  assert.match(main, /function monitorDeps[\s\S]*?return invokeTool\(plugin, tool, args, button\);/);
  assert.match(main, /async function invokeTool[\s\S]*?effectivePolicy === 'pin_required'[\s\S]*?askPin\(/);
  // Editing the rule throws away the last check, so a stale review is never started.
  assert.match(monitors, /addEventListener\('input', \(e\) => \{\s*if \(form\.contains\(e\.target as Node\)\) replace\(result\);/);
  assert.match(monitors, /addEventListener\('change', \(e\) => \{\s*if \(form\.contains\(e\.target as Node\)\) replace\(result\);/);
  // Text an AI wrote is always shown with a label saying so.
  const labels = [...monitors.matchAll(/aiText\(('[^']*'|str\(reasoning\.label\))/g)].map((m) => m[1]);
  assert.equal(labels.length, 3);
  for (const l of labels) assert.ok(l === 'str(reasoning.label)' || /AI-generated, may be wrong/.test(l), l);
  // App-only tools are never offered as generic forms or as agent gates.
  assert.match(main, /plugin\.tools\.filter\(\(t\) => !t\.appOnly/);
  assert.match(main, /p\.tools\.filter\(\(t\) => !t\.appOnly\)\.map/);
});

test('Lifecycle: one copy per install, close-to-tray only while monitors run, and the UI notices a lock', () => {
  // The single-instance claim comes before anything else starts.
  assert.match(mainRs, /fn main\(\) \{\s*\/\/[^\n]*\n\s*let claim = match claim_instance\(\) \{[\s\S]*?Ok\(Instance::AlreadyRunning\) => return,/);
  // Closing hides the window only when a plugin is working in the background.
  assert.match(mainRs, /CloseRequested \{ api, \.\. \} = event \{\s*if window\.state::<Arc<Engine>>\(\)\.background_active\(\) \{\s*api\.prevent_close\(\);/);
  // The elevated restart releases the claim so the elevated copy can start.
  assert.match(mainRs, /drop\(claim\.0\.lock\(\)\.unwrap\(\)\.take\(\)\);\s*let reclaim[\s\S]*?relaunch_elevated\(\)/);
  const main = fs.readFileSync('src/ui/main.ts', 'utf8');
  // Only input in the app window counts as activity.
  assert.match(main, /document\.addEventListener\('pointerdown', noteActivity, true\);/);
  assert.match(main, /document\.addEventListener\('keydown', noteActivity, true\);/);
  assert.equal(main.match(/api\.noteActivity\(\)/g)?.length, 1, 'activity is reported from one place');
  // The poll checks the lock state first, because the vault can lock without the UI asking.
  assert.match(main, /pollTimer = window\.setInterval\(async \(\) => \{\s*try \{\s*\/\/[^\n]*\n\s*const now = await api\.status\(\);\s*status = now;\s*if \(!now\.unlocked\) return route\(\);/);
});

test('Action plans: the app shows the plan as AegisWin describes it and approves it by hash', () => {
  const main = fs.readFileSync('src/ui/main.ts', 'utf8');
  // A plan approval sends the hash of the plan that was shown; the command passes it to the engine.
  assert.match(main, /api\.decideTicket\(t\.ticketId, yes, pin\.value, comment\.value\.trim\(\) \|\| null, t\.plan\?\.hash \?\? null\)/);
  assert.match(mainRs, /async fn decide_ticket\([\s\S]*?plan_hash: Option<String>,[\s\S]*?engine\.decide\(&ticket_id, approve, pin, comment, "app", plan_hash\.as_deref\(\)\)/);
  // Cancel needs no PIN and goes straight to the engine.
  assert.match(apiTs, /cancelTicket: \(ticketId: string\) => call<TicketView>\('cancel_ticket', \{ ticketId \}\)/);
  assert.match(mainRs, /async fn cancel_ticket\(engine: EngineState<'_>, ticket_id: String\) -> Cmd<TicketView> \{\s*engine\.cancel_ticket\(&ticket_id\)\s*\}/);
  // Every piece of supplied text is shown under the label of who wrote it.
  const plan = main.slice(main.indexOf('function planCard('), main.indexOf('function ticketCard('));
  assert.ok(plan.length > 0, 'planCard exists');
  assert.equal(plan.match(/suppliedText\(plan\.suppliedLabel,/g)?.length, 2, 'step reasoning and the plan title and reasoning');
  // Outside the lines that build a labelled block, supplied text is never read.
  const unlabelled = plan.split('\n').filter((line) => !line.includes('suppliedText(plan.suppliedLabel,') && !line.includes('const { title, reasoning } = plan;'));
  assert.deepEqual(unlabelled.filter((line) => /reasoning|title\b/.test(line)), [], 'no supplied text outside its label');
  // The heading, toast, top bar, and tray use the code-written name, never the supplied title.
  assert.match(plan, /h\('h3', \{\}, t\.toolName\)/);
  assert.match(plan, /h\('pre', \{\}, s\.commands\.length/);
  assert.match(plan, /'Stop after this step'/);
  assert.match(main, /if \(t\.plan\) return planCard\(t, t\.plan\);/);
});

test('Serial executor: the app shows the change in progress, and the shell never cuts one off', () => {
  const main = fs.readFileSync('src/ui/main.ts', 'utf8');
  assert.match(main, /const \{ running, queued \} = status\.change;/);
  assert.match(main, /queued: \['approved, waiting its turn'/);
  // Restarting as administrator is refused while a change runs; Quit asks first.
  assert.match(mainRs, /async fn restart_as_admin[\s\S]*?if let Some\(tool\) = engine\.change_running\(\) \{\s*return Err/);
  assert.match(mainRs, /fn quit_app[\s\S]*?change_running\(\)[\s\S]*?os::confirm\(/);
  assert.match(mainRs, /"quit" => quit_app\(app\),/);
});
