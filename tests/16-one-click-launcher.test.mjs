import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const LAUNCHER_EXE = 'Start AegisWin.exe';
const SRC_DIR = 'launcher/src';

function launcherSources() {
  return fs.readdirSync(SRC_DIR).filter((f) => f.endsWith('.rs')).map((f) => ({
    file: path.join(SRC_DIR, f),
    text: fs.readFileSync(path.join(SRC_DIR, f), 'utf8'),
  }));
}

test('One-Click Launcher: prebuilt exe is committed at the repo root with an embedded asInvoker manifest', () => {
  // Committed so a fresh clone can run it before Rust or Node.js exist on the machine.
  const exe = fs.readFileSync(LAUNCHER_EXE);
  assert.equal(exe.subarray(0, 2).toString('latin1'), 'MZ', `${LAUNCHER_EXE} must be a Windows PE executable`);
  assert.ok(exe.length < 2 * 1024 * 1024, 'Launcher should stay small (std-only, size-optimized)');
  // Without a manifest, Windows installer detection may force UAC on a setup-like exe.
  assert.ok(exe.includes(Buffer.from('level="asInvoker"')), 'Launcher exe must embed the asInvoker manifest');

  const manifest = fs.readFileSync('launcher/launcher.manifest', 'utf8');
  assert.match(manifest, /requestedExecutionLevel level="asInvoker" uiAccess="false"/);
  const rc = fs.readFileSync('launcher/launcher.rc', 'utf8');
  assert.match(rc, /ICON "\.\.\/src-tauri\/icons\/icon\.ico"/);
  assert.match(rc, /24 "launcher\.manifest"/);
});

test('One-Click Launcher: no shells, and runtime code uses only the standard library', () => {
  for (const { file, text } of launcherSources()) {
    // PLUGIN_SPEC section 4: absolute-path binaries with an argv, never a shell.
    assert.doesNotMatch(text, /cmd\.exe|powershell|pwsh|Command::new\("(cmd|sh|bash)"\)/i, `${file} must not invoke a shell`);
    assert.doesNotMatch(text, /npm\.cmd|\.bat\b/i, `${file} must run npm through node + npm-cli.js, not a batch file`);
  }
  const cargo = fs.readFileSync('launcher/Cargo.toml', 'utf8');
  assert.doesNotMatch(cargo, /^\[dependencies\]/m, 'Launcher must not take runtime dependencies');
  assert.ok(fs.existsSync('launcher/Cargo.lock'), 'Missing launcher/Cargo.lock');
});

test('One-Click Launcher: wired into npm scripts, CI, gitignore, and the README', () => {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  assert.equal(pkg.scripts['launcher:build'], 'node scripts/build-launcher.mjs');
  assert.match(fs.readFileSync('scripts/ci-runner.mjs', 'utf8'), /--manifest-path launcher\/Cargo\.toml/, 'CI must run the launcher Rust tests');
  assert.match(fs.readFileSync('.gitignore', 'utf8'), /^launcher\/target\/$/m);

  const readme = fs.readFileSync('README.md', 'utf8');
  assert.ok(readme.includes(LAUNCHER_EXE), 'README must point users at the launcher');
  assert.ok(readme.includes('npm run launcher:build'), 'README must say how to rebuild the launcher');
});
