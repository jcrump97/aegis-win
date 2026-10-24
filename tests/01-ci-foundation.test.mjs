import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

test('CI Foundation: repository configuration and Vite/Tauri scaffolding exist', () => {
  assert.ok(fs.existsSync('package.json'), 'package.json must exist');
  assert.ok(fs.existsSync('vite.config.ts'), 'vite.config.ts must exist');
  assert.ok(fs.existsSync('.github/workflows/ci.yml'), 'CI workflow must exist');
  assert.ok(fs.existsSync('.githooks/commit-msg'), 'commit-msg hook must exist');
  assert.ok(fs.existsSync('.githooks/pre-commit'), 'pre-commit hook must exist');

  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  assert.equal(pkg.name, 'aegis-win');
  assert.ok(pkg.scripts.test, 'test script must be defined');
  assert.ok(pkg.scripts.ci, 'ci script must be defined');
});

test('CI Foundation: commit-msg regex enforces prepended (type) convention', () => {
  const hook = fs.readFileSync('.githooks/commit-msg', 'utf8');
  assert.match(hook, /\(feat\|fix\|doc\|chore\|test\|refactor\|security\|perf\)/);
  const pattern = /^\((feat|fix|doc|chore|test|refactor|security|perf)\) .+/;
  assert.ok(pattern.test('(chore) Initialize repository and CI pipeline'));
  assert.ok(pattern.test('(fix) Resolve DNS timeout edge case'));
  assert.ok(!pattern.test('Initialize repository (chore)'), 'Trailing tag must be rejected');
});

test('CI Foundation: commit-msg hook rejects AI attribution trailers and footers', () => {
  const hook = fs.readFileSync('.githooks/commit-msg', 'utf8');
  const match = hook.match(/^ATTRIBUTION_PATTERN='(.+)'$/m);
  assert.ok(match, 'commit-msg hook must define ATTRIBUTION_PATTERN');
  // Same semantics as the hook's `grep -Ei`: case-insensitive, per line.
  const pattern = new RegExp(match[1], 'im');

  assert.ok(pattern.test('Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'));
  assert.ok(pattern.test('co-authored-by: GitHub Copilot <copilot@github.com>'));
  assert.ok(pattern.test('Generated with [Claude Code](https://claude.com/claude-code)'));
  assert.ok(!pattern.test('(feat) Add Claude-compatible MCP tool listing'), 'Mentioning a product in the subject is allowed');
  assert.ok(!pattern.test('Co-Authored-By: Jane Doe <jane@example.com>'), 'Human co-authors are allowed');
});

test('CI Foundation: npm run ci also runs the Rust workspace tests', () => {
  const runner = fs.readFileSync('scripts/ci-runner.mjs', 'utf8');
  assert.match(runner, /test --workspace/);
  const cargo = fs.readFileSync('Cargo.toml', 'utf8');
  assert.match(cargo, /\[workspace\]/);
  assert.match(cargo, /crates\/aegis-core/);
});

test('CI Foundation: npm run ci typechecks and builds the UI before the Rust tests', () => {
  const runner = fs.readFileSync('scripts/ci-runner.mjs', 'utf8');
  const tsc = runner.indexOf("execSync('npx --no-install tsc -p .'");
  const vite = runner.indexOf("execSync('npx --no-install vite build");
  const cargo = runner.indexOf('test --workspace --quiet`');
  assert.ok(tsc > 0 && vite > tsc && cargo > vite, 'tsc, then vite build (Tauri embeds dist/), then cargo test');
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  assert.equal(pkg.scripts.typecheck, 'tsc -p .');
  assert.ok(!pkg.dependencies?.react, 'The UI is plain TypeScript; React was removed');
});

test('Rust core only: the Node.js prototype is gone and live docs no longer point at it', () => {
  for (const legacy of ['src/core', 'src/ui/app-shell.mjs']) {
    assert.ok(!fs.existsSync(legacy), `${legacy} was removed by ADR 0001 and must not come back`);
  }
  for (const plugin of fs.readdirSync('plugins')) {
    assert.ok(!fs.existsSync(`plugins/${plugin}/index.mjs`), `plugins/${plugin} must be a Rust crate, not index.mjs`);
    assert.ok(fs.existsSync(`plugins/${plugin}/src/lib.rs`), `plugins/${plugin} is missing src/lib.rs`);
  }
  // The ADR keeps the history; the operating docs must describe what ships.
  for (const doc of ['AGENT.md', 'CLAUDE.md', 'README.md', 'documentation/ARCHITECTURE.md', 'documentation/PLUGIN_SPEC.md']) {
    assert.doesNotMatch(fs.readFileSync(doc, 'utf8'), /src\/core\/|index\.mjs|CentralLlmService/, `${doc} still references the prototype`);
  }
});
