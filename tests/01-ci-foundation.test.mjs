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
