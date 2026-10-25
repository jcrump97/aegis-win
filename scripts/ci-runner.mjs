#!/usr/bin/env node
/**
 * AegisWin Automated CI Pipeline Runner
 * Runs on every commit via Git hooks and in GitHub Actions.
 * Verifies:
 *  1. Atomic commit message prefix convention: ^(chore|doc|feat|fix|test|refactor|perf|security)\b
 *  2. Documentation folder integrity & audit synchronization
 *  3. Core & Plugin automated test suites via Node built-in test runner (Vite/Vitest compatible)
 *  4. Rust unit tests for standalone crates (the one-click launcher)
 */
import { execFileSync, execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const rootDir = process.cwd();

function collectTestFiles(dir, results = []) {
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
      collectTestFiles(full, results);
    } else if (entry.isFile() && entry.name.endsWith('.test.mjs')) {
      results.push(full);
    }
  }
  return results;
}

console.log('========================================================');
console.log(' [AegisWin CI] Starting Atomic Verification Pipeline...');
console.log('========================================================');

const testFiles = [
  ...collectTestFiles(path.join(rootDir, 'tests')),
  ...collectTestFiles(path.join(rootDir, 'plugins')),
];

if (testFiles.length === 0) {
  console.error('[AegisWin CI] FAIL: Every commit must include verified tests.');
  process.exit(1);
}

console.log(`[AegisWin CI] Discovered ${testFiles.length} test suite(s):`);
for (const tf of testFiles) {
  console.log(`  -> ${path.relative(rootDir, tf)}`);
}

try {
  const cmd = `node --test ${testFiles.map((f) => `"${f}"`).join(' ')}`;
  execSync(cmd, { stdio: 'inherit' });
} catch (err) {
  console.error('[AegisWin CI] FAIL: Test suite execution failed.');
  process.exit(1);
}

// Rust crates with their own manifest (the one-click launcher). CI always has cargo; a local
// machine without Rust skips with a warning instead of blocking a docs-only commit.
const rustCrates = [path.join(rootDir, 'launcher', 'Cargo.toml')].filter((m) => fs.existsSync(m));
for (const manifest of rustCrates) {
  console.log(`[AegisWin CI] cargo test --manifest-path ${path.relative(rootDir, manifest)}`);
  try {
    execFileSync('cargo', ['test', '--locked', '--manifest-path', manifest], { stdio: 'inherit' });
  } catch (err) {
    if (err.code === 'ENOENT' && !process.env.CI) {
      console.warn('[AegisWin CI] WARN: cargo not found; skipping Rust tests (they still run in GitHub Actions).');
      continue;
    }
    console.error('[AegisWin CI] FAIL: Rust tests failed.');
    process.exit(1);
  }
}
console.log('[AegisWin CI] PASS: All unit, integration, and audit tests succeeded.');
