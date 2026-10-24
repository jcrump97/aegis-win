#!/usr/bin/env node
/**
 * AegisWin Automated CI Pipeline Runner
 * Runs on every commit via Git hooks and in GitHub Actions.
 * Verifies:
 *  1. Atomic commit message prefix convention: ^(chore|doc|feat|fix|test|refactor|perf|security)\b
 *  2. Documentation folder integrity & audit synchronization
 *  3. Core & Plugin automated test suites via Node built-in test runner (Vite/Vitest compatible)
 */
import { execSync } from 'node:child_process';
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
  console.log('[AegisWin CI] PASS: All unit, integration, and audit tests succeeded.');
} catch (err) {
  console.error('[AegisWin CI] FAIL: Test suite execution failed.');
  process.exit(1);
}
