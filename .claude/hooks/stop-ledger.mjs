#!/usr/bin/env node
// Claude Code Stop hook: when code was changed but documentation/AUDIT_LEDGER.md
// was not, sends the session back once to update the ledger or to say why not
// (AGENTS.md section 2, Mandatory Documentation Audit). Looks at uncommitted
// changes only, and never blocks twice in a row.
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const CODE = /^(crates|plugins|src|src-tauri|launcher|scripts|\.githooks|\.github)\//;
const LEDGER = 'documentation/AUDIT_LEDGER.md';

/** The paths in `git status --porcelain` output. */
export function changedPaths(porcelain) {
  return porcelain
    .split(/\r?\n/)
    .filter((line) => line.length > 3)
    .map((line) => line.slice(3).split(' -> ').pop().replace(/^"|"$/g, ''));
}

/** Why the session should go on, or null when it may stop. */
export function reason(paths) {
  const code = paths.filter((p) => CODE.test(p));
  if (code.length === 0 || paths.includes(LEDGER)) return null;
  return `Code changed (${code.slice(0, 5).join(', ')}${code.length > 5 ? ', …' : ''}) but ${LEDGER} did not. Add the ledger row and update any spec in documentation/ the change affects. If the work is not finished yet, say what is left and stop again.`;
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  try {
    if (JSON.parse(input).stop_hook_active) return;
  } catch {
    // No input: check anyway.
  }
  let status;
  try {
    status = execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8', timeout: 8000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return;
  }
  const why = reason(changedPaths(status));
  if (why) console.log(JSON.stringify({ decision: 'block', reason: why }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
