#!/usr/bin/env node
/**
 * Checks commit messages the way .githooks/commit-msg does, for commits made
 * in a clone where the hooks were never turned on (git does not clone
 * core.hooksPath). CI runs it over a pull request's commits.
 *
 *   node scripts/check-commit-messages.mjs <base>..<head>
 *   BASE_SHA=... HEAD_SHA=... [PR_BODY=...] node scripts/check-commit-messages.mjs
 *
 * Merge commits are skipped. tests/17-contributor-process.test.mjs keeps the
 * two patterns below equal to the hook's.
 */
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const PREFIXES = ['feat', 'fix', 'doc', 'chore', 'test', 'refactor', 'security', 'perf'];
export const ATTRIBUTION_PATTERN = '^co-authored-by:.*(claude|anthropic|copilot|gemini|openai|chatgpt)|generated with \\[?(claude|copilot|gemini|chatgpt)';

const subject = new RegExp(`^\\((${PREFIXES.join('|')})\\) .+`);
const attribution = new RegExp(ATTRIBUTION_PATTERN, 'im');

/** The problems with one commit message; empty when it is fine. */
export function checkMessage(message) {
  const problems = [];
  const first = message.split(/\r?\n/, 1)[0];
  if (!subject.test(first)) problems.push(`must start with a type tag, e.g. "(fix) Describe the change" (got: ${first})`);
  if (attribution.test(message)) problems.push('carries an AI attribution trailer or footer (credit goes in the README)');
  return problems;
}

/** A pull request description may not carry an attribution footer either. */
export function checkPrBody(body) {
  return attribution.test(body ?? '') ? ['the pull request description carries an AI attribution footer (credit goes in the README)'] : [];
}

function main() {
  const range = process.argv[2] ?? (process.env.BASE_SHA && process.env.HEAD_SHA ? `${process.env.BASE_SHA}..${process.env.HEAD_SHA}` : null);
  if (!range || !/^[\w./~^-]+\.\.[\w./~^-]+$/.test(range)) {
    console.error('Usage: node scripts/check-commit-messages.mjs <base>..<head>');
    process.exit(2);
  }
  const log = execFileSync('git', ['log', '--no-merges', '--format=%H%x00%B%x01', range], { encoding: 'utf8' });
  const commits = log.split('\x01').map((c) => c.trim()).filter(Boolean);
  let failed = 0;
  for (const commit of commits) {
    const [hash, message = ''] = commit.split('\x00');
    for (const problem of checkMessage(message.trim())) {
      console.error(`[commit ${hash.slice(0, 7)}] ${problem}`);
      failed += 1;
    }
  }
  for (const problem of checkPrBody(process.env.PR_BODY)) {
    console.error(`[pull request] ${problem}`);
    failed += 1;
  }
  if (failed > 0) process.exit(1);
  console.log(`[AegisWin CI] ${commits.length} commit message(s) checked.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
