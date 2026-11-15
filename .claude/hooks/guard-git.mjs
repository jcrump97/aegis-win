#!/usr/bin/env node
// Claude Code PreToolUse hook (Bash, PowerShell): refuses git commands that
// skip the repo's hooks or commit signing (AGENT.md section 2).
import { pathToFileURL } from 'node:url';

const SKIPS = [
  [/--no-verify\b/, '--no-verify skips the commit-msg and pre-commit hooks'],
  [/--no-gpg-sign\b/, '--no-gpg-sign makes an unsigned commit'],
  [/commit\.gpgsign\s*=\s*false/i, 'commit.gpgsign=false makes an unsigned commit'],
  [/core\.hooksPath\s*=/i, 'overriding core.hooksPath skips the repo hooks'],
];

/** Why the command is refused, or null when it may run. */
export function refusal(command) {
  if (typeof command !== 'string' || !/\bgit\b/.test(command)) return null;
  const hit = SKIPS.find(([pattern]) => pattern.test(command));
  return hit ? `Refused: ${hit[1]}. If a hook fails, fix what it reports (AGENT.md section 2). Only the maintainer may bypass it, by running the command themselves.` : null;
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  let command;
  try {
    command = JSON.parse(input).tool_input?.command;
  } catch {
    return;
  }
  const reason = refusal(command);
  if (reason) {
    console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
