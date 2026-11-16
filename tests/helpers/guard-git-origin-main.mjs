#!/usr/bin/env node
// Claude Code PreToolUse hook (Bash, PowerShell): refuses git commands that
// skip the repo's hooks or commit signing (AGENTS.md section 2).
//
// It reads the arguments of each git command in the line, so a flag that is
// only text (a commit message, a file body, a search pattern) is not refused.
// It is a reminder for a session, not a security boundary: CI checks commit
// messages again (scripts/check-commit-messages.mjs).
import { pathToFileURL } from 'node:url';

const NO_VERIFY = 'skips the commit-msg and pre-commit hooks';
const NO_SIGN = 'makes an unsigned commit';
const HOOKS_PATH = 'pointing core.hooksPath away from .githooks skips the repo hooks';
const SHELLS = /^(.*[\\/])?(sh|bash|zsh|pwsh|powershell|cmd)(\.exe)?$/i;
const GIT = /^(.*[\\/])?git(\.exe)?$/i;
const FALSE = /^(false|no|off|0)$/i;
// Short options of `git commit` that take a value: the rest of the group is that value.
const COMMIT_VALUE_FLAGS = 'mFCctSu';
// Options of `git` itself whose value is the next argument.
const GIT_VALUE_FLAGS = new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--config-env']);

/** The command without the bodies of here-documents and PowerShell here-strings, which are text. */
function withoutBodies(command) {
  const text = command.replace(/@(['"])\r?\n[\s\S]*?\r?\n\1@/g, "''");
  const out = [];
  let until = null;
  for (const line of text.split(/\r?\n/)) {
    if (until !== null) {
      if (line.trim() === until) until = null;
      continue;
    }
    out.push(line);
    const here = line.match(/<<-?\s*(['"]?)([A-Za-z_]\w*)\1/);
    if (here) until = here[2];
  }
  return out.join('\n');
}

/** The commands in a shell line, each a list of arguments with the quotes removed. */
export function commands(line) {
  const all = [];
  let args = [];
  let arg = null;
  const endArg = () => {
    if (arg !== null) args.push(arg);
    arg = null;
  };
  const endCommand = () => {
    endArg();
    if (args.length > 0) all.push(args);
    args = [];
  };
  let quote = null;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    const next = line[i + 1];
    if (quote) {
      if (ch === quote) {
        if (quote === "'" && next === "'") {
          arg += "'";
          i += 1;
        } else {
          quote = null;
        }
      } else if (quote === '"' && next !== undefined && (ch === '`' || (ch === '\\' && '"\\$`'.includes(next)))) {
        // An escaped character. A backslash before anything else is itself, as in a Windows path.
        arg += next;
        i += 1;
      } else {
        arg += ch;
      }
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      arg ??= '';
    } else if ((ch === '\\' || ch === '`') && (next === '\n' || next === '\r')) {
      i += next === '\r' && line[i + 2] === '\n' ? 2 : 1; // A continued line.
    } else if (ch === '\\' && (next === '"' || next === "'")) {
      arg = (arg ?? '') + next;
      i += 1;
    } else if (/\s/.test(ch) && ch !== '\n') {
      endArg();
    } else if (';&|()\n{}'.includes(ch)) {
      endCommand();
    } else {
      arg = (arg ?? '') + ch;
    }
  }
  endCommand();
  return all;
}

/** `long` or a shortened form of it that git still accepts, e.g. --no-verif. */
function isLong(arg, long) {
  return arg.length >= 6 && long.startsWith(arg);
}

/** Why one git command (its arguments after `git`) is refused, or null. */
function gitRefusal(args) {
  let sub = null;
  let rest = [];
  // git's own options come before the subcommand: `-c key=value` sets a config value for this one command.
  for (let i = 0; i < args.length && sub === null; i += 1) {
    const arg = args[i];
    if (arg === '-c') {
      const [key, value = ''] = (args[i + 1] ?? '').split('=');
      if (/^commit\.gpgsign$/i.test(key) && FALSE.test(value)) return `commit.gpgsign=false ${NO_SIGN}`;
      if (/^core\.hookspath$/i.test(key)) return HOOKS_PATH;
      i += 1;
    } else if (GIT_VALUE_FLAGS.has(arg)) {
      i += 1;
    } else if (!arg.startsWith('-')) {
      sub = arg;
      rest = args.slice(i + 1);
    }
  }
  if (sub === null) return null;

  const end = rest.indexOf('--');
  const options = end === -1 ? rest : rest.slice(0, end);
  for (const arg of options) {
    if (isLong(arg, '--no-verify')) return `--no-verify ${NO_VERIFY}`;
    if (isLong(arg, '--no-gpg-sign')) return `--no-gpg-sign ${NO_SIGN}`;
  }

  if (sub === 'commit') {
    for (const arg of options) {
      if (!/^-[A-Za-z]/.test(arg)) continue;
      for (const flag of arg.slice(1)) {
        if (flag === 'n') return `-n (the short form of --no-verify) ${NO_VERIFY}`;
        if (COMMIT_VALUE_FLAGS.includes(flag)) break;
      }
    }
  }

  if (sub === 'config') {
    const unset = options.some((a) => a === 'unset' || a === '--unset' || a === '--unset-all');
    const hooks = options.findIndex((a) => /^core\.hookspath$/i.test(a));
    if (hooks !== -1) {
      const value = options[hooks + 1];
      if (unset || (value !== undefined && !/^(\.\/)?\.githooks\/?$/.test(value))) return HOOKS_PATH;
    }
    const sign = options.findIndex((a) => /^commit\.gpgsign$/i.test(a));
    if (sign !== -1 && (unset || FALSE.test(options[sign + 1] ?? ''))) return `turning commit.gpgsign off ${NO_SIGN}`;
  }
  return null;
}

function why(command, depth) {
  for (const args of commands(withoutBodies(command))) {
    const git = args.findIndex((a) => GIT.test(a));
    if (git !== -1) {
      const reason = gitRefusal(args.slice(git + 1));
      if (reason) return reason;
    }
    // A command handed to another shell as one argument, e.g. bash -c "git commit ...".
    if (depth < 2 && args.some((a) => SHELLS.test(a))) {
      for (const arg of args) {
        const reason = /\s/.test(arg) ? why(arg, depth + 1) : null;
        if (reason) return reason;
      }
    }
  }
  return null;
}

/** Why the command is refused, or null when it may run. */
export function refusal(command) {
  if (typeof command !== 'string' || !/\bgit\b/i.test(command)) return null;
  const reason = why(command, 0);
  return reason ? `Refused: ${reason}. If a hook fails, fix what it reports (AGENTS.md section 2). Only the maintainer may bypass it, by running the command themselves.` : null;
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
