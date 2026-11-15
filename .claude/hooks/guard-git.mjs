#!/usr/bin/env node
// Claude Code PreToolUse hook (Bash, PowerShell): refuses git commands that
// skip the repo's hooks or commit signing (AGENTS.md section 2).
//
// It reads the arguments of each git command in the line, so a flag that is
// only text (a commit message, a file body, a search pattern) is not refused.
// A shell is denied by default: every argument of a command that holds a shell
// name (sh, bash, zsh, pwsh, powershell, cmd) is read as a possible command.
// Only `sh|bash|zsh PATH ...` and `pwsh|powershell [-NoProfile|-NonInteractive|
// -NoLogo]... -File PATH ...` (PATH a plain token, nothing fed to stdin) are
// script runs whose later arguments are text (isScriptRun). Any other flag
// before the script, such as bash -x script.sh, is refused even when harmless.
// Not read: text piped into a shell (echo "..." | bash, cat <<EOF | bash), a
// command inside $(...) within a quoted argument, a command inside
// backticks within a quoted argument, a value set earlier with `export` or in
// the environment, an alias set with `git config alias.x ...`, and a script
// file's contents.
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
// Of those, the ones whose value may be the next argument (-S and -u only take an attached value).
const SEPARATE_VALUE_FLAGS = 'mFCct';
const COMMIT_LONG_VALUE_FLAGS = new Set(['--message', '--file', '--template', '--author', '--date', '--reuse-message', '--reedit-message']);
// Options of `git log` and `git grep` whose value is the next argument: a search text, not an option.
const SEARCH_VALUE_FLAGS = new Set(['--grep', '-S', '-G', '--author', '--committer']);
// core.hooksPath set to the repo's own hooks is what `git config` is allowed to do too.
const HOOKS_OK = /^(\.\/)?\.githooks\/?$/;
// Options of `git` itself whose value is the next argument.
const GIT_VALUE_FLAGS = new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace', '--exec-path']);

/** The command without the bodies of here-documents and PowerShell here-strings, which are text. */
function withoutBodies(command) {
  const text = command.replace(/@(['"])\r?\n[\s\S]*?\r?\n\1@/g, "''");
  const out = [];
  let until = null;
  let keep = false;
  for (const line of text.split(/\r?\n/)) {
    if (until !== null) {
      if (line.trim() === until) {
        until = null;
        keep = false;
      } else if (keep) {
        out.push(line);
      }
      continue;
    }
    out.push(line);
    // `<<<` is a here-string, not a here-document. A body fed to a shell is a script, so it stays.
    const here = line.match(/(?<!<)<<-?\s*(['"]?)([A-Za-z_]\w*)\1/);
    if (here) {
      until = here[2];
      if (commands(line.slice(0, here.index)).some((args) => args.some((a) => SHELLS.test(a)))) keep = true;
    }
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
    } else if (ch === '#' && arg === null) {
      // A comment runs to the end of the line.
      while (i + 1 < line.length && line[i + 1] !== '\n' && line[i + 1] !== '\r') i += 1;
    } else if (/\s/.test(ch) && ch !== '\n') {
      endArg();
    } else if (';&|()\n{}`'.includes(ch)) {
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

/** Why setting config `key` to `value` for one command (`-c`, GIT_CONFIG_*) is refused, or null. */
function configRefusal(key, value) {
  if (/^commit\.gpgsign$/i.test(key) && FALSE.test(value)) return `commit.gpgsign=false ${NO_SIGN}`;
  if (/^core\.hookspath$/i.test(key) && !HOOKS_OK.test(value)) return HOOKS_PATH;
  // An alias is a git command line (or, after `!`, a shell command line) that runs under another name.
  if (/^alias\./i.test(key)) {
    if (value.startsWith('!')) return why(value.slice(1), 1);
    return gitRefusal(commands(value)[0] ?? []);
  }
  return null;
}

/** Why GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n assignments in front of a command are refused, or null. */
function envRefusal(words) {
  const env = new Map(words.map((w) => w.match(/^(GIT_CONFIG_(?:KEY|VALUE)_\d+)=(.*)$/s)).filter(Boolean).map((m) => [m[1], m[2]]));
  for (const [name, key] of env) {
    const n = name.match(/^GIT_CONFIG_KEY_(\d+)$/)?.[1];
    const reason = n === undefined ? null : configRefusal(key, env.get(`GIT_CONFIG_VALUE_${n}`) ?? '');
    if (reason) return reason;
  }
  return null;
}

/** The options of a command: the arguments before `--`, minus the values of options that take the next argument. */
function optionsOf(sub, rest) {
  const end = rest.indexOf('--');
  const out = [];
  for (let i = 0; i < (end === -1 ? rest.length : end); i += 1) {
    const arg = rest[i];
    out.push(arg);
    let takes = false;
    if (sub === 'commit') {
      // A value flag that ends its group takes the next argument: `-m text`, `-am text`.
      const group = /^-[A-Za-z]+$/.test(arg) ? arg.slice(1) : '';
      const first = [...group].findIndex((f) => COMMIT_VALUE_FLAGS.includes(f));
      takes = COMMIT_LONG_VALUE_FLAGS.has(arg) || (first !== -1 && first === group.length - 1 && SEPARATE_VALUE_FLAGS.includes(group[first]));
    } else {
      takes = SEARCH_VALUE_FLAGS.has(arg) || (sub === 'grep' && arg === '-e');
    }
    if (takes) i += 1;
  }
  return out;
}

/** Why one git command (its arguments after `git`) is refused, or null. */
function gitRefusal(args) {
  let sub = null;
  let rest = [];
  // git's own options come before the subcommand: `-c key=value` sets a config value for this one command.
  for (let i = 0; i < args.length && sub === null; i += 1) {
    const arg = args[i];
    const inline = arg.match(/^--config-env=(.*)$/s);
    if (arg === '-c' || arg === '--config-env' || inline) {
      const setting = inline ? inline[1] : (args[i + 1] ?? '');
      const eq = setting.indexOf('=');
      const key = eq === -1 ? setting : setting.slice(0, eq);
      const value = eq === -1 ? '' : setting.slice(eq + 1);
      // --config-env names an environment variable for the value, which the guard cannot read.
      const reason = arg === '-c' ? configRefusal(key, value) : /^commit\.gpgsign$/i.test(key) ? `commit.gpgsign from an environment variable may turn signing off, which ${NO_SIGN}` : configRefusal(key, '');
      if (reason) return reason;
      if (!inline) i += 1;
    } else if (GIT_VALUE_FLAGS.has(arg)) {
      i += 1;
    } else if (!arg.startsWith('-')) {
      sub = arg;
      rest = args.slice(i + 1);
    }
  }
  if (sub === null) return null;

  const options = optionsOf(sub, rest);
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
      if (unset || (value !== undefined && !HOOKS_OK.test(value))) return HOOKS_PATH;
    }
    const sign = options.findIndex((a) => /^commit\.gpgsign$/i.test(a));
    if (sign !== -1 && (unset || FALSE.test(options[sign + 1] ?? ''))) return `turning commit.gpgsign off ${NO_SIGN}`;
  }
  return null;
}

// A script path with no quote, `$`, brace, glob or redirection character, not starting with - or +.
const PLAIN_PATH = /^[A-Za-z0-9_./][A-Za-z0-9_./\\:-]*$/;
const PS_VALUELESS_FLAGS = new Set(['-noprofile', '-noninteractive', '-nologo']);

/**
 * Whether a command is a shell running a script file, so that its later arguments are the script's
 * arguments and never a command. Anything else that holds a shell name is denied by default: the
 * guard reads every argument as a possible command. Only two forms are recognised, each the only
 * shell word on the command and the first word:
 *   sh|bash|zsh PATH ...                         (no flag at all, so the first argument is the script)
 *   pwsh|powershell [-NoProfile|-NonInteractive|-NoLogo]... -File PATH ...
 * PATH is a plain token (PLAIN_PATH). No later argument may contain `<`, so nothing feeds stdin.
 */
function isScriptRun(args) {
  if (!SHELLS.test(args[0]) || args.filter((a) => SHELLS.test(a)).length !== 1) return false;
  const name = args[0].replace(/^.*[\\/]/, '').replace(/\.exe$/i, '').toLowerCase();
  let i = 1;
  if (/^(pwsh|powershell)$/.test(name)) {
    while (i < args.length && PS_VALUELESS_FLAGS.has(args[i].toLowerCase())) i += 1;
    if (args[i]?.toLowerCase() !== '-file') return false;
    i += 1;
  } else if (!/^(sh|bash|zsh)$/.test(name)) {
    return false;
  }
  return PLAIN_PATH.test(args[i] ?? '') && !args.slice(i + 1).some((a) => a.includes('<'));
}

function why(command, depth) {
  for (const args of commands(withoutBodies(command))) {
    const git = args.findIndex((a) => GIT.test(a));
    if (git !== -1) {
      const reason = envRefusal(args.slice(0, git)) ?? gitRefusal(args.slice(git + 1));
      if (reason) return reason;
    }
    // A command handed to another shell as one argument, e.g. bash -c "git commit ...".
    if (depth < 2 && args.some((a) => SHELLS.test(a)) && !isScriptRun(args)) {
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
