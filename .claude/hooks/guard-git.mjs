#!/usr/bin/env node
// Claude Code PreToolUse hook (Bash, PowerShell): refuses git commands that
// skip the repo's hooks or commit signing (AGENTS.md section 2).
//
// Two readings, so the guard is at least as strict as before by construction:
//  - A line that is not "plain" (isPlain below: anything but ASCII letters,
//    digits, blanks and a few punctuation marks, any shell or launcher word,
//    unbalanced or doubled quotes) gets origin/main's rule unchanged
//    (guard-git-strict.mjs).
//  - A plain line is read by the parser below, which reads the arguments of
//    each git command, so a flag that is only text (a message or search value,
//    a `#` comment after a blank) is not refused. That is all of issue #34 that
//    is delivered: for a line with any other character it stays refused.
// The parser also runs on every line and only adds refusals: --config-env, a
// GIT_CONFIG_KEY_n assignment, a `-c alias.x=...`, a backtick as a command
// separator, a here-document fed to a shell, a here-string (issue #32).
// Not read, each tracked in an issue:
//   #66  text piped into a shell (echo "..." | bash, cat <<EOF | bash), and a
//        PowerShell here-string after -Command
//   #67  an alias whose flag is added at the call, GIT_CONFIG_PARAMETERS,
//        GIT_CONFIG_GLOBAL, $env: assignments, eval
//   #70  a command inside $(...) or backticks within a quoted argument outside
//        a shell's arguments, git config alias.x, values set earlier with
//        `export`, a script file's contents
//   #81  a PowerShell -EncodedCommand (base64) command
//   #90  other interpreters and launchers (dash, ksh, fish, python -c,
//        node -e, env -S, watch, ssh, iex, Start-Process)
//   #93  a quote the reader mis-tracks (bash $'a\'b', a PowerShell
//        backtick-quote), which hides the rest of the line
// It is a reminder for a session, not a security boundary: CI checks commit
// messages again (scripts/check-commit-messages.mjs).
import { pathToFileURL } from 'node:url';
import { strictRefusal } from './guard-git-strict.mjs';

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
// Options whose value is the next argument (a search text or a name, not an option), by subcommand.
// Elsewhere -S is --gpg-sign with an attached value only, so `merge -S --no-verify` has a real option.
const SEARCH_VALUE_FLAGS = new Map([
  ['--grep', ['log', 'rev-list']],
  ['-S', ['log', 'diff', 'show', 'grep', 'reflog']],
  ['-G', ['log', 'diff', 'show', 'grep', 'reflog']],
  ['--author', ['log', 'rev-list']],
  ['--committer', ['log', 'rev-list']],
]);
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
    } else if (ch === '#' && arg === null && (i === 0 || ' \t\n'.includes(line[i - 1]))) {
      // A comment starts only at a word start after an ASCII blank or at a line start, and runs to the end of the line.
      // (Only a plain line relies on this; any other line is also read by the strict rule.)
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
    if (value.startsWith('!')) return why(value.slice(1));
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
      takes = SEARCH_VALUE_FLAGS.get(arg)?.includes(sub) === true || (sub === 'grep' && arg === '-e');
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

/** Why the parser refuses the line, or null. It reads every git command's arguments; it does not read a shell's. */
function why(command) {
  for (const args of commands(withoutBodies(command))) {
    const git = args.findIndex((a) => GIT.test(a));
    if (git !== -1) {
      const reason = envRefusal(args.slice(0, git)) ?? gitRefusal(args.slice(git + 1));
      if (reason) return reason;
    }
  }
  return null;
}

// The only characters a plain line holds: ASCII letters, digits, space, tab, newline and `- _ . / : = , + ' " ; & | #`.
// Backtick, backslash, `$`, brackets, `< >`, `%`, `^`, `!`, `*`, `?`, `~`, `@`, non-ASCII and control characters are not here.
const PLAIN_CHARS = /^[A-Za-z0-9 \t\n\-_./:=,+'";&|#]*$/;
// A shell, or a program that runs a command line, anywhere in the line.
const SHELL_WORD = /(?<![A-Za-z0-9_])(?:sh|bash|zsh|dash|ksh|fish|csh|tcsh|nu|xonsh|pwsh|powershell|cmd|env|sudo|eval|exec|xargs|watch|ssh|iex|invoke-expression|start-process|python\d*|node|perl|ruby|command|builtin)(?![A-Za-z0-9_])/i;

/**
 * Whether a line is plain enough for the parser's reading to stand alone. Its quotes must be balanced
 * with no doubled quote (`''` and `""` mean different things to bash and PowerShell).
 */
export function isPlain(line) {
  if (!PLAIN_CHARS.test(line) || SHELL_WORD.test(line) || /''|""/.test(line)) return false;
  let quote = null;
  for (const ch of line) {
    if (quote === null && (ch === "'" || ch === '"')) quote = ch;
    else if (ch === quote) quote = null;
  }
  return quote === null;
}

/** Why the command is refused, or null when it may run. */
export function refusal(command) {
  if (typeof command !== 'string' || !/\bgit\b/i.test(command)) return null;
  const parsed = why(command);
  if (parsed === null && !isPlain(command)) return strictRefusal(command);
  const reason = parsed;
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
