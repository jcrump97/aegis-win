import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const REQUIRED_DOCS = [
  'AGENTS.md',
  'CLAUDE.md',
  'documentation/GUIDING_PRINCIPLES.md',
  'documentation/ARCHITECTURE.md',
  'documentation/PLUGIN_SPEC.md',
  'documentation/SECURITY_MODEL.md',
  'documentation/AUDIT_LEDGER.md',
  'documentation/adr/0001-rust-core.md',
  'documentation/adr/0002-ai-monitor-creator.md',
  'documentation/adr/0003-action-plans.md',
  'documentation/adr/0004-approval-channel-and-key-hardening.md',
  'documentation/adr/0005-diagnose-this-pc.md',
];

test('Documentation Audit: all required agent and architecture docs exist and are non-empty', () => {
  for (const docPath of REQUIRED_DOCS) {
    assert.ok(fs.existsSync(docPath), `Missing required documentation file: ${docPath}`);
    const content = fs.readFileSync(docPath, 'utf8');
    assert.ok(content.length > 200, `Documentation file ${docPath} is unexpectedly short`);
  }
});

test('Documentation Audit: ARCHITECTURE.md contains system diagram and sequence diagrams', () => {
  const arch = fs.readFileSync('documentation/ARCHITECTURE.md', 'utf8');
  assert.match(arch, /AEGISWIN PORTABLE SINGLE EXECUTABLE/);
  assert.match(arch, /sequenceDiagram/);
  assert.match(arch, /pending_approval/);
  assert.match(arch, /OFF_LAN_TRUST_REQUIRED/);
});

test('Documentation Audit: SECURITY_MODEL.md enforces Zero-Knowledge PIN and AES-256-GCM standards', () => {
  const sec = fs.readFileSync('documentation/SECURITY_MODEL.md', 'utf8');
  assert.match(sec, /AES-256-GCM/);
  assert.match(sec, /PIN Non-Exposure Invariant/);
  assert.match(sec, /netsh advfirewall/);
});

test('Documentation Audit: ADR 0001 records the accepted Rust-core decision and is linked from the specs', () => {
  const adr = fs.readFileSync('documentation/adr/0001-rust-core.md', 'utf8');
  assert.match(adr, /\*\*Status\*\*: Accepted/);
  assert.match(adr, /## Migration plan/);
  for (const doc of ['documentation/ARCHITECTURE.md', 'documentation/PLUGIN_SPEC.md', 'documentation/SECURITY_MODEL.md', 'AGENTS.md', 'CLAUDE.md']) {
    assert.match(fs.readFileSync(doc, 'utf8'), /adr\/0001-rust-core\.md/, `${doc} must link ADR 0001`);
  }
});

test('Documentation Audit: agent docs list every commit prefix the hook allows and forbid AI attribution', () => {
  const hook = fs.readFileSync('.githooks/commit-msg', 'utf8');
  const prefixes = hook.match(/\((feat\|[a-z|]+)\)/)[1].split('|');
  assert.ok(prefixes.length >= 8, 'Expected the full prefix alternation from the hook');
  for (const doc of ['AGENTS.md', 'CLAUDE.md']) {
    const text = fs.readFileSync(doc, 'utf8');
    for (const p of prefixes) assert.ok(text.includes(`(${p})`), `${doc} must document the (${p}) prefix`);
    assert.match(text, /No AI Attribution/, `${doc} must state the no-AI-attribution rule`);
  }
});

test('Documentation Audit: README covers status, Windows dev setup, and the Claude acknowledgement', () => {
  const readme = fs.readFileSync('README.md', 'utf8');
  assert.match(readme, /adr\/0001-rust-core\.md/, 'README must point to the migration ADR in its status note');
  // Git does not clone core.hooksPath, so the README is the only place a new contributor learns to enable the hooks.
  assert.match(readme, /git config core\.hooksPath \.githooks/);
  for (const script of ['ci', 'dev', 'tauri:dev', 'tauri:build']) {
    assert.ok(readme.includes(`npm run ${script}`), `README must document npm run ${script}`);
  }
  assert.match(readme, /## Acknowledgements[\s\S]*Claude/, 'README must credit Claude under Acknowledgements');
});

test('Documentation Audit: ADR 0001 amendment defines the basic app and the MCP tool-name rule', () => {
  const adr = fs.readFileSync('documentation/adr/0001-rust-core.md', 'utf8');
  assert.match(adr, /## Amendment 1/);
  assert.match(adr, /Definition of "basic functioning app"/);
  // MCP clients reject tool names outside this pattern, so the colon form must not leak into MCP.
  assert.match(adr, /\^\[a-zA-Z0-9_-\]\{1,64\}\$/);
  const sec = fs.readFileSync('documentation/SECURITY_MODEL.md', 'utf8');
  assert.match(sec, /reveal_mcp_token/);
});

test('Documentation Audit: ADRs 0002 and 0003 are accepted and keep their trust rules', () => {
  const monitor = fs.readFileSync('documentation/adr/0002-ai-monitor-creator.md', 'utf8');
  assert.match(monitor, /\*\*Status\*\*: Accepted/);
  // Monitors only observe; the AI never activates anything.
  assert.match(monitor, /the AI proposes, code validates and describes, the owner approves with the PIN/);
  assert.match(monitor, /`activate_monitor` \| \*\*pin_required\*\*/);
  const plans = fs.readFileSync('documentation/adr/0003-action-plans.md', 'utf8');
  assert.match(plans, /\*\*Status\*\*: Accepted/);
  // One PIN approves exactly the stored plan, and the device page never asks for the PIN (ADR 0004 §1).
  assert.match(plans, /hashed with SHA-256/);
  assert.match(plans, /It never asks for the PIN\./);
  assert.match(plans, /one global serial executor/);
  // The device page cancels as the weaker caller, so a stolen page link cannot stop the owner's plans (#71).
  assert.match(plans, /The device page's cancel checks origin the same way, as the weaker caller/);
  assert.match(plans, /Its Decline, which needs no code, is limited the same way/);
  assert.doesNotMatch(plans, /Decline needs the PIN, as before/);
  assert.doesNotMatch(plans, /The device page's cancel does not check origin/);
  // Plugin data in the vault: own records only, and the store never replaces the gate.
  const spec = fs.readFileSync('documentation/PLUGIN_SPEC.md', 'utf8');
  assert.match(spec, /## 5\. Plugin Data in the Vault/);
  assert.match(spec, /\*\*Own records only\.\*\*/);
  assert.match(spec, /\*\*Gating is the tool's job\.\*\*/);
  for (const doc of [monitor, plans]) {
    assert.doesNotMatch(doc, /\*Recommendation:/, 'every open question records its decision');
  }
});

test('Documentation Audit: ADR 0004 is accepted and records every owner decision', () => {
  const adr = fs.readFileSync('documentation/adr/0004-approval-channel-and-key-hardening.md', 'utf8');
  assert.match(adr, /\*\*Status\*\*: Accepted/);
  for (const d of ['D1', 'D2', 'D3', 'D4', 'D5', 'D6']) assert.ok(adr.includes(`- **${d}. `) && new RegExp(String.raw`\*\*` + d + String.raw`\. [^*]+: \([ab]\)\.\*\*`).test(adr), `${d} is decided`);
  // The vault PIN never goes to a web page, and approval codes stay out of the vault lockout.
  assert.match(adr, /The vault PIN is never sent to a web page\./);
  assert.match(adr, /Wrong codes never count towards `PinGuard`\./);
  // A submission during apply is a conflict, and turning the feature off destroys a held code (#72, #73).
  assert.match(adr, /answered 409 "being applied": it costs no attempt and no hourly miss/);
  assert.match(adr, /destroys that code for good, even if the owner turns it on again before the decision finishes/);
  assert.match(adr, /The mark is cleared however the decision ends, a panic included/);
  const model = fs.readFileSync('documentation/SECURITY_MODEL.md', 'utf8');
  assert.match(model, /it cancels and declines as an agent would, and may stop or decline only requests and plans an agent made/);
  assert.match(model, /never given back, even if the owner turns it on again before that decision finishes/);
  // Wrong codes on the device page never end a plan only the app may end.
  assert.match(model, /on a plan the owner or the assistant wrote they only cancel the code, so the plan keeps waiting for the app/);
  assert.doesNotMatch(model, /3 wrong codes lock the ticket;/);
  assert.match(adr, /On a plan the owner or the assistant wrote, 3 wrong codes only cancel the code: the plan stays `pending_approval`/);
  assert.match(adr, /the page declines only requests and plans an agent made; a plan the owner or the assistant wrote is declined in the app/);
  assert.doesNotMatch(model, /The page's cancel does not check origin/);
  // §8: hardening is complete for 0.x; new security work needs a finding, new attack surface, or an outside review.
  assert.match(adr, /## 8\. Security scope after this ADR/);
  assert.match(adr, /\*\*Security hardening is complete for 0\.x\.\*\*/);
  for (const trigger of ['**A finding.**', '**New attack surface.**', '**An outside security review.**']) assert.ok(adr.includes(trigger), `§8 lists ${trigger}`);
  assert.match(fs.readFileSync('documentation/SECURITY_MODEL.md', 'utf8'), /security baseline for 0\.x\. .*\[ADR 0004 §8\]\(adr\/0004-approval-channel-and-key-hardening\.md\)/, 'SECURITY_MODEL points to the scope rule');
});

test('Documentation Audit: ADR 0005 keeps findings code-written and AI suggestions bound to them', () => {
  const adr = fs.readFileSync('documentation/adr/0005-diagnose-this-pc.md', 'utf8');
  assert.match(adr, /\*\*Status\*\*: Accepted/);
  assert.match(adr, /code finds, code describes, the AI ranks and explains, the owner approves with the PIN/);
  // Checks cannot write, record, or call an LLM; the AI can only pick tools code linked to a finding.
  assert.ok(adr.includes('It has **no** `PluginStore`, history handle, or `LlmHandle`.'), 'checks get no store, history, or LLM');
  assert.ok(adr.includes("appears in **that finding's own `next` list**"), 'AI steps are limited to code-linked tools');
  // Review fixes: the engine (not the plugin) enforces nextTools, and Diagnose cannot bypass a tightened read tool.
  assert.ok(adr.includes('**The engine, not the plugin, enforces `nextTools`.**'), 'engine enforces nextTools');
  assert.ok(adr.includes('**It follows the owner\'s gates, not only its own.**'), 'aegis__diagnose respects pin_required read tools');
  assert.ok(adr.includes('**One diagnosis at a time.**'), 'one diagnosis at a time');
  for (const d of ['D1', 'D2', 'D3', 'D4', 'D5']) assert.match(adr, new RegExp(String.raw`^- \*\*` + d + String.raw`\. .*\*\*Decided: \([ab]\)`, 'm'), `${d} is decided`);
  // Phase 1a: the plugin contract for checks is documented where plugin authors look.
  const spec = fs.readFileSync('documentation/PLUGIN_SPEC.md', 'utf8');
  assert.match(spec, /### 2\.4 Diagnose checks/);
  assert.ok(spec.includes('**The manifest is rejected at startup** unless every `nextTools` entry names a `planEligible` tool'), 'nextTools is validated at startup');
  assert.ok(spec.includes('**The engine, not the plugin, enforces the rest**'), 'the engine enforces next steps');
  assert.match(fs.readFileSync('documentation/ARCHITECTURE.md', 'utf8'), /### 2\.5 Diagnose this PC/);
  // Phase 2: the AI picks only among a finding's own next steps, and the engine keeps what was checked.
  assert.ok(adr.includes('**Review as plan** proposes the engine\'s copy, so the app never supplies the steps of an `Assistant` plan.'), 'the window never supplies AI steps');
  const sec = fs.readFileSync('documentation/SECURITY_MODEL.md', 'utf8');
  assert.match(sec, /Diagnose's own requests \(ADR 0005 §5\)\*\* use the reserved id `diagnose`/);
  assert.ok(spec.includes('`diagnose` for Diagnose\'s LLM requests'), 'PLUGIN_SPEC reserves diagnose');
  // Phase 1b: every check a plugin declares is documented in its README.
  for (const plugin of ['event-logs', 'usage-monitor']) {
    const readme = fs.readFileSync(`plugins/${plugin}/README.md`, 'utf8');
    assert.match(readme, /## Diagnose checks/, `${plugin} README documents its checks`);
    for (const check of JSON.parse(fs.readFileSync(`plugins/${plugin}/manifest.json`, 'utf8')).checks) {
      assert.ok(readme.includes(`\`${check.id}\``), `${plugin} README documents ${check.id}`);
    }
  }
});

test('Documentation Audit: agent docs keep the review and findings rules, and no doc describes removed behaviour', () => {
  // Findings are filed as issues, reviews come from a fresh session, and shared functions get a caller audit.
  for (const doc of ['AGENTS.md', 'CLAUDE.md']) {
    const text = fs.readFileSync(doc, 'utf8');
    for (const rule of ['Fresh-Session Review', 'File Every Finding', 'Caller Audit', 'Two-Actor Test', 'Fixes Start with a Failing Test']) {
      assert.ok(text.includes(`**${rule}**`), `${doc} must name the ${rule} rule`);
    }
  }
  // The rules are written once, in the file other AI tools look for, and CLAUDE.md loads it.
  assert.ok(!fs.existsSync('AGENT.md'), 'the singular name is gone');
  assert.match(fs.readFileSync('CLAUDE.md', 'utf8'), /^@AGENTS\.md\r?$/m, 'CLAUDE.md imports AGENTS.md on a line of its own');
  assert.doesNotMatch(fs.readFileSync('CLAUDE.md', 'utf8'), /\*\*Status:\*\*/, 'the issue format is not repeated in CLAUDE.md');
  assert.match(fs.readFileSync('AGENTS.md', 'utf8'), /\*\*Two-Actor Test\*\*/);
  assert.match(fs.readFileSync('README.md', 'utf8'), /filed as a \[GitHub issue\]/, 'README tells contributors where findings go');
  // Behaviour that was removed: the elevated helper, an approval link for agents, the PIN on a web page.
  const agent = fs.readFileSync('AGENTS.md', 'utf8');
  assert.doesNotMatch(agent, /--elevate-tool/);
  assert.doesNotMatch(agent, /returns an approval URL/);
  assert.match(agent, /No web page ever takes the PIN/);
  // The UI scale range is the one the engine enforces (80 to 150).
  assert.match(fs.readFileSync('crates/aegis-core/src/engine.rs', 'utf8'), /\(80\.\.=150\)\.contains\(&scale\)/);
  assert.match(agent, /`80%`–`150%`/);
  assert.match(fs.readFileSync('documentation/ARCHITECTURE.md', 'utf8'), /Dynamic Zoom: 80% - 150%/);
  assert.match(fs.readFileSync('documentation/GUIDING_PRINCIPLES.md', 'utf8'), /`--ui-scale: 0\.80` to `1\.50`/);
});

test('Documentation Audit: the guiding principles in AGENTS.md are numbered in order', () => {
  // Rendered Markdown renumbers a list, so an out-of-order source shows different numbers than it says (issue #28).
  const section = fs.readFileSync('AGENTS.md', 'utf8').split(/^## /m).find((s) => s.startsWith('1. Guiding Engineering Principles'));
  const numbers = [...section.matchAll(/^(\d+)\. \*\*/gm)].map((m) => Number(m[1]));
  assert.ok(numbers.length >= 7, 'the principles are found');
  assert.deepEqual(numbers, numbers.map((_, i) => i + 1));
});

test('Documentation Audit: the HPKE crate is pinned exactly and SECURITY_MODEL names the same version', () => {
  // The vault and history crypto crates move together, by hand (issue #94). A pin that drifts from the
  // documented version, or a default feature switched on (post-quantum KEM, ChaCha20-Poly1305), is a reviewed change.
  const manifest = fs.readFileSync('crates/aegis-core/Cargo.toml', 'utf8');
  const pin = manifest.match(/^hpke = \{ version = "=(\d+\.\d+\.\d+)", default-features = false, features = \["alloc", "x25519", "aes"\] \}\r?$/m);
  assert.ok(pin, 'hpke is pinned with "=", default features off, and only the alloc, x25519 and aes features');
  const sec = fs.readFileSync('documentation/SECURITY_MODEL.md', 'utf8');
  assert.ok(sec.includes('**pinned to exactly ' + pin[1] + '**, default features off, features `alloc`, `x25519` and `aes` only'), 'SECURITY_MODEL §10 names the pinned version and features');
  // aegis-core takes rand_core and x25519-dalek from hpke, so their versions cannot drift from it.
  assert.doesNotMatch(manifest, /^(rand_core|x25519-dalek) =/m);
  const lock = fs.readFileSync('Cargo.lock', 'utf8');
  const versions = [...lock.matchAll(/^name = "hpke"\r?\nversion = "([^"]+)"/gm)].map((m) => m[1]);
  assert.deepEqual(versions, [pin[1]], 'Cargo.lock has the pinned version, and only that one');
});

test('Documentation Audit: SECURITY_MODEL §10 names the file that holds each stored-format test', () => {
  // A reviewer checking a crypto bump follows these pointers, so each must lead to the test it names.
  const sec = fs.readFileSync('documentation/SECURITY_MODEL.md', 'utf8');
  const where = {
    vault: { doc: '(`vault.rs`, reading `crates/aegis-core/tests/fixtures/`)', tests: ['argon2id_output_matches_the_stored_known_answers', 'a_stored_format_2_vault_still_opens', 'a_stored_format_1_vault_still_opens'] },
    chain: { doc: 'HMAC known answers (`chain.rs`)', tests: ['the_ratchet_and_the_mac_match_known_answers'] },
    history: { doc: 'read back from its stored bytes (`history.rs`', tests: ['the_suite_matches_the_cfrg_known_answer_vector'] },
  };
  for (const [file, { doc, tests }] of Object.entries(where)) {
    assert.ok(sec.includes(doc), `SECURITY_MODEL §10 points to ${file}.rs`);
    const src = fs.readFileSync(`crates/aegis-core/src/${file}.rs`, 'utf8');
    for (const name of tests) assert.match(src, new RegExp(`fn ${name}\\(`), `${file}.rs holds ${name}`);
  }
});
