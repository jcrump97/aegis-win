import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const REQUIRED_DOCS = [
  'AGENT.md',
  'CLAUDE.md',
  'documentation/GUIDING_PRINCIPLES.md',
  'documentation/ARCHITECTURE.md',
  'documentation/PLUGIN_SPEC.md',
  'documentation/SECURITY_MODEL.md',
  'documentation/AUDIT_LEDGER.md',
  'documentation/adr/0001-rust-core.md',
  'documentation/adr/0002-ai-monitor-creator.md',
  'documentation/adr/0003-action-plans.md',
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
  for (const doc of ['documentation/ARCHITECTURE.md', 'documentation/PLUGIN_SPEC.md', 'documentation/SECURITY_MODEL.md', 'AGENT.md', 'CLAUDE.md']) {
    assert.match(fs.readFileSync(doc, 'utf8'), /adr\/0001-rust-core\.md/, `${doc} must link ADR 0001`);
  }
});

test('Documentation Audit: agent docs list every commit prefix the hook allows and forbid AI attribution', () => {
  const hook = fs.readFileSync('.githooks/commit-msg', 'utf8');
  const prefixes = hook.match(/\((feat\|[a-z|]+)\)/)[1].split('|');
  assert.ok(prefixes.length >= 8, 'Expected the full prefix alternation from the hook');
  for (const doc of ['AGENT.md', 'CLAUDE.md']) {
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
  // One PIN approves exactly the stored plan, and the browser page never skips the PIN.
  assert.match(plans, /hashed with SHA-256/);
  assert.match(plans, /It always requires the PIN\./);
  assert.match(plans, /one global serial executor/);
  // Plugin data in the vault: own records only, and the store never replaces the gate.
  const spec = fs.readFileSync('documentation/PLUGIN_SPEC.md', 'utf8');
  assert.match(spec, /## 5\. Plugin Data in the Vault/);
  assert.match(spec, /\*\*Own records only\.\*\*/);
  assert.match(spec, /\*\*Gating is the tool's job\.\*\*/);
  for (const doc of [monitor, plans]) {
    assert.doesNotMatch(doc, /\*Recommendation:/, 'every open question records its decision');
  }
});
