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
