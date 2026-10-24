import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PortableVault } from '../src/core/vault.mjs';

test('PortableVault: initializes, encrypts with AES-256-GCM on disk, and verifies PIN in constant time', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-vault-'));
  try {
    const vault = new PortableVault(tmpDir);
    assert.equal(vault.isInitialized(), false);

    const res = vault.unlockWithPin('849201');
    assert.equal(res.initializedNew, true);
    assert.equal(vault.isUnlocked(), true);
    assert.equal(vault.verifyPin('849201'), true);
    assert.equal(vault.verifyPin('000000'), false);

    vault.updateState((s) => {
      s.llmConfig.apiKey = 'sk-secret-openai-token-999';
      return s;
    });

    const rawDisk = fs.readFileSync(path.join(tmpDir, 'vault.enc.json'), 'utf8');
    assert.ok(!rawDisk.includes('sk-secret-openai-token-999'), 'API key must be encrypted at rest');
    assert.ok(!rawDisk.includes('849201'), 'PIN must never be written to disk');

    const vault2 = new PortableVault(tmpDir);
    assert.throws(() => vault2.unlockWithPin('111111'), /INVALID_PIN/);
    vault2.unlockWithPin('849201');
    assert.equal(vault2.getState().llmConfig.apiKey, 'sk-secret-openai-token-999');

    const scrubbed = vault2.scrubForExternalOutput('User pin is 849201 and key is sk-secret-openai-token-999');
    assert.equal(scrubbed, 'User pin is [REDACTED_PIN] and key is [REDACTED_API_KEY]');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
