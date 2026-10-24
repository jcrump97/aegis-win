import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PortableVault } from '../src/core/vault.mjs';
import { ElevationIpcBridge } from '../src/core/elevation-bridge.mjs';

test('ElevationIpcBridge: passes encrypted UAC jobs across integrity levels and rejects tampered job files', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-ipc14-'));
  try {
    const vault = new PortableVault(tmpDir);
    vault.unlockWithPin('314159');
    const bridge = new ElevationIpcBridge(vault);

    // 1. Standard user creates encrypted job for sfc_scan
    const job = bridge.createEncryptedJob({
      pluginId: 'windows-health',
      toolId: 'sfc_scan',
      args: { dryRun: false },
    });
    assert.match(job.uacCommand, /aegis-win\.exe --elevate-job JOB-/);

    // 2. Elevated instance executes job and writes signed encrypted response
    bridge.executeElevatedJobFile(job.jobId, (req) => ({
      executedTool: `${req.pluginId}:${req.toolId}`,
      integrityLevel: 'High (Administrator)',
    }));

    // 3. Standard user collects and cleans up job result
    const collected = bridge.collectJobResult(job.jobId, true);
    assert.equal(collected.output.executedTool, 'windows-health:sfc_scan');
    assert.equal(fs.existsSync(job.reqPath), false, 'Job files must be cleaned up after collection');

    // 4. Verify tamper detection if an attacker modifies the ciphertext on disk
    const tamperedJob = bridge.createEncryptedJob({
      pluginId: 'windows-health',
      toolId: 'winsock_reset',
    });
    const raw = JSON.parse(fs.readFileSync(tamperedJob.reqPath, 'utf8'));
    raw.ciphertext = raw.ciphertext.slice(0, -4) + 'ffff';
    fs.writeFileSync(tamperedJob.reqPath, JSON.stringify(raw), 'utf8');

    assert.throws(
      () => bridge.executeElevatedJobFile(tamperedJob.jobId, () => ({})),
      /TAMPER_DETECTED/
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
