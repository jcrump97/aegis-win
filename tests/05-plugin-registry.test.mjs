import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PortableVault } from '../src/core/vault.mjs';
import { CentralLlmService } from '../src/core/llm-service.mjs';
import { PluginRegistry } from '../src/core/plugin-registry.mjs';

test('PluginRegistry: manages first-run wizard selection and per-tool gate customization', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-reg-'));
  try {
    const vault = new PortableVault(tmpDir);
    vault.unlockWithPin('123456');
    const llm = new CentralLlmService(vault);
    const registry = new PluginRegistry(vault, llm);

    registry.registerPlugin({
      manifest: {
        id: 'sample-plugin',
        name: 'Sample Diagnostic Plugin',
        version: '1.0.0',
        description: 'Test plugin',
        tools: [
          {
            id: 'read_status',
            name: 'Read Status',
            description: 'Safe read tool',
            requiresAdmin: false,
            defaultGatePolicy: 'auto',
          },
          {
            id: 'repair_stack',
            name: 'Repair Stack',
            description: 'Mutating repair tool',
            requiresAdmin: true,
            defaultGatePolicy: 'pin_required',
          },
        ],
      },
      handlers: {
        read_status: async () => ({ ok: true, mode: 'read' }),
        repair_stack: async () => ({ ok: true, mode: 'repaired' }),
      },
    });

    registry.completeFirstRunSetup({
      selectedPlugins: ['sample-plugin'],
      selectedComponents: { 'usage-monitor:resource-spikes': true },
    });

    assert.equal(registry.isPluginInstalled('sample-plugin'), true);
    assert.equal(registry.getToolGatePolicy('sample-plugin', 'read_status'), 'auto');
    assert.equal(registry.getToolGatePolicy('sample-plugin', 'repair_stack'), 'pin_required');

    registry.setToolGatePolicy('sample-plugin', 'read_status', 'pin_required');
    assert.equal(registry.getToolGatePolicy('sample-plugin', 'read_status'), 'pin_required');

    const res = await registry.executeToolDirect('sample-plugin', 'read_status', {});
    assert.deepEqual(res, { ok: true, mode: 'read' });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
