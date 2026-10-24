import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PortableVault } from '../src/core/vault.mjs';
import { CentralLlmService } from '../src/core/llm-service.mjs';
import { PluginRegistry } from '../src/core/plugin-registry.mjs';
import { LocalMcpServer, FirewallPortManager } from '../src/core/mcp-server.mjs';

test('Async Background Job Runner: returns running state immediately for long-running tools and completes asynchronously', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-async13-'));
  try {
    const vault = new PortableVault(tmpDir);
    vault.unlockWithPin('778899');
    const llm = new CentralLlmService(vault);
    const registry = new PluginRegistry(vault, llm);

    registry.registerPlugin({
      manifest: {
        id: 'windows-health',
        name: 'Windows Health',
        version: '1.0.0',
        description: 'Health tools',
        tools: [
          {
            id: 'sfc_scan',
            name: 'SFC Scan',
            description: 'Long-running system file scan',
            requiresAdmin: true,
            defaultGatePolicy: 'pin_required',
          },
        ],
      },
      handlers: {
        sfc_scan: async () => {
          await new Promise((r) => setTimeout(r, 80));
          return { repaired: true, log: 'CBS.log updated' };
        },
      },
    });

    const mcpServer = new LocalMcpServer({
      vault,
      registry,
      firewallManager: new FirewallPortManager(() => 'Ok.'),
    });
    const status = await mcpServer.start(0);
    const baseUrl = `http://127.0.0.1:${status.port}`;
    const authKey = vault.getState().mcpConfig.authKey;

    const callRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authKey}` },
      body: JSON.stringify({
        method: 'tools/call',
        params: { name: 'windows-health:sfc_scan', arguments: { asyncExecution: true } },
      }),
    });
    const { result } = await callRes.json();

    // Approve with asyncExecution: true -> returns immediately with status 'running'
    const approveRes = await fetch(result.approvalUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision: 'accept', comment: 'Run SFC in background', pin: '778899' }),
    });
    const approveData = await approveRes.json();
    assert.equal(approveData.ticket.status, 'running');
    assert.ok(approveData.ticket.progressPercent >= 15);

    // Wait for background job completion and poll mcp:check_ticket
    await new Promise((r) => setTimeout(r, 140));
    const pollRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authKey}` },
      body: JSON.stringify({
        method: 'tools/call',
        params: { name: 'mcp:check_ticket', arguments: { ticketId: result.ticketId } },
      }),
    });
    const pollData = await pollRes.json();
    assert.equal(pollData.result.status, 'approved');
    assert.equal(pollData.result.progressPercent, 100);
    assert.deepEqual(pollData.result.result, { repaired: true, log: 'CBS.log updated' });

    await mcpServer.stop();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
