import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PortableVault } from '../src/core/vault.mjs';
import { CentralLlmService } from '../src/core/llm-service.mjs';
import { PluginRegistry } from '../src/core/plugin-registry.mjs';
import { LocalMcpServer, FirewallPortManager } from '../src/core/mcp-server.mjs';

test('LocalMcpServer: opens firewall port, enforces Bearer auth, serves PIN approval web page, and never leaks PIN', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-mcp-'));
  const SECRET_PIN = '951753';
  const firewallCmds = [];

  try {
    const vault = new PortableVault(tmpDir);
    vault.unlockWithPin(SECRET_PIN);
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
            id: 'check_status',
            name: 'Check Status',
            description: 'Read status',
            requiresAdmin: false,
            defaultGatePolicy: 'auto',
          },
          {
            id: 'flush_dns',
            name: 'Flush DNS',
            description: 'Flushes DNS cache',
            requiresAdmin: false,
            defaultGatePolicy: 'pin_required',
          },
        ],
      },
      handlers: {
        check_status: async () => ({ healthy: true }),
        flush_dns: async () => ({ flushed: true, command: 'ipconfig /flushdns' }),
      },
    });

    const fw = new FirewallPortManager((cmd) => {
      firewallCmds.push(cmd);
      return 'Ok.';
    });

    const mcpServer = new LocalMcpServer({ vault, registry, firewallManager: fw });
    const status = await mcpServer.start(0);
    assert.equal(status.running, true);
    assert.ok(status.port > 0);
    assert.equal(firewallCmds.length, 1);
    assert.match(firewallCmds[0], /netsh advfirewall firewall add rule/);

    const baseUrl = `http://127.0.0.1:${status.port}`;
    const authKey = vault.getState().mcpConfig.authKey;

    const unauthRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'tools/list' }),
    });
    assert.equal(unauthRes.status, 401);

    const gatedCallRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authKey}`,
      },
      body: JSON.stringify({
        method: 'tools/call',
        params: { name: 'windows-health:flush_dns', arguments: { dryRun: false } },
      }),
    });
    const gatedData = await gatedCallRes.json();
    assert.equal(gatedData.result.status, 'pending_approval');
    assert.ok(gatedData.result.approvalUrl.startsWith(`${baseUrl}/approve/T-`));

    const htmlRes = await fetch(gatedData.result.approvalUrl);
    assert.equal(htmlRes.status, 200);
    const htmlText = await htmlRes.text();
    assert.match(htmlText, /Approve or Decline Requested Tool Execution/);
    assert.match(htmlText, /name="decision"/);
    assert.match(htmlText, /name="comment"/);
    assert.match(htmlText, /name="pin"/);

    const badPinRes = await fetch(gatedData.result.approvalUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision: 'accept', comment: 'Try wrong pin', pin: '000000' }),
    });
    assert.equal(badPinRes.status, 403);

    const goodPinRes = await fetch(gatedData.result.approvalUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        decision: 'accept',
        comment: 'Approved during maintenance window.',
        pin: SECRET_PIN,
      }),
    });
    assert.equal(goodPinRes.status, 200);
    const approvedBody = await goodPinRes.json();
    assert.equal(approvedBody.ticket.status, 'approved');
    assert.equal(approvedBody.ticket.userComment, 'Approved during maintenance window.');
    assert.deepEqual(approvedBody.ticket.result, { flushed: true, command: 'ipconfig /flushdns' });
    assert.ok(!JSON.stringify(approvedBody).includes(SECRET_PIN), 'PIN must never appear in response');

    await mcpServer.stop();
    assert.equal(firewallCmds.length, 2);
    assert.match(firewallCmds[1], /netsh advfirewall firewall delete rule/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
