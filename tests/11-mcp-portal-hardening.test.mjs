import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { PortableVault } from '../src/core/vault.mjs';
import { CentralLlmService } from '../src/core/llm-service.mjs';
import { PluginRegistry } from '../src/core/plugin-registry.mjs';
import { LocalMcpServer, FirewallPortManager } from '../src/core/mcp-server.mjs';

test('MCP Portal Hardening: blocks DNS rebinding Host headers, validates CSRF nonces, and locks out ticket after 3 failed PIN attempts', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-sec11-'));
  try {
    const vault = new PortableVault(tmpDir);
    vault.unlockWithPin('654321');
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
            id: 'winsock_reset',
            name: 'Reset Winsock',
            description: 'Reset network catalog',
            requiresAdmin: true,
            defaultGatePolicy: 'pin_required',
          },
        ],
      },
      handlers: {
        winsock_reset: async () => ({ reset: true }),
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

    // 1. Verify DNS Rebinding attack with spoofed Host header is blocked with 403
    const rebindStatus = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: status.port,
          path: '/mcp',
          method: 'POST',
          headers: {
            Host: 'evil-rebind.attacker.com',
            'Content-Type': 'application/json',
          },
        },
        (res) => resolve(res.statusCode)
      );
      req.on('error', reject);
      req.end(JSON.stringify({ method: 'tools/list' }));
    });
    assert.equal(rebindStatus, 403, 'Spoofed Host header must be rejected with 403');

    // 2. Create a gated ticket
    const callRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authKey}`,
      },
      body: JSON.stringify({
        method: 'tools/call',
        params: { name: 'windows-health:winsock_reset', arguments: {} },
      }),
    });
    const { result } = await callRes.json();
    const approvalUrl = result.approvalUrl;

    // 3. Extract CSRF token from approval HTML
    const pageHtml = await (await fetch(approvalUrl)).text();
    const csrfMatch = pageHtml.match(/name="csrfToken" value="([a-f0-9]+)"/);
    assert.ok(csrfMatch, 'Approval page must embed a hidden csrfToken');
    const validCsrf = csrfMatch[1];

    // 4. Forged CSRF token must be rejected with 403 without burning a PIN attempt
    const badCsrfRes = await fetch(approvalUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        csrfToken: 'forged_token_000',
        decision: 'accept',
        pin: '654321',
      }),
    });
    assert.equal(badCsrfRes.status, 403);

    // 5. Three wrong PIN attempts must lock out the ticket permanently (423 Locked)
    const attempt1 = await fetch(approvalUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrfToken: validCsrf, decision: 'accept', pin: '000001' }),
    });
    assert.equal(attempt1.status, 403);

    const attempt2 = await fetch(approvalUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrfToken: validCsrf, decision: 'accept', pin: '000002' }),
    });
    assert.equal(attempt2.status, 403);

    const attempt3 = await fetch(approvalUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrfToken: validCsrf, decision: 'accept', pin: '000003' }),
    });
    assert.equal(attempt3.status, 423, 'Third failed PIN attempt must lock out the ticket with HTTP 423');

    // 6. Even with the CORRECT PIN afterwards, the locked-out ticket must remain rejected (423)
    const afterLockout = await fetch(approvalUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrfToken: validCsrf, decision: 'accept', pin: '654321' }),
    });
    assert.equal(afterLockout.status, 423);

    await mcpServer.stop();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
