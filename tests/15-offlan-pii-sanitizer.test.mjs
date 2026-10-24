import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PortableVault } from '../src/core/vault.mjs';
import { CentralLlmService, scrubHostAndPiiForOffLan } from '../src/core/llm-service.mjs';

test('Off-LAN PII & Host Sanitizer: redacts C:\Users\<Name>, UNC shares, and hostnames on Off-LAN calls while preserving on LAN', async () => {
  const sampleLog = 'Crash in C:\\Users\\jdoe_admin\\AppData\\Local\\App.exe reading \\\\CORP-NAS01\\FinanceShare\\db.mdb';
  const scrubbed = scrubHostAndPiiForOffLan(sampleLog);
  assert.ok(!scrubbed.includes('jdoe_admin'), 'Windows profile username must be redacted');
  assert.ok(scrubbed.includes('C:\\Users\\<REDACTED_USER>\\AppData'));
  assert.ok(!scrubbed.includes('CORP-NAS01'), 'UNC server name must be redacted');
  assert.ok(scrubbed.includes('\\\\<REDACTED_HOST>\\<REDACTED_SHARE>'));

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-pii15-'));
  try {
    const vault = new PortableVault(tmpDir);
    vault.unlockWithPin('909090');

    let lastSentPrompt = '';
    const llm = new CentralLlmService(vault, async (_url, opts) => {
      const body = JSON.parse(opts.body);
      lastSentPrompt = body.messages[1].content;
      return { choices: [{ message: { content: 'Clean analysis' } }] };
    });

    // 1. On-LAN keeps local paths intact for local Ollama debugging
    await llm.analyze({ pluginId: 'event-logs', userPrompt: sampleLog });
    assert.ok(lastSentPrompt.includes('jdoe_admin'));

    // 2. Off-LAN automatically scrubs profile paths and UNC shares even after plugin is trusted
    vault.updateState((s) => {
      s.llmConfig.baseUrl = 'https://api.openai.com/v1';
      return s;
    });
    llm.grantPluginExternalTrust('event-logs');
    const offLanRes = await llm.analyze({ pluginId: 'event-logs', userPrompt: sampleLog });
    assert.equal(offLanRes.piiScrubbed, true);
    assert.ok(!lastSentPrompt.includes('jdoe_admin'));
    assert.ok(lastSentPrompt.includes('<REDACTED_USER>'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
