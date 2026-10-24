import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PortableVault } from '../src/core/vault.mjs';
import { CentralLlmService, isLanAddress } from '../src/core/llm-service.mjs';

test('CentralLlmService: accurately classifies On-LAN vs Off-LAN endpoints', () => {
  assert.equal(isLanAddress('http://127.0.0.1:11434/v1'), true);
  assert.equal(isLanAddress('http://localhost:1234/v1'), true);
  assert.equal(isLanAddress('http://192.168.1.50:11434/v1'), true);
  assert.equal(isLanAddress('http://10.0.0.12:8000/v1'), true);
  assert.equal(isLanAddress('http://172.20.10.2:11434/v1'), true);
  assert.equal(isLanAddress('http://ollama.local:11434/v1'), true);

  assert.equal(isLanAddress('https://api.openai.com/v1'), false);
  assert.equal(isLanAddress('https://openrouter.ai/api/v1'), false);
  assert.equal(isLanAddress('http://172.32.0.1:8080/v1'), false);
  assert.equal(isLanAddress('http://8.8.8.8/v1'), false);
});

test('CentralLlmService: enforces per-plugin Off-LAN trust prompt and scrubs PIN', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-llm-'));
  try {
    const vault = new PortableVault(tmpDir);
    vault.unlockWithPin('739104');

    let capturedBody = null;
    const mockTransport = async (_url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return {
        choices: [{ message: { content: 'Diagnosed Event ID 1000 successfully.' } }],
      };
    };

    const llm = new CentralLlmService(vault, mockTransport);

    const lanRes = await llm.analyze({
      pluginId: 'event-logs',
      userPrompt: 'Check log entry with accidental pin 739104',
    });
    assert.equal(lanRes.isOffLan, false);
    assert.ok(!capturedBody.messages[1].content.includes('739104'), 'PIN must be scrubbed from LLM payload');
    assert.ok(capturedBody.messages[1].content.includes('[REDACTED_PIN]'));

    vault.updateState((s) => {
      s.llmConfig.baseUrl = 'https://api.openai.com/v1';
      s.llmConfig.apiKey = 'sk-live-test-12345';
      return s;
    });

    await assert.rejects(
      () => llm.analyze({ pluginId: 'event-logs', userPrompt: 'Analyze crash dump' }),
      (err) => err.code === 'OFF_LAN_TRUST_REQUIRED' && err.details.pluginId === 'event-logs'
    );

    llm.grantPluginExternalTrust('event-logs');
    const offLanRes = await llm.analyze({ pluginId: 'event-logs', userPrompt: 'Analyze crash dump' });
    assert.equal(offLanRes.isOffLan, true);
    assert.equal(offLanRes.content, 'Diagnosed Event ID 1000 successfully.');

    await assert.rejects(
      () => llm.analyze({ pluginId: 'windows-health', userPrompt: 'Explain SFC output' }),
      (err) => err.code === 'OFF_LAN_TRUST_REQUIRED' && err.details.pluginId === 'windows-health'
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
