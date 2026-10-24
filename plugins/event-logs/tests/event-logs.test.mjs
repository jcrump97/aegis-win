import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PortableVault } from '../../../src/core/vault.mjs';
import { CentralLlmService } from '../../../src/core/llm-service.mjs';
import { eventLogsPlugin } from '../index.mjs';

test('Plugin [event-logs]: queries logs, filters by Event ID 1000, guards Security channel when non-admin, and integrates with LLM', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-evlog-'));
  try {
    const vault = new PortableVault(tmpDir);
    vault.unlockWithPin('445566');
    const llm = new CentralLlmService(vault, async () => ({
      choices: [{ message: { content: 'Fault in SearchIndexer.exe caused by corrupted index.' } }],
    }));

    // 1. Standard user querying Application Error logs
    const appLogs = await eventLogsPlugin.handlers.query_logs(
      { channel: 'Application', severity: 'Error', limit: 10 },
      { isElevatedAdmin: false }
    );
    assert.equal(appLogs.count, 2);
    assert.match(appLogs.nativeCommand, /wevtutil qe "Application"/);

    // 2. Standard user querying Security channel gets graceful elevation guidance
    const secLogs = await eventLogsPlugin.handlers.query_logs(
      { channel: 'Security' },
      { isElevatedAdmin: false }
    );
    assert.equal(secLogs.requiresElevation, true);
    assert.match(secLogs.elevationCommand, /--elevate-tool event-logs:query_logs/);

    // 3. Filter by Event ID 1000
    const filtered = await eventLogsPlugin.handlers.filter_by_event_id({ channel: 'Application', eventId: 1000 });
    assert.equal(filtered.count, 1);
    assert.equal(filtered.events[0].processName, 'SearchIndexer.exe');

    // 4. Analyze with LLM
    const aiRes = await eventLogsPlugin.handlers.analyze_logs_with_llm(
      { events: filtered.events },
      { llmService: llm }
    );
    assert.equal(aiRes.analyzedEventCount, 1);
    assert.match(aiRes.diagnosis, /SearchIndexer\.exe/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
