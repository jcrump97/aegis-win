import test from 'node:test';
import assert from 'node:assert/strict';
import { usageMonitorPlugin } from '../index.mjs';

test('Plugin [usage-monitor]: respects modular sub-component selection and correlates resource spikes with crashes', async () => {
  await usageMonitorPlugin.handlers.configure_watch_window({
    startTime: '02:00',
    endTime: '04:00',
    cpuThresholdPercent: 90,
  });

  // 1. All 3 components enabled
  const fullSnap = await usageMonitorPlugin.handlers.capture_diagnostic_snapshot(
    {},
    {
      installedComponents: {
        'usage-monitor:resource-spikes': true,
        'usage-monitor:crash-correlator': true,
        'usage-monitor:active-window': true,
      },
    }
  );
  assert.equal(fullSnap.enabledSubComponents.length, 3);
  assert.ok(fullSnap.clues.resourceSpikes);
  assert.ok(fullSnap.clues.correlatedCrashEvents);
  assert.ok(fullSnap.clues.foregroundWindowTimeline);

  // 2. Only resource-spikes enabled (user opted out of active-window tracking on first run)
  const partialSnap = await usageMonitorPlugin.handlers.capture_diagnostic_snapshot(
    {},
    {
      installedComponents: {
        'usage-monitor:resource-spikes': true,
        'usage-monitor:crash-correlator': false,
        'usage-monitor:active-window': false,
      },
    }
  );
  assert.deepEqual(partialSnap.enabledSubComponents, ['usage-monitor:resource-spikes']);
  assert.ok(partialSnap.clues.resourceSpikes);
  assert.equal(partialSnap.clues.foregroundWindowTimeline, undefined);
});
