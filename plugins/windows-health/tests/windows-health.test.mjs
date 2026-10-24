import test from 'node:test';
import assert from 'node:assert/strict';
import { windowsHealthPlugin } from '../index.mjs';

test('Plugin [windows-health]: enforces dry-run warnings, standard-user elevation checks, and admin execution', async () => {
  // 1. Flush DNS works as standard user
  const dnsRes = await windowsHealthPlugin.handlers.flush_dns({ dryRun: false }, { isElevatedAdmin: false });
  assert.equal(dnsRes.executed, true);
  assert.match(dnsRes.output, /Successfully flushed the DNS Resolver Cache/);

  // 2. IP release/renew dryRun warns about transient socket disconnect
  const ipDry = await windowsHealthPlugin.handlers.ip_release_renew({ dryRun: true });
  assert.equal(ipDry.dryRun, true);
  assert.match(ipDry.impactWarning, /Temporarily drops active TCP\/UDP sockets/);

  // 3. SFC scan as standard user prompts for self-elevation
  const sfcStd = await windowsHealthPlugin.handlers.sfc_scan({ dryRun: false }, { isElevatedAdmin: false });
  assert.equal(sfcStd.executed, false);
  assert.equal(sfcStd.requiresElevation, true);
  assert.match(sfcStd.selfElevationCommand, /--elevate-tool windows-health:sfc_scan/);

  // 4. SFC scan & Winsock reset as elevated admin execute cleanly
  const sfcAdm = await windowsHealthPlugin.handlers.sfc_scan({ dryRun: false }, { isElevatedAdmin: true });
  assert.equal(sfcAdm.executed, true);
  assert.match(sfcAdm.output, /Windows Resource Protection found corrupt files/);

  const wsAdm = await windowsHealthPlugin.handlers.winsock_reset({ dryRun: false }, { isElevatedAdmin: true });
  assert.equal(wsAdm.executed, true);
  assert.equal(wsAdm.rebootRequired, true);
});
