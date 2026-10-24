import test from 'node:test';
import assert from 'node:assert/strict';
import { FirewallPortManager } from '../src/core/mcp-server.mjs';

test('FirewallPortManager: skips unnecessary netsh elevation on loopback (127.0.0.1) and provides UAC elevation command for LAN (0.0.0.0) when non-admin', () => {
  const executedCmds = [];
  const fw = new FirewallPortManager((cmd) => {
    executedCmds.push(cmd);
    return 'Ok.';
  });

  // 1. Loopback bind (127.0.0.1) under standard user (`asInvoker`) -> no netsh needed!
  const loopRes = fw.openPortForBind({ host: '127.0.0.1', port: 47821, isElevatedAdmin: false });
  assert.equal(loopRes.loopbackBypass, true);
  assert.equal(loopRes.requiresElevation, false);
  assert.equal(executedCmds.length, 0, 'Loopback bind must not invoke netsh advfirewall');

  // 2. LAN bind (0.0.0.0) under standard user (`asInvoker`) -> flags one-time UAC elevation command
  const lanStdRes = fw.openPortForBind({ host: '0.0.0.0', port: 47821, isElevatedAdmin: false });
  assert.equal(lanStdRes.opened, false);
  assert.equal(lanStdRes.requiresElevation, true);
  assert.match(lanStdRes.elevationCommand, /--elevate-firewall-port 47821/);

  // 3. LAN bind (0.0.0.0) under elevated admin -> executes netsh rule
  const lanAdmRes = fw.openPortForBind({ host: '0.0.0.0', port: 47821, isElevatedAdmin: true });
  assert.equal(lanAdmRes.opened, true);
  assert.equal(executedCmds.length, 1);
});
