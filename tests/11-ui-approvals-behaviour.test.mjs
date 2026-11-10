// Behaviour test: runs the real UI (src/ui/main.ts, bundled with esbuild)
// against a fake DOM and a mocked Tauri backend, then clicks through it.
//
// Regression for abe6905: a running plan was filed under "Earlier requests",
// below "No requests are waiting.", so after switching to the Monitor tab and
// back it looked as if the plan was gone.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { installFakeDom } from './helpers/fake-dom.mjs';

const root = path.resolve(import.meta.dirname, '..');
const manifest = (id) => JSON.parse(fs.readFileSync(path.join(root, 'plugins', id, 'manifest.json'), 'utf8'));

function pluginView(m) {
  return {
    id: m.id,
    name: m.name,
    version: m.version,
    description: m.description,
    installed: true,
    optionalInstallDefault: m.optionalInstallDefault,
    usesLlm: m.usesLlm,
    trustedOffLan: false,
    subComponents: (m.subComponents ?? []).map((c) => ({ ...c, enabled: true })),
    tools: m.tools.map((t) => ({
      id: t.id,
      name: t.name,
      description: t.description,
      requiresAdmin: t.requiresAdmin,
      readOnly: t.readOnly,
      component: t.component ?? null,
      available: true,
      defaultGatePolicy: t.defaultGatePolicy,
      effectivePolicy: t.defaultGatePolicy,
      mcpName: `${m.id}__${t.id}`,
      appOnly: Boolean(t.appOnly),
      planEligible: Boolean(t.planEligible),
      inputSchema: t.inputSchema,
    })),
  };
}

const base = { args: {}, createdAt: '2026-11-08T10:00:00Z', attemptsRemaining: 3, comment: null, decidedVia: 'app', requiresAdmin: false };
const step = (index, toolId, status) => ({
  index,
  tool: `windows-health__${toolId}`,
  pluginId: 'windows-health',
  toolId,
  toolName: toolId,
  toolDescription: '',
  requiresAdmin: false,
  args: {},
  commands: [`C:\\Windows\\System32\\ipconfig.exe /${toolId}`],
  status,
});
const runningPlan = {
  ...base,
  ticketId: 'plan-1',
  pluginId: 'aegis',
  toolId: 'plan',
  toolName: 'Action plan (2 steps)',
  toolDescription: '2 steps',
  status: 'running',
  plan: { origin: 'owner', suppliedLabel: 'Written by you', hash: 'ab'.repeat(32), shortHash: 'abababab', summary: '2 steps · stops if a step fails, earlier changes stay.', flags: [], expiresAt: '2026-11-08T10:10:00Z' },
  steps: [step(1, 'flush_dns', 'running'), step(2, 'winsock_reset', 'pending')],
};
const queued = { ...base, ticketId: 'one-2', pluginId: 'windows-health', toolId: 'ip_release_renew', toolName: 'Renew IP address', toolDescription: '', status: 'queued', queuePosition: 1 };
const finished = { ...base, ticketId: 'one-3', pluginId: 'windows-health', toolId: 'sfc_scan', toolName: 'System file check', toolDescription: '', status: 'approved', result: { success: true } };

const calls = [];
let reviews = [];
let notices = [];
let autostart = { state: 'off', shortcut: 'C:\Startup\AegisWin Monitor.lnk', wanted: true };
const autostartCalls = [];
const recordCalls = [];
let recordEvents = [
  { at: '2026-11-08T10:05:00Z', event: 'finished', ticketId: 'one-3aaaaaaa', status: 'execution_failed', reason: 'Step 2 failed: broke' },
  { at: '2026-11-08T10:04:00Z', event: 'change_finished', ticketId: 'one-3aaaaaaa', tool: 'windows-health__sfc_scan', outcome: 'succeeded', step: 1 },
  { at: '2026-11-08T10:01:00Z', event: 'decided', ticketId: 'one-3aaaaaaa', approved: true, via: 'browser', comment: 'go', lockedOut: false },
  { at: '2026-11-08T10:00:00Z', event: 'created', ticketId: 'one-3aaaaaaa', origin: 'mcp plan', toolName: 'Action plan (2 steps)', plan: { hash: 'cd'.repeat(32), title: 'Fix <b>it</b>', titleLabel: 'Supplied by the requesting agent', steps: [] } },
];
let app = null;
function backend(cmd, args) {
  calls.push(cmd);
  switch (cmd) {
    case 'status':
      return { vaultExists: true, unlocked: true, firstRunCompleted: true, elevated: true, version: '1.0.0', dataDir: 'C:\\x\\data', pinLockoutSeconds: 0, uiScale: 100, change: { running: 'Action plan (2 steps)', queued: 1 }, runtimeReviews: reviews, resumeNotices: notices };
    case 'get_autostart':
      return autostart;
    case 'enable_autostart':
      autostartCalls.push({ cmd, ...args });
      if (!args.replace) throw { code: 'CONFLICT', message: 'A Startup shortcut from another AegisWin copy already exists. Replace it?' };
      autostart = { ...autostart, state: 'on' };
      return autostart;
    case 'disable_autostart':
      autostartCalls.push({ cmd });
      autostart = { ...autostart, state: 'off' };
      return autostart;
    case 'read_approval_record':
      recordCalls.push({ cmd, ...args });
      return { days: args.days, retention: { maxDays: 90, maxMb: 64 }, events: recordEvents, omitted: 0, files: [{ name: 'seg-1.bin', status: 'ok' }] };
    case 'delete_approval_record':
      recordCalls.push({ cmd, ...args });
      recordEvents = [];
      return 3;
    case 'dismiss_resume_notice':
      assert.equal(args.pluginId, 'usage-monitor');
      notices = [];
      return null;
    case 'rewrite_runtime':
      assert.equal(args.pluginId, 'usage-monitor');
      reviews = [];
      return null;
    case 'list_plugins':
      return ['windows-health', 'usage-monitor'].map((id) => pluginView(manifest(id)));
    case 'get_settings':
      return {
        uiScale: 100,
        autoLockMinutes: 15,
        llm: { baseUrl: 'http://127.0.0.1:11434', model: 'm', hasApiKey: false, contextTokens: 8192, endpoint: null, endpointError: null },
        mcp: { enabled: false, host: '127.0.0.1', port: 47821, openFirewall: true, status: { running: false, url: null, localUrl: null, firewallRule: false, note: null }, suggestedLanHost: null },
      };
    case 'list_tickets':
      return [runningPlan, queued, finished];
    case 'run_tool':
      if (args.toolId === 'list_monitors') return { status: 'completed', result: { monitors: [], maxMonitors: 20, loadError: null, note: '' } };
      return { status: 'completed', result: {} };
    default:
      return null;
  }
}

async function settle() {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
}

/** The Approvals tab, flattened: each heading or card in page order, as text. */
function approvalsSections(document) {
  // The first child holds runtime-file review banners; the tab comes after it.
  const stack = document.querySelector('main').childNodes.at(-1);
  return stack.childNodes.map((n) => n.textContent.replace(/\s+/g, ' ').trim());
}

function nav(document, tab) {
  const button = document.querySelectorAll('.nav').find((b) => b.dataset.tab === tab);
  assert.ok(button, `the ${tab} tab is in the sidebar`);
  return button;
}

test('a running plan stays under "In progress" after switching to the Monitor tab and back', async () => {
  app = installFakeDom();
  const { document } = app;
  window.__TAURI_INTERNALS__ = { invoke: async (cmd, args) => backend(cmd, args), transformCallback: () => 0 };

  const bundle = await build({
    entryPoints: [path.join(root, 'src/ui/main.ts')],
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    loader: { '.css': 'empty' },
    logLevel: 'silent',
  });
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-ui-')), 'main.mjs');
  fs.writeFileSync(file, bundle.outputFiles[0].text);
  await import(pathToFileURL(file).href);
  await settle();

  const check = (when) => {
    const sections = approvalsSections(document);
    const at = (pred, what) => {
      const i = sections.findIndex(pred);
      assert.ok(i >= 0, `${when}: ${what} is shown (page: ${JSON.stringify(sections.map((s) => s.slice(0, 40)))})`);
      return i;
    };
    assert.ok(!sections.some((s) => s === 'No requests are waiting.' || s.startsWith('No requests are waiting.')), `${when}: no "nothing waiting" notice while a plan runs`);
    const progress = at((s) => s === 'In progress', 'the In progress heading');
    const plan = at((s) => s.includes('Action plan (2 steps)') && s.includes('Your plan'), 'the running plan');
    const waiting = at((s) => s.includes('Renew IP address'), 'the queued request');
    const earlier = at((s) => s === 'Earlier requests', 'the Earlier requests heading');
    const done = at((s) => s.includes('System file check'), 'the finished request');
    assert.ok(progress < plan && plan < waiting && waiting < earlier && earlier < done, `${when}: running, then queued, then finished`);
    assert.ok(sections[plan].includes('Stop after this step'), `${when}: the running plan can still be stopped`);
  };

  nav(document, 'approvals').click();
  await settle();
  check('first visit');

  nav(document, 'plugin:usage-monitor').click();
  await settle();
  assert.ok(calls.includes('run_tool'), 'the Monitor tab loaded its monitors');
  assert.ok(document.querySelector('main').textContent.includes('Monitor'), 'the Monitor tab is shown');

  nav(document, 'approvals').click();
  await settle();
  check('after the Monitor tab');
});

test('a runtime file set aside at unlock shows a banner until the owner rewrites it', async () => {
  assert.ok(app, 'the app was loaded by the previous test');
  const { document, intervals } = app;
  const banner = () => document.querySelector('main').childNodes[0];
  assert.equal(banner().textContent, '', 'no banner while nothing is set aside');

  reviews = [{ pluginId: 'usage-monitor', differences: ['monitoring settings'] }];
  for (const poll of intervals) await poll();
  await settle();
  const text = banner().textContent;
  assert.ok(text.includes(manifest('usage-monitor').name), `the banner names the plugin (${text})`);
  assert.ok(text.includes('monitoring settings'), 'the banner says what differed');

  nav(document, 'plugin:usage-monitor').click();
  await settle();
  assert.ok(banner().textContent.includes('monitoring settings'), 'the banner stays when the tab changes');

  const rewrite = document.querySelectorAll('button').find((b) => b.textContent.startsWith('Rewrite it from my saved settings'));
  assert.ok(rewrite, 'the banner offers the rewrite');
  rewrite.click();
  await settle();
  assert.ok(calls.includes('rewrite_runtime'));
  assert.equal(banner().textContent, '', 'the banner goes once the file is rewritten');
});

test('after a resume at launch, a banner shows the gap until dismissed', async () => {
  const { document, intervals } = app;
  const banner = () => document.querySelector('main').childNodes[0];
  notices = [{ pluginId: 'usage-monitor', from: '2026-11-07T22:00:00Z', to: '2026-11-08T07:30:00Z', label: 'Not monitoring: AegisWin was closed.' }];
  for (const poll of intervals) await poll();
  await settle();
  const text = banner().textContent;
  assert.ok(text.includes('monitors were stopped from') && text.includes('the gap is recorded'), `the banner says when (${text})`);
  assert.ok(text.includes('AegisWin was closed.'), 'and why');

  const dismiss = document.querySelectorAll('button').find((b) => b.textContent === 'Dismiss');
  assert.ok(dismiss, 'the banner can be dismissed');
  dismiss.click();
  await settle();
  assert.ok(calls.includes('dismiss_resume_notice'));
  assert.equal(banner().textContent, '', 'the banner goes once dismissed');
});

test('the Startup shortcut needs the PIN to turn on, asks before replacing another copy, and turns off without it', async () => {
  const { document } = app;
  nav(document, 'settings').click();
  await settle();
  const card = () => document.querySelectorAll('section').find((s) => s.id === 'autostart');
  const button = (label) => card().querySelectorAll('button').find((b) => b.textContent === label);
  assert.ok(card().textContent.includes('Off:'), 'starts off');

  button('Turn on (PIN)').click();
  await settle();
  const dialog = () => document.querySelectorAll('dialog').find((d) => d.open);
  const pin = dialog().querySelector('input');
  pin.value = '246810';
  dialog().querySelector('form').dispatchEvent({ type: 'submit', defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } });
  await settle();
  assert.ok(dialog().textContent.includes('Replace the other shortcut?'), "another copy's shortcut: the owner is asked");
  dialog().querySelectorAll('button').find((b) => b.textContent === 'Replace').click();
  await settle();
  assert.deepEqual(autostartCalls, [
    { cmd: 'enable_autostart', pin: '246810', replace: false },
    { cmd: 'enable_autostart', pin: '246810', replace: true },
  ]);
  assert.ok(card().textContent.includes('On:'), 'now on');

  button('Turn off').click();
  await settle();
  assert.deepEqual(autostartCalls.at(-1), { cmd: 'disable_autostart' }, 'turning off sends no PIN');
  assert.ok(card().textContent.includes('Off:'));
});

test('the approval record needs the PIN to show and to delete, and shows supplied text as text', async () => {
  const { document } = app;
  nav(document, 'approvals').click();
  await settle();
  const card = () => document.querySelectorAll('section').find((s) => s.id === 'approval-record');
  assert.ok(card(), 'the record card is on the Approvals tab');
  const button = (label) => card().querySelectorAll('button').find((b) => b.textContent === label);
  const dialog = () => document.querySelectorAll('dialog').find((d) => d.open);
  const submitPin = async (pin) => {
    dialog().querySelector('input').value = pin;
    dialog().querySelector('form').dispatchEvent({ type: 'submit', defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } });
    await settle();
  };

  button('Show record (PIN)').click();
  await settle();
  await submitPin('246810');
  assert.deepEqual(recordCalls, [{ cmd: 'read_approval_record', pin: '246810', days: 7 }]);
  const text = card().textContent;
  assert.ok(text.includes('Approved via browser. Note: go'), text);
  assert.ok(text.includes('execution failed. Step 2 failed: broke'), text);
  assert.ok(text.includes('titled "Fix <b>it</b>" (Supplied by the requesting agent)'), 'the supplied title is shown as text with its label');
  assert.ok(!card().querySelectorAll('b').length, 'no markup from a record is rendered');

  // Re-rendering the tab (the poll does this every 2 seconds) keeps what is shown.
  nav(document, 'approvals').click();
  await settle();
  assert.ok(card().textContent.includes('Approved via browser'));

  button('Delete the record (PIN)').click();
  await settle();
  dialog().querySelectorAll('button').find((b) => b.textContent === 'Delete').click();
  await settle();
  await submitPin('246810');
  assert.deepEqual(recordCalls.at(-1), { cmd: 'delete_approval_record', pin: '246810' });
  assert.ok(card().textContent.includes('Approval record deleted (3 file(s)).'));
});
