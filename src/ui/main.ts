// AegisWin desktop UI. Every action goes through a Tauri command; the
// Rust engine enforces all gates, so this file only decides what to show.

import './styles.css';
import { api, asError, type AegisError, type PluginView, type SettingsView, type Status, type TicketView, type ToolView } from './api';
import { askPin, busy, confirmDialog, copyText, h, replace, toast } from './dom';
import { rawJson, renderValue, schemaForm } from './render';

const root = document.getElementById('app')!;

let status: Status;
let plugins: PluginView[] = [];
let settings: SettingsView | null = null;
let tickets: TicketView[] = [];
let activeTab = '';
let pollTimer: number | undefined;
let mainEl: HTMLElement | null = null;
let shellParts: { approvalsCount: HTMLElement; mcpPill: HTMLElement } | null = null;

const PIN_MIN = 6;

// ---- helpers ---------------------------------------------------------------

function applyScale(percent: number): void {
  document.documentElement.style.setProperty('--scale', String(percent / 100));
}

function errorNotice(e: AegisError): HTMLElement {
  return h('div', { class: 'notice error', role: 'alert' }, e.message);
}

async function handleError(e: unknown): Promise<void> {
  const err = asError(e);
  if (err.code === 'VAULT_LOCKED') {
    await refreshStatus();
    route();
    return;
  }
  toast(err.message, 'error');
}

async function refreshStatus(): Promise<void> {
  status = await api.status();
  applyScale(status.uiScale);
}

function adminNotice(what: string): HTMLElement {
  const button = h('button', { class: 'primary' }, 'Restart as administrator');
  button.addEventListener('click', () => restartAsAdmin());
  return h('div', { class: 'notice', role: 'alert' }, h('p', {}, `${what} needs administrator rights. AegisWin is running as a standard user.`), button);
}

async function restartAsAdmin(): Promise<void> {
  const ok = await confirmDialog(
    'Restart as administrator?',
    'Windows will ask for permission. AegisWin locks, closes, and reopens with administrator rights; you will unlock it again with your PIN.',
    'Restart',
  );
  if (!ok) return;
  try {
    await api.restartAsAdmin();
  } catch (e) {
    await handleError(e);
  }
}

function pinPair(): { element: HTMLElement; read(): string | { error: string } } {
  const a = h('input', { type: 'password', autocomplete: 'new-password', id: 'pin-new', minlength: PIN_MIN, required: true });
  const b = h('input', { type: 'password', autocomplete: 'new-password', id: 'pin-confirm', required: true });
  return {
    element: h('div', {}, h('label', { for: 'pin-new' }, 'New PIN'), a, h('div', { class: 'hint' }, `At least ${PIN_MIN} characters. Letters are allowed and make it stronger.`), h('label', { for: 'pin-confirm' }, 'Confirm PIN'), b),
    read() {
      if (a.value.length < PIN_MIN) return { error: `The PIN must be at least ${PIN_MIN} characters.` };
      if (a.value !== b.value) return { error: 'The two PINs do not match.' };
      return a.value;
    },
  };
}

function brand(): HTMLElement {
  return h('div', { class: 'brand' }, h('div', { class: 'logo', 'aria-hidden': 'true' }, 'AW'), h('div', {}, h('h1', {}, 'AegisWin'), h('div', { class: 'hint' }, 'Windows diagnostics and repairs, with you in control')));
}

// ---- routing ---------------------------------------------------------------

function route(): void {
  stopPolling();
  shellParts = null;
  mainEl = null;
  if (!status.vaultExists) setupScreen();
  else if (!status.unlocked) unlockScreen();
  else if (!status.firstRunCompleted) void wizardScreen();
  else void appShell();
}

function setupScreen(): void {
  const pins = pinPair();
  const message = h('div');
  const submit = h('button', { type: 'submit', class: 'primary' }, 'Create PIN and continue');
  const form = h(
    'form',
    { class: 'card narrow stack' },
    brand(),
    h('h2', {}, 'Welcome. Choose a PIN.'),
    h('p', {}, 'Your PIN encrypts everything AegisWin stores and approves every repair an AI agent asks for. It is never saved anywhere, never shown to an agent, and cannot be recovered.'),
    h('p', { class: 'hint' }, `Data folder: ${status.dataDir}`),
    pins.element,
    message,
    submit,
  );
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const pin = pins.read();
    if (typeof pin !== 'string') return replace(message, errorNotice({ code: 'PIN_TOO_WEAK', message: pin.error }));
    try {
      status = await busy(submit, () => api.setupVault(pin));
      route();
    } catch (err) {
      replace(message, errorNotice(asError(err)));
    }
  });
  replace(root, h('div', { class: 'center' }, form));
}

function unlockScreen(): void {
  const input = h('input', { type: 'password', id: 'unlock-pin', autocomplete: 'current-password', required: true });
  const message = h('div');
  const submit = h('button', { type: 'submit', class: 'primary' }, 'Unlock');
  const showLockout = (seconds: number) => {
    if (seconds > 0) replace(message, h('div', { class: 'notice error', role: 'alert' }, `Too many wrong PINs. Try again in ${seconds} seconds.`));
  };
  showLockout(status.pinLockoutSeconds);
  const form = h(
    'form',
    { class: 'card narrow stack' },
    brand(),
    h('h2', {}, 'Unlock AegisWin'),
    status.elevated ? h('span', { class: 'badge warn' }, 'Running as administrator') : null,
    h('label', { for: 'unlock-pin' }, 'PIN'),
    input,
    message,
    submit,
  );
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      status = await busy(submit, () => api.unlockVault(input.value));
      input.value = '';
      applyScale(status.uiScale);
      route();
    } catch (err) {
      input.value = '';
      const error = asError(err);
      replace(message, errorNotice(error));
      if (error.code === 'PIN_LOCKED_OUT') {
        await refreshStatus();
        showLockout(status.pinLockoutSeconds);
      }
      input.focus();
    }
  });
  replace(root, h('div', { class: 'center' }, form));
  input.focus();
}

// ---- plugin selection (wizard and settings) ---------------------------------

function pluginSelector(list: PluginView[], useDefaults: boolean): { element: HTMLElement; read(): Record<string, string[]> } {
  const rows = list.map((p) => {
    const installed = useDefaults ? p.optionalInstallDefault : p.installed;
    const box = h('input', { type: 'checkbox', id: `install-${p.id}`, checked: installed });
    const comps = p.subComponents.map((c) => ({
      id: c.id,
      box: h('input', { type: 'checkbox', id: `comp-${c.id}`, checked: useDefaults ? true : c.enabled }),
      c,
    }));
    const compList = comps.length
      ? h(
          'div',
          { class: 'stack', style: 'margin-left:1.6rem' },
          ...comps.map(({ box: cb, c }) => h('div', {}, h('label', { class: 'inline', for: `comp-${c.id}` }, cb, c.name), h('div', { class: 'hint' }, c.description))),
        )
      : null;
    const sync = () => comps.forEach(({ box: cb }) => (cb.disabled = !box.checked));
    box.addEventListener('change', sync);
    sync();
    const tools = p.tools.length === 1 ? '1 tool' : `${p.tools.length} tools`;
    return {
      p,
      box,
      comps,
      element: h(
        'div',
        { class: 'card stack' },
        h('label', { class: 'inline', for: `install-${p.id}` }, box, h('strong', {}, p.name), h('span', { class: 'badge' }, tools), p.usesLlm ? h('span', { class: 'badge accent' }, 'can use an LLM') : null),
        h('p', { class: 'hint' }, p.description),
        compList,
      ),
    };
  });
  return {
    element: h('div', { class: 'stack' }, ...rows.map((r) => r.element)),
    read() {
      const selection: Record<string, string[]> = {};
      for (const r of rows) if (r.box.checked) selection[r.p.id] = r.comps.filter((c) => c.box.checked).map((c) => c.id);
      return selection;
    },
  };
}

async function wizardScreen(): Promise<void> {
  try {
    plugins = await api.listPlugins();
  } catch (e) {
    return handleError(e);
  }
  const selector = pluginSelector(plugins, true);
  const finish = h('button', { class: 'primary' }, 'Finish setup');
  finish.addEventListener('click', async () => {
    try {
      plugins = await busy(finish, () => api.setInstalled(selector.read()));
      await refreshStatus();
      route();
    } catch (e) {
      await handleError(e);
    }
  });
  replace(
    root,
    h(
      'div',
      { class: 'center' },
      h('div', { class: 'card wide stack' }, brand(), h('h2', {}, 'Choose what to turn on'), h('p', { class: 'hint' }, 'You can change this later in Settings. Nothing runs in the background unless a component below needs it.'), selector.element, h('div', { class: 'row end' }, finish)),
    ),
  );
}

// ---- main shell -----------------------------------------------------------

async function appShell(): Promise<void> {
  try {
    [plugins, settings, tickets] = await Promise.all([api.listPlugins(), api.getSettings(), api.listTickets()]);
  } catch (e) {
    return handleError(e);
  }
  const installed = plugins.filter((p) => p.installed);
  const tabs = [...installed.map((p) => `plugin:${p.id}`), 'approvals', 'mcp', 'llm', 'settings'];
  if (!tabs.includes(activeTab)) activeTab = tabs[0];

  const approvalsCount = h('span');
  const mcpPill = h('button', { class: 'badge', onclick: () => selectTab('mcp') });
  const lock = h('button', {}, 'Lock');
  lock.addEventListener('click', async () => {
    status = await api.lockVault();
    route();
  });
  const adminPart = status.elevated
    ? h('span', { class: 'badge warn' }, 'Administrator')
    : h('button', { onclick: () => restartAsAdmin(), title: 'Some repairs need administrator rights' }, 'Restart as administrator');

  const nav = (id: string, label: string, extra?: Node) =>
    h('button', { class: `nav ${activeTab === id ? 'active' : ''}`, 'data-tab': id, onclick: () => selectTab(id) }, h('span', {}, label), extra);

  const sidebar = h(
    'nav',
    { class: 'sidebar', 'aria-label': 'Sections' },
    h('div', { class: 'section' }, 'Tools'),
    ...installed.map((p) => nav(`plugin:${p.id}`, p.name)),
    installed.length === 0 ? h('p', { class: 'hint' }, 'No plugins turned on. See Settings.') : null,
    h('div', { class: 'section' }, 'AI agents'),
    nav('approvals', 'Approvals', approvalsCount),
    nav('mcp', 'MCP server'),
    h('div', { class: 'section' }, 'Configure'),
    nav('llm', 'LLM'),
    nav('settings', 'Settings'),
  );
  mainEl = h('main', { class: 'main' });
  shellParts = { approvalsCount, mcpPill };
  replace(
    root,
    h(
      'div',
      { class: 'app' },
      h('header', { class: 'topbar' }, brand(), h('div', { class: 'row' }, mcpPill, adminPart, lock)),
      sidebar,
      mainEl,
    ),
  );
  updateShellBadges();
  renderTab();
  startPolling();
}

function selectTab(id: string): void {
  activeTab = id;
  document.querySelectorAll<HTMLElement>('.nav').forEach((el) => el.classList.toggle('active', el.dataset.tab === id));
  renderTab();
}

function updateShellBadges(): void {
  if (!shellParts) return;
  const pending = tickets.filter((t) => t.status === 'pending_approval').length;
  replace(shellParts.approvalsCount, pending ? h('span', { class: 'count', 'aria-label': `${pending} pending` }, pending) : null);
  const mcp = settings?.mcp;
  shellParts.mcpPill.className = `badge ${mcp?.status.running ? 'ok' : ''}`;
  replace(shellParts.mcpPill, mcp?.status.running ? `MCP on :${mcp.port}` : 'MCP off');
}

function renderTab(): void {
  if (!mainEl) return;
  const content =
    activeTab.startsWith('plugin:') ? pluginTab(activeTab.slice(7))
    : activeTab === 'approvals' ? approvalsTab()
    : activeTab === 'mcp' ? mcpTab()
    : activeTab === 'llm' ? llmTab()
    : settingsTab();
  replace(mainEl, content);
}

// ---- polling for approval requests ------------------------------------------

function ticketSignature(list: TicketView[]): string {
  return list.map((t) => `${t.ticketId}:${t.status}`).join('|');
}

function startPolling(): void {
  stopPolling();
  pollTimer = window.setInterval(async () => {
    try {
      const next = await api.listTickets();
      const before = new Set(tickets.filter((t) => t.status === 'pending_approval').map((t) => t.ticketId));
      for (const t of next) if (t.status === 'pending_approval' && !before.has(t.ticketId)) toast(`An AI agent is asking to run "${t.toolName}". Open Approvals to decide.`);
      const changed = ticketSignature(next) !== ticketSignature(tickets);
      tickets = next;
      updateShellBadges();
      // Do not wipe a PIN the user is typing into an approval form.
      const typing = Array.from(document.querySelectorAll<HTMLInputElement>('.ticket input, .ticket textarea')).some((i) => i.value !== '');
      if (changed && activeTab === 'approvals' && !typing) renderTab();
    } catch (e) {
      const err = asError(e);
      if (err.code === 'VAULT_LOCKED') await handleError(e);
    }
  }, 2000);
}

function stopPolling(): void {
  if (pollTimer !== undefined) window.clearInterval(pollTimer);
  pollTimer = undefined;
}

// ---- plugin tabs ------------------------------------------------------------

interface FollowUp {
  tool: string;
  label: string;
  args(result: Record<string, unknown>): Record<string, unknown> | null;
}

function commandOutputText(result: Record<string, unknown>): string | null {
  if (result.executed !== true || !Array.isArray(result.outputs)) return null;
  return (result.outputs as Array<Record<string, unknown>>)
    .map((o) => `> ${o.command}\n(exit code ${o.exitCode})\n${o.stdout ?? ''}\n${o.stderr ?? ''}`.trim())
    .join('\n\n');
}

const eventFollowUp: FollowUp = {
  tool: 'analyze_logs_with_llm',
  label: 'Ask the LLM about these events',
  args: (r) => (Array.isArray(r.events) && r.events.length ? { events: r.events.slice(0, 100) } : null),
};
const healthFollowUp: FollowUp = {
  tool: 'interpret_health_output',
  label: 'Ask the LLM to explain this output',
  args: (r) => {
    const text = commandOutputText(r);
    return text ? { commandOutput: text.slice(0, 100000) } : null;
  },
};
const FOLLOW_UPS: Record<string, FollowUp> = {
  'event-logs:query_logs': eventFollowUp,
  'event-logs:filter_by_event_id': eventFollowUp,
  'usage-monitor:capture_diagnostic_snapshot': { tool: 'analyze_clues_with_llm', label: 'Ask the LLM what is slowing this PC down', args: (r) => ({ snapshot: r }) },
  'windows-health:sfc_scan': healthFollowUp,
  'windows-health:flush_dns': healthFollowUp,
  'windows-health:ip_release_renew': healthFollowUp,
  'windows-health:winsock_reset': healthFollowUp,
};

function pluginTab(pluginId: string): HTMLElement {
  const plugin = plugins.find((p) => p.id === pluginId);
  if (!plugin) return h('p', {}, 'Plugin not found.');
  return h(
    'div',
    { class: 'stack' },
    h('div', {}, h('h2', {}, plugin.name), h('p', { class: 'hint' }, plugin.description)),
    ...plugin.tools.map((tool) => toolCard(plugin, tool)),
  );
}

function toolBadges(tool: ToolView): HTMLElement {
  return h(
    'div',
    { class: 'badges' },
    tool.readOnly ? h('span', { class: 'badge ok' }, 'read-only') : h('span', { class: 'badge warn' }, 'changes the system'),
    tool.requiresAdmin ? h('span', { class: 'badge danger' }, 'administrator') : null,
    tool.effectivePolicy === 'pin_required' ? h('span', { class: 'badge accent' }, 'PIN') : null,
    !tool.available ? h('span', { class: 'badge' }, 'component off') : null,
  );
}

function toolCard(plugin: PluginView, tool: ToolView): HTMLElement {
  const form = schemaForm(tool.inputSchema, `${plugin.id}-${tool.id}`);
  const result = h('div', { 'aria-live': 'polite' });
  const run = h('button', { class: 'primary' }, form.hasDryRun ? 'Run' : 'Run');
  const dry = form.hasDryRun ? h('button', {}, 'Dry run (show commands)') : null;
  const start = (dryRun: boolean, button: HTMLButtonElement) => {
    const read = form.read();
    if ('error' in read) return replace(result, errorNotice({ code: 'INVALID_ARGUMENTS', message: read.error }));
    const args = form.hasDryRun ? { ...read.args, dryRun } : read.args;
    void runTool(plugin, tool, args, result, button);
  };
  run.addEventListener('click', () => start(false, run));
  dry?.addEventListener('click', () => start(true, dry));
  if (!tool.available) run.disabled = true;
  return h(
    'section',
    { class: 'card' },
    h('div', { class: 'tool-head' }, h('div', {}, h('h3', {}, tool.name), h('p', { class: 'hint' }, tool.description)), toolBadges(tool)),
    Object.keys(tool.inputSchema.properties ?? {}).some((k) => k !== 'dryRun') ? form.element : null,
    h('div', { class: 'row', style: 'margin-top:0.8rem' }, run, dry),
    result,
  );
}

async function runTool(plugin: PluginView, tool: ToolView, args: Record<string, unknown>, resultEl: HTMLElement, button: HTMLButtonElement): Promise<void> {
  const dryRun = args.dryRun === true;
  if (tool.requiresAdmin && !status.elevated && !dryRun) {
    replace(resultEl, h('div', { class: 'result' }, adminNotice(tool.name)));
    return;
  }
  let pin: string | null = null;
  if (tool.effectivePolicy === 'pin_required' && !dryRun) {
    pin = await askPin(`Run "${tool.name}"?`, tool.description, 'Run');
    if (pin === null) return;
  }
  try {
    const outcome = await busy(button, () => api.runTool(plugin.id, tool.id, args, pin));
    if (outcome.status === 'completed') showResult(resultEl, plugin, tool, outcome.result);
  } catch (e) {
    const err = asError(e);
    if (err.code === 'VAULT_LOCKED') return handleError(e);
    if (err.code === 'REQUIRES_ADMIN') return replace(resultEl, h('div', { class: 'result' }, adminNotice(tool.name)));
    if (err.code === 'OFF_LAN_TRUST_REQUIRED') {
      if (await askTrust(plugin)) return runTool(plugin, tool, args, resultEl, button);
    }
    replace(resultEl, h('div', { class: 'result' }, errorNotice(err)));
  }
}

function showResult(resultEl: HTMLElement, plugin: PluginView, tool: ToolView, value: unknown): void {
  const follow = FOLLOW_UPS[`${plugin.id}:${tool.id}`];
  const target = follow ? plugin.tools.find((t) => t.id === follow.tool) : undefined;
  const followArgs = follow && target && value && typeof value === 'object' ? follow.args(value as Record<string, unknown>) : null;
  const followResult = h('div');
  let followButton: HTMLButtonElement | null = null;
  if (follow && target && followArgs) {
    const btn = h('button', {}, follow.label);
    btn.addEventListener('click', () => void runTool(plugin, target, followArgs, followResult, btn));
    followButton = btn;
  }
  replace(resultEl, h('div', { class: 'result' }, renderValue(value), rawJson(value), followButton ? h('div', { class: 'row', style: 'margin-top:0.6rem' }, followButton) : null, followResult));
}

async function askTrust(plugin: PluginView): Promise<boolean> {
  const host = settings?.llm.endpoint?.host ?? 'the configured endpoint';
  const pin = await askPin(
    `Let ${plugin.name} use ${host}?`,
    `${host} is outside your local network. AegisWin removes your user name, computer name, profile paths and network share names before sending, but the diagnostics themselves (event messages, process names, command output) will leave this PC. You can revoke this in the LLM tab.`,
    'Allow',
  );
  if (pin === null) return false;
  try {
    await api.grantLlmTrust(plugin.id, pin);
    plugins = await api.listPlugins();
    return true;
  } catch (e) {
    await handleError(e);
    return false;
  }
}

// ---- approvals ------------------------------------------------------------

const STATUS_TEXT: Record<string, [string, string]> = {
  pending_approval: ['waiting for you', 'warn'],
  running: ['running', 'accent'],
  approved: ['approved', 'ok'],
  declined: ['declined', ''],
  execution_failed: ['failed', 'danger'],
  locked_out: ['locked (wrong PINs)', 'danger'],
  expired: ['expired', ''],
};

function approvalsTab(): HTMLElement {
  const pending = tickets.filter((t) => t.status === 'pending_approval');
  const done = tickets.filter((t) => t.status !== 'pending_approval');
  return h(
    'div',
    { class: 'stack' },
    h('div', {}, h('h2', {}, 'Approvals'), h('p', { class: 'hint' }, 'When an AI agent calls a tool that needs your PIN, the request waits here. The agent can also show you a browser link for the same request. Requests expire after 30 minutes and are forgotten when AegisWin locks.')),
    pending.length === 0 ? h('div', { class: 'card' }, h('p', {}, 'No requests are waiting.')) : null,
    ...pending.map(ticketCard),
    done.length ? h('h3', {}, 'Earlier requests') : null,
    ...done.map(ticketCard),
  );
}

function ticketCard(t: TicketView): HTMLElement {
  const [label, tone] = STATUS_TEXT[t.status] ?? [t.status, ''];
  const head = h(
    'div',
    { class: 'tool-head' },
    h('div', {}, h('h3', {}, t.toolName), h('p', { class: 'hint' }, `${t.pluginId} · requested ${new Date(t.createdAt).toLocaleString()}`)),
    h('div', { class: 'badges' }, t.requiresAdmin ? h('span', { class: 'badge danger' }, 'administrator') : null, h('span', { class: `badge ${tone}` }, label)),
  );
  const body: Node[] = [head, h('p', {}, t.toolDescription), h('div', { class: 'hint' }, 'Arguments'), h('pre', {}, JSON.stringify(t.args, null, 2))];
  if (t.status === 'pending_approval') {
    const pin = h('input', { type: 'password', autocomplete: 'off', id: `pin-${t.ticketId}` });
    const comment = h('textarea', { rows: 2, maxlength: 500, id: `comment-${t.ticketId}` });
    const message = h('div');
    const approve = h('button', { class: 'primary' }, 'Approve and run');
    const decline = h('button', {}, 'Decline');
    const decide = async (yes: boolean, button: HTMLButtonElement) => {
      if (!pin.value) return replace(message, errorNotice({ code: 'PIN_REQUIRED', message: 'Enter your PIN to approve or decline.' }));
      try {
        await busy(button, () => api.decideTicket(t.ticketId, yes, pin.value, comment.value.trim() || null));
        pin.value = '';
        comment.value = '';
        tickets = await api.listTickets();
        updateShellBadges();
        renderTab();
      } catch (e) {
        pin.value = '';
        const err = asError(e);
        replace(message, errorNotice(err));
        if (err.code === 'CONFLICT' || err.code === 'NOT_FOUND' || (err.code === 'PIN_LOCKED_OUT' && err.message.includes('request'))) {
          tickets = await api.listTickets();
          renderTab();
        }
      }
    };
    approve.addEventListener('click', () => decide(true, approve));
    decline.addEventListener('click', () => decide(false, decline));
    body.push(
      h('div', { class: 'grid2' }, h('div', {}, h('label', { for: `pin-${t.ticketId}` }, 'Your PIN'), pin, h('div', { class: 'hint' }, `${t.attemptsRemaining} attempt(s) left for this request`)), h('div', {}, h('label', { for: `comment-${t.ticketId}` }, 'Note for the agent (optional)'), comment)),
      message,
      h('div', { class: 'row', style: 'margin-top:0.6rem' }, approve, decline),
    );
  } else {
    if (t.decidedVia) body.push(h('p', { class: 'hint' }, `Decided in the ${t.decidedVia === 'browser' ? 'browser' : 'app'}${t.comment ? `: "${t.comment}"` : ''}`));
    if (t.error) body.push(errorNotice(t.error));
    if (t.result !== undefined) body.push(h('details', {}, h('summary', {}, 'Result'), renderValue(t.result), rawJson(t.result)));
  }
  return h('section', { class: 'card ticket' }, ...body);
}

// ---- MCP --------------------------------------------------------------------

function mcpTab(): HTMLElement {
  const container = h('div', { class: 'stack' }, h('h2', {}, 'MCP server'), h('p', { class: 'hint' }, 'Lets AI agents such as Claude call AegisWin tools over the Model Context Protocol. Read-only tools run right away; anything that changes the system waits for your PIN.'));
  if (!settings) return container;
  const mcp = settings.mcp;

  const statusCard = h('section', { class: 'card stack' });
  const renderStatus = () => {
    const s = settings!.mcp.status;
    const toggle = h('button', { class: s.running ? '' : 'primary' }, s.running ? 'Stop server' : 'Start server');
    toggle.addEventListener('click', async () => {
      try {
        await busy(toggle, () => (s.running ? api.stopMcp() : api.startMcp()));
        settings = await api.getSettings();
        updateShellBadges();
        renderStatus();
      } catch (e) {
        await handleError(e);
      }
    });
    replace(
      statusCard,
      h('div', { class: 'row' }, h('h3', { class: 'grow' }, 'Status'), h('span', { class: `badge ${s.running ? 'ok' : ''}` }, s.running ? 'running' : 'stopped'), toggle),
      s.url ? h('div', { class: 'row' }, h('code', { class: 'grow' }, s.url), h('button', { onclick: () => copyText(s.url!) }, 'Copy URL')) : h('p', { class: 'hint' }, 'The server only runs while AegisWin is unlocked. Starting it also turns on auto-start after unlock.'),
      s.firewallRule ? h('div', { class: 'notice ok' }, 'A Windows Firewall rule allows other PCs on your private network to connect. It is removed when the server stops.') : null,
      s.note ? h('div', { class: 'notice' }, s.note) : null,
    );
  };
  renderStatus();

  const host = h('select', { id: 'mcp-host' }, h('option', { value: '127.0.0.1' }, '127.0.0.1 — this PC only (recommended)'));
  if (mcp.suggestedLanHost) host.appendChild(h('option', { value: mcp.suggestedLanHost }, `${mcp.suggestedLanHost} — other PCs on your network`));
  if (mcp.host !== '127.0.0.1' && mcp.host !== mcp.suggestedLanHost) host.appendChild(h('option', { value: mcp.host }, mcp.host));
  host.value = mcp.host;
  const port = h('input', { type: 'number', id: 'mcp-port', min: 1024, max: 65535, value: mcp.port });
  const firewall = h('input', { type: 'checkbox', id: 'mcp-fw', checked: mcp.openFirewall });
  const save = h('button', { class: 'primary' }, 'Save');
  save.addEventListener('click', async () => {
    try {
      settings = await busy(save, () => api.updateSettings({ mcpHost: host.value, mcpPort: Number(port.value), mcpOpenFirewall: firewall.checked }));
      updateShellBadges();
      toast('MCP settings saved.');
      renderStatus();
    } catch (e) {
      await handleError(e);
    }
  });
  const configCard = h(
    'section',
    { class: 'card' },
    h('h3', {}, 'Network'),
    h('div', { class: 'grid2' }, h('div', {}, h('label', { for: 'mcp-host' }, 'Listen on'), host), h('div', {}, h('label', { for: 'mcp-port' }, 'Port'), port)),
    h('label', { class: 'inline', for: 'mcp-fw' }, firewall, 'Add a Windows Firewall rule for network mode (needs administrator)'),
    h('div', { class: 'row end' }, save),
  );

  const tokenArea = h('div', { class: 'stack' });
  const reveal = h('button', {}, 'Show token and setup commands');
  reveal.addEventListener('click', async () => {
    const pin = await askPin('Show the MCP token?', 'Anyone with this token can ask AegisWin to run tools (changes still need your PIN). Only paste it into AI clients you trust.', 'Show');
    if (pin === null) return;
    try {
      const token = await api.revealMcpToken(pin);
      const url = settings!.mcp.status.url ?? `http://${settings!.mcp.host}:${settings!.mcp.port}/mcp`;
      const claudeCode = `claude mcp add --transport http aegis-win ${url} --header "Authorization: Bearer ${token}"`;
      const json = JSON.stringify({ mcpServers: { 'aegis-win': { type: 'http', url, headers: { Authorization: `Bearer ${token}` } } } }, null, 2);
      replace(
        tokenArea,
        h('div', { class: 'row' }, h('code', { class: 'grow' }, token), h('button', { onclick: () => copyText(token) }, 'Copy token')),
        h('div', {}, h('div', { class: 'hint' }, 'Claude Code'), h('pre', {}, claudeCode), h('button', { onclick: () => copyText(claudeCode) }, 'Copy command')),
        h('div', {}, h('div', { class: 'hint' }, 'JSON config (clients that support HTTP servers)'), h('pre', {}, json), h('button', { onclick: () => copyText(json) }, 'Copy JSON')),
      );
    } catch (e) {
      await handleError(e);
    }
  });
  const rotate = h('button', { class: 'danger' }, 'Issue a new token');
  rotate.addEventListener('click', async () => {
    if (!(await confirmDialog('Issue a new token?', 'Every connected AI client stops working until you give it the new token.', 'Issue new token'))) return;
    try {
      await api.rotateMcpToken();
      replace(tokenArea);
      toast('New token issued.');
    } catch (e) {
      await handleError(e);
    }
  });
  const tokenCard = h('section', { class: 'card stack' }, h('h3', {}, 'Connect an AI client'), h('div', { class: 'row' }, reveal, rotate), tokenArea);

  return h('div', { class: 'stack' }, container, statusCard, configCard, tokenCard, gatesCard());
}

function gatesCard(): HTMLElement {
  const rows = plugins
    .filter((p) => p.installed)
    .flatMap((p) =>
      p.tools.map((t) => {
        const select = h('select', { 'aria-label': `Gate for ${t.name}` }, h('option', { value: 'auto' }, 'runs immediately'), h('option', { value: 'pin_required' }, 'needs my PIN'));
        select.value = t.effectivePolicy;
        select.addEventListener('change', async () => {
          const policy = select.value as 'auto' | 'pin_required';
          let pin: string | null = null;
          if (policy === 'auto' && t.effectivePolicy === 'pin_required') {
            pin = await askPin(`Let agents run "${t.name}" without asking?`, t.readOnly ? 'This tool only reads information.' : 'This tool changes the system. Agents will be able to run it without your approval.', 'Allow');
            if (pin === null) {
              select.value = t.effectivePolicy;
              return;
            }
          }
          try {
            await api.setGatePolicy(p.id, t.id, policy, pin);
            plugins = await api.listPlugins();
            toast(`${t.name}: ${policy === 'auto' ? 'runs immediately' : 'needs your PIN'}.`);
          } catch (e) {
            select.value = t.effectivePolicy;
            await handleError(e);
          }
        });
        return h('tr', {}, h('td', {}, t.name, h('div', { class: 'hint mono' }, t.mcpName)), h('td', {}, t.readOnly ? 'read-only' : 'changes the system', t.requiresAdmin ? ', administrator' : ''), h('td', {}, select));
      }),
    );
  return h(
    'section',
    { class: 'card stack' },
    h('h3', {}, 'What agents may run without asking'),
    h('p', { class: 'hint' }, 'Making a tool stricter never needs your PIN; loosening one does. Dry runs never need approval.'),
    h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Tool'), h('th', {}, 'Effect'), h('th', {}, 'Gate'))), h('tbody', {}, ...rows))),
  );
}

// ---- LLM --------------------------------------------------------------------

function llmTab(): HTMLElement {
  if (!settings) return h('div');
  const llm = settings.llm;
  const baseUrl = h('input', { type: 'text', id: 'llm-url', value: llm.baseUrl, spellcheck: 'false' });
  const model = h('input', { type: 'text', id: 'llm-model', value: llm.model, spellcheck: 'false' });
  const classification = h('div');
  const showClass = () => {
    const s = settings!.llm;
    replace(
      classification,
      s.endpointError ? h('span', { class: 'badge danger' }, s.endpointError)
      : s.endpoint?.relayed ? h('span', { class: 'badge warn' }, `${s.model} runs in Ollama's cloud: data leaves this PC, so each plugin needs your permission`)
      : s.endpoint?.isLan ? h('span', { class: 'badge ok' }, `${s.endpoint.host} is on your LAN: data stays local`)
      : s.endpoint ? h('span', { class: 'badge warn' }, `${s.endpoint.host} is off-LAN: each plugin needs your permission`)
      : null,
    );
  };
  showClass();
  const models = h('div', { class: 'row' });
  const save = h('button', { class: 'primary' }, 'Save');
  save.addEventListener('click', async () => {
    try {
      settings = await busy(save, () => api.updateSettings({ llmBaseUrl: baseUrl.value, llmModel: model.value }));
      plugins = await api.listPlugins();
      showClass();
      renderTrust();
      toast('LLM settings saved.');
    } catch (e) {
      await handleError(e);
    }
  });
  const test = h('button', {}, 'Test connection');
  test.addEventListener('click', async () => {
    try {
      const out = await busy(test, () => api.testLlm());
      replace(
        models,
        out.models.length ? h('span', { class: 'hint' }, 'Models (click to use):') : h('span', { class: 'hint' }, 'Connected, but the server listed no models.'),
        ...out.models.map((m) => h('button', { class: 'badge accent', onclick: () => (model.value = m) }, m)),
      );
    } catch (e) {
      replace(models, errorNotice(asError(e)));
    }
  });

  const keyState = h('span');
  const showKey = () => replace(keyState, settings!.llm.hasApiKey ? h('span', { class: 'badge ok' }, 'API key saved') : h('span', { class: 'badge' }, 'no API key'));
  showKey();
  const key = h('input', { type: 'password', id: 'llm-key', autocomplete: 'off', placeholder: 'Paste a key to replace the saved one' });
  const saveKey = h('button', {}, 'Save key');
  const clearKey = h('button', { class: 'danger' }, 'Remove key');
  const setKey = async (value: string, button: HTMLButtonElement) => {
    try {
      await busy(button, () => api.setLlmApiKey(value));
      key.value = '';
      settings = await api.getSettings();
      showKey();
      toast(value ? 'API key saved.' : 'API key removed.');
    } catch (e) {
      await handleError(e);
    }
  };
  saveKey.addEventListener('click', () => key.value.trim() && setKey(key.value, saveKey));
  clearKey.addEventListener('click', () => setKey('', clearKey));

  const trustBody = h('div', { class: 'stack' });
  const renderTrust = () => {
    const users = plugins.filter((p) => p.installed && p.usesLlm);
    replace(
      trustBody,
      ...(users.length
        ? users.map((p) => {
            const btn = p.trustedOffLan ? h('button', { class: 'danger' }, 'Revoke') : h('button', {}, 'Allow');
            btn.addEventListener('click', async () => {
              try {
                if (p.trustedOffLan) await api.revokeLlmTrust(p.id);
                else if (!(await askTrust(p))) return;
                plugins = await api.listPlugins();
                renderTrust();
              } catch (e) {
                await handleError(e);
              }
            });
            return h('div', { class: 'row' }, h('span', { class: 'grow' }, p.name), h('span', { class: `badge ${p.trustedOffLan ? 'warn' : ''}` }, p.trustedOffLan ? 'may send off-LAN' : 'LAN only'), btn);
          })
        : [h('p', { class: 'hint' }, 'No installed plugin uses an LLM.')]),
    );
  };
  renderTrust();

  return h(
    'div',
    { class: 'stack' },
    h('div', {}, h('h2', {}, 'LLM'), h('p', { class: 'hint' }, 'Plugins can ask an LLM to explain logs and command output. Use a local server such as Ollama or LM Studio, or any OpenAI-compatible endpoint.')),
    h('section', { class: 'card' }, h('h3', {}, 'Endpoint'), h('label', { for: 'llm-url' }, 'Base URL'), baseUrl, h('div', { class: 'hint' }, 'Ollama: http://127.0.0.1:11434/v1 · LM Studio: http://127.0.0.1:1234/v1'), h('label', { for: 'llm-model' }, 'Model'), model, h('div', { style: 'margin-top:0.6rem' }, classification), h('div', { class: 'row', style: 'margin-top:0.8rem' }, save, test), models),
    h('section', { class: 'card' }, h('div', { class: 'row' }, h('h3', { class: 'grow' }, 'API key'), keyState), h('p', { class: 'hint' }, 'Stored encrypted in the vault and never shown again. Local servers usually need none.'), key, h('div', { class: 'row', style: 'margin-top:0.6rem' }, saveKey, clearKey)),
    h('section', { class: 'card' }, h('h3', {}, 'Off-LAN permission'), h('p', { class: 'hint' }, 'An endpoint outside your network only receives data from plugins you allow, after personal details are scrubbed. Changing the endpoint to a different host clears these permissions.'), trustBody),
  );
}

// ---- settings ---------------------------------------------------------------

function settingsTab(): HTMLElement {
  const scale = h('input', { type: 'range', id: 'ui-scale', min: 80, max: 150, step: 5, value: settings?.uiScale ?? 100 });
  const scaleLabel = h('span', { class: 'mono' }, `${scale.value}%`);
  scale.addEventListener('input', () => {
    replace(scaleLabel, `${scale.value}%`);
    applyScale(Number(scale.value));
  });
  scale.addEventListener('change', async () => {
    try {
      settings = await api.updateSettings({ uiScale: Number(scale.value) });
    } catch (e) {
      await handleError(e);
    }
  });

  const selector = pluginSelector(plugins, false);
  const savePlugins = h('button', { class: 'primary' }, 'Save plugins');
  savePlugins.addEventListener('click', async () => {
    try {
      plugins = await busy(savePlugins, () => api.setInstalled(selector.read()));
      toast('Plugins updated.');
      await appShell();
      selectTab('settings');
    } catch (e) {
      await handleError(e);
    }
  });

  const current = h('input', { type: 'password', id: 'pin-current', autocomplete: 'current-password' });
  const pins = pinPair();
  const pinMessage = h('div');
  const changePin = h('button', { class: 'primary', type: 'submit' }, 'Change PIN');
  const pinForm = h('form', { class: 'card' }, h('h3', {}, 'Change PIN'), h('label', { for: 'pin-current' }, 'Current PIN'), current, pins.element, pinMessage, h('div', { class: 'row end', style: 'margin-top:0.8rem' }, changePin));
  pinForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const next = pins.read();
    if (typeof next !== 'string') return replace(pinMessage, errorNotice({ code: 'PIN_TOO_WEAK', message: next.error }));
    try {
      await busy(changePin, () => api.changePin(current.value, next));
      pinForm.reset();
      replace(pinMessage, h('div', { class: 'notice ok' }, 'PIN changed.'));
    } catch (err) {
      current.value = '';
      replace(pinMessage, errorNotice(asError(err)));
    }
  });

  return h(
    'div',
    { class: 'stack' },
    h('h2', {}, 'Settings'),
    h('section', { class: 'card' }, h('h3', {}, 'Display'), h('label', { for: 'ui-scale' }, 'Text size'), h('div', { class: 'row' }, scale, scaleLabel)),
    h('section', { class: 'stack' }, h('h3', {}, 'Plugins and components'), selector.element, h('div', { class: 'row end' }, savePlugins)),
    pinForm,
    h(
      'section',
      { class: 'card' },
      h('h3', {}, 'About'),
      h('dl', { class: 'kv' }, h('dt', {}, 'Version'), h('dd', {}, status.version), h('dt', {}, 'Data folder'), h('dd', { class: 'mono' }, status.dataDir), h('dt', {}, 'Running as'), h('dd', {}, status.elevated ? 'administrator' : 'standard user')),
    ),
  );
}

// ---- start ------------------------------------------------------------------

async function boot(): Promise<void> {
  try {
    await refreshStatus();
    route();
  } catch (e) {
    replace(root, h('div', { class: 'center' }, h('div', { class: 'card narrow stack' }, brand(), errorNotice(asError(e)), h('p', { class: 'hint' }, 'AegisWin must be started as the desktop app (npm run tauri:dev), not in a regular browser.'))));
  }
}

void boot();
