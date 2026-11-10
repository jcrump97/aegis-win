// AegisWin desktop UI. Every action goes through a Tauri command; the
// Rust engine enforces all gates, so this file only decides what to show.

import './styles.css';
import { api, asError, type AegisError, type ApprovalRecordEvent, type AutostartView, type DeviceCodeView, type PluginView, type SettingsView, type Status, type TicketView, type ToolView } from './api';
import { append, askPin, busy, confirmDialog, copyText, h, replace, toast } from './dom';
import { forgetMonitorPanel, MONITOR_TOOLS, monitorPanel, type ToolRun } from './monitors';
import { generatePassphrase } from './passphrase';
import { rawJson, renderValue, schemaForm } from './render';

const root = document.getElementById('app')!;

let status: Status;
let plugins: PluginView[] = [];
let settings: SettingsView | null = null;
let tickets: TicketView[] = [];
let activeTab = '';
let pollTimer: number | undefined;
let mainEl: HTMLElement | null = null;
let shellParts: { approvalsCount: HTMLElement; mcpPill: HTMLElement; changePill: HTMLElement; reviews: HTMLElement } | null = null;
let reviewSignature = '';
/** Steps the owner is collecting for an action plan. Memory only; dropped on lock. */
let planDraft: Array<{ tool: string; name: string; args: Record<string, unknown> }> = [];
const MAX_PLAN_STEPS = 5;

const PIN_MIN = 6;
const PASSPHRASE_MIN = 14;
/** Set by the passphrase banner's second button: preselects keeping the old PIN on this PC. */
let keyChoice: 'passphrase' | 'pc' | null = null;

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

function pinPair(prefix = 'pin', label = 'New PIN'): { element: HTMLElement; read(): string | { error: string } } {
  const a = h('input', { type: 'password', autocomplete: 'new-password', id: `${prefix}-new`, minlength: PIN_MIN });
  const b = h('input', { type: 'password', autocomplete: 'new-password', id: `${prefix}-confirm` });
  return {
    element: h('div', {}, h('label', { for: `${prefix}-new` }, label), a, h('div', { class: 'hint' }, `At least ${PIN_MIN} characters.`), h('label', { for: `${prefix}-confirm` }, 'Confirm PIN'), b),
    read() {
      if ([...a.value].length < PIN_MIN) return { error: `The PIN must be at least ${PIN_MIN} characters.` };
      if (a.value !== b.value) return { error: 'The two PINs do not match.' };
      return a.value;
    },
  };
}

const SCORE_TEXT = ['very weak', 'weak', 'fair', 'strong', 'very strong'];

/**
 * Chooses the vault passphrase (ADR 0004 §3.2): five generated words by
 * default, or the owner's own of 14+ characters with a strength guide.
 * Generated words are made in this window and never sent back by the app.
 */
function passphraseChooser(): { element: HTMLElement; read(): string | { error: string } } {
  let words = generatePassphrase();
  const generated = h('input', { type: 'radio', name: 'pp-mode', id: 'pp-generated', checked: true });
  const own = h('input', { type: 'radio', name: 'pp-mode', id: 'pp-own' });

  const shown = h('code', { class: 'passphrase' }, words);
  const hide = h('button', { type: 'button' }, 'Hide');
  const again = h('button', { type: 'button' }, 'New words');
  const written = h('input', { type: 'checkbox', id: 'pp-written' });
  hide.addEventListener('click', () => {
    const hidden = shown.classList.toggle('concealed');
    hide.textContent = hidden ? 'Show again' : 'Hide';
  });
  again.addEventListener('click', () => {
    words = generatePassphrase();
    shown.textContent = words;
    shown.classList.remove('concealed');
    hide.textContent = 'Hide';
    written.checked = false;
  });
  const generatedArea = h(
    'div',
    { class: 'stack' },
    shown,
    h('div', { class: 'row' }, again, hide),
    h('p', { class: 'hint' }, 'Five random words from the EFF wordlist (about 64 bits). Write them down and keep them somewhere safe: they cannot be recovered, and they are the only way to open your AegisWin folder on another PC.'),
    h('label', { class: 'inline', for: 'pp-written' }, written, 'I’ve written it down'),
  );

  const a = h('input', { type: 'password', autocomplete: 'new-password', id: 'pp-new' });
  const b = h('input', { type: 'password', autocomplete: 'new-password', id: 'pp-confirm' });
  const meter = h('div', { class: 'hint', 'aria-live': 'polite' });
  let timer: number | undefined;
  a.addEventListener('input', () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(async () => {
      if (!a.value) return replace(meter);
      try {
        const s = await api.passphraseStrength(a.value);
        replace(
          meter,
          h('meter', { min: 0, max: 4, low: 2, high: 3, optimum: 4, value: s.score, 'aria-label': 'Passphrase strength' }),
          ` ${SCORE_TEXT[s.score] ?? ''}, about ${s.bits} bits. `,
          s.longEnough ? '' : `Needs at least ${PASSPHRASE_MIN} characters. `,
          s.warning ? `${s.warning} ` : '',
          s.suggestions.join(' '),
        );
      } catch {
        replace(meter);
      }
    }, 250);
  });
  const ownArea = h(
    'div',
    { class: 'stack', hidden: true },
    h('label', { for: 'pp-new' }, 'Passphrase'),
    a,
    meter,
    h('label', { for: 'pp-confirm' }, 'Confirm passphrase'),
    b,
    h('p', { class: 'hint' }, `At least ${PASSPHRASE_MIN} characters. Several unrelated words are easier to remember than symbols. Aim for “very strong”.`),
  );
  const sync = () => {
    generatedArea.hidden = !generated.checked;
    ownArea.hidden = generated.checked;
  };
  generated.addEventListener('change', sync);
  own.addEventListener('change', sync);

  return {
    element: h(
      'div',
      { class: 'stack' },
      h('div', { class: 'row' }, h('label', { class: 'inline', for: 'pp-generated' }, generated, 'Generate words for me (recommended)'), h('label', { class: 'inline', for: 'pp-own' }, own, 'Choose my own')),
      generatedArea,
      ownArea,
    ),
    read() {
      if (generated.checked) {
        if (!written.checked) return { error: 'Write the passphrase down, then tick “I’ve written it down”.' };
        return words;
      }
      if ([...a.value].length < PASSPHRASE_MIN) return { error: `The passphrase must be at least ${PASSPHRASE_MIN} characters.` };
      if (a.value !== b.value) return { error: 'The two passphrases do not match.' };
      return a.value;
    },
  };
}

const PC_PIN_LIMITS =
  'The PIN works only on this PC and this Windows account; a copy of the folder cannot be opened with it elsewhere. It does not stop programs running as you, which can try PINs quickly, or someone who also knows your Windows password. Your passphrase still works everywhere.';

/** Opt-in short PIN for this PC (ADR 0004 §3.3). `read` gives the PIN, or null when not chosen. */
function pcPinOption(checked: boolean, hint?: string): { element: HTMLElement; read(): string | null | { error: string } } {
  const box = h('input', { type: 'checkbox', id: 'pc-pin-on', checked });
  const pins = pinPair('pc-pin', 'PIN for this PC');
  const area = h('div', { class: 'stack' }, hint ? h('p', { class: 'hint' }, hint) : null, pins.element);
  const sync = () => (area.hidden = !box.checked);
  box.addEventListener('change', sync);
  sync();
  return {
    element: h('div', { class: 'stack' }, h('label', { class: 'inline', for: 'pc-pin-on' }, box, 'Also keep a short PIN on this PC'), h('p', { class: 'hint' }, PC_PIN_LIMITS), area),
    read: () => (box.checked ? pins.read() : null),
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
  forgetMonitorPanel();
  recordCard = null;
  if (!status.unlocked) planDraft = [];
  if (!status.vaultExists) setupScreen();
  else if (!status.unlocked) unlockScreen();
  else if (!status.firstRunCompleted) void wizardScreen();
  else void appShell();
}

function setupScreen(): void {
  const chooser = passphraseChooser();
  const pcPin = pcPinOption(false);
  const message = h('div');
  const submit = h('button', { type: 'submit', class: 'primary' }, 'Create and continue');
  const form = h(
    'form',
    { class: 'card narrow stack' },
    brand(),
    h('h2', {}, 'Welcome. Choose a passphrase.'),
    h('p', {}, 'Your passphrase encrypts everything AegisWin stores and approves every repair an AI agent asks for. It is never saved anywhere, never shown to an agent, and cannot be recovered.'),
    h('p', { class: 'hint' }, `Data folder: ${status.dataDir}`),
    chooser.element,
    pcPin.element,
    message,
    submit,
  );
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const passphrase = chooser.read();
    if (typeof passphrase !== 'string') return replace(message, errorNotice({ code: 'PIN_TOO_WEAK', message: passphrase.error }));
    const pin = pcPin.read();
    if (pin !== null && typeof pin !== 'string') return replace(message, errorNotice({ code: 'PIN_TOO_WEAK', message: pin.error }));
    if (pin === passphrase) return replace(message, errorNotice({ code: 'PIN_TOO_WEAK', message: 'Use a different PIN for this PC than the passphrase.' }));
    try {
      status = await busy(submit, () => api.setupVault(passphrase));
      if (pin !== null) status = await busy(submit, () => api.setThisPcPin(passphrase, pin));
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
  const forget = h('button', { type: 'button' }, 'Forget this PC');
  forget.addEventListener('click', async () => {
    const ok = await confirmDialog('Forget this PC?', 'This deletes the short PIN for this PC. Only your passphrase will open AegisWin until you set a PIN again. Nothing else changes.', 'Forget this PC');
    if (!ok) return;
    try {
      status = await busy(forget, () => api.forgetThisPc());
      unlockScreen();
    } catch (err) {
      replace(message, errorNotice(asError(err)));
    }
  });
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
    h('label', { for: 'unlock-pin' }, status.thisPcPin ? 'Passphrase, or your PIN for this PC' : 'Passphrase (or your PIN, if you set AegisWin up before passphrases)'),
    input,
    message,
    submit,
    status.thisPcPin ? h('div', { class: 'row end' }, forget) : null,
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
  const changePill = h('span', { class: 'badge warn', role: 'status' });
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
  shellParts = { approvalsCount, mcpPill, changePill, reviews: h('div', { class: 'stack', 'aria-live': 'polite' }) };
  reviewSignature = '';
  replace(
    root,
    h(
      'div',
      { class: 'app' },
      h('header', { class: 'topbar' }, brand(), h('div', { class: 'row' }, changePill, mcpPill, adminPart, lock)),
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
  // One change runs at a time; tool results read meanwhile may show a system mid-change.
  const { running, queued } = status.change;
  const waiting = queued ? `${queued} waiting` : '';
  const text = running ? `Change in progress: ${running}${waiting ? ` · ${waiting}` : ''}` : waiting;
  shellParts.changePill.hidden = !text;
  replace(shellParts.changePill, text);
  updateRuntimeReviews(shellParts.reviews);
}

/** Runtime files the unlock check set aside (ADR 0002 §5): nothing resumes from them until the owner rewrites them. */
/** Goes to the approval record card. */
function openRecord(): void {
  selectTab('approvals');
  document.getElementById('approval-record')?.scrollIntoView({ block: 'start' });
}

function updateRuntimeReviews(host: HTMLElement): void {
  const reviews = status.runtimeReviews ?? [];
  const notices = status.resumeNotices ?? [];
  const signature = [
    status.needsPassphrase ? 'needs-passphrase' : '',
    status.approvalRecordFull ? 'record-full' : '',
    status.unwrittenRecords ? `unwritten:${status.unwrittenRecords}` : '',
    ...reviews.map((r) => `${r.pluginId}:${r.differences.join(',')}`),
    ...notices.map((n) => `gap:${n.pluginId}:${n.from ?? ''}:${n.to}`),
  ].join('|');
  if (signature === reviewSignature) return;
  reviewSignature = signature;
  const choose = (choice: 'passphrase' | 'pc') => {
    keyChoice = choice;
    selectTab('settings');
    document.getElementById('vault-key')?.scrollIntoView({ block: 'start' });
  };
  replace(
    host,
    status.needsPassphrase
      ? h(
          'div',
          { class: 'notice error', role: 'alert' },
          h('p', {}, h('strong', {}, 'Your PIN can be guessed in hours if someone copies your AegisWin folder.')),
          h('p', { class: 'hint' }, 'Choose a passphrase to protect the folder. You can keep typing your current PIN on this PC if you like. Everything keeps working until you choose.'),
          h('div', { class: 'row' }, h('button', { class: 'primary', onclick: () => choose('passphrase') }, 'Set a passphrase'), h('button', { onclick: () => choose('pc') }, 'Keep a short PIN on this PC only')),
        )
      : null,
    status.approvalRecordFull
      ? h(
          'div',
          { class: 'notice error', role: 'alert' },
          h('p', {}, h('strong', {}, 'The approval record is full, so agent requests are refused.')),
          h('p', { class: 'hint' }, 'Delete the record, or keep it for fewer days, on the Approvals tab. Both need your PIN.'),
          h('div', { class: 'row' }, h('button', { class: 'primary', onclick: openRecord }, 'Open the approval record')),
        )
      : null,
    status.unwrittenRecords
      ? h(
          'div',
          { class: 'notice error', role: 'alert' },
          h('p', {}, h('strong', {}, `AegisWin couldn't write ${status.unwrittenRecords} event(s) to its approval record.`)),
          h('p', { class: 'hint' }, 'It writes them before the next event. Until then, approvals and changes that cannot be recorded are refused. Check that the disk has space.'),
        )
      : null,
    ...notices.map((n) => {
      const name = plugins.find((p) => p.id === n.pluginId)?.name ?? n.pluginId;
      const when = (iso: string): string => new Date(iso).toLocaleString();
      const span = n.from ? `from ${when(n.from)} to ${when(n.to)}` : `until ${when(n.to)}`;
      const dismiss = h('button', {}, 'Dismiss');
      dismiss.addEventListener('click', async () => {
        await busy(dismiss, () => api.dismissResumeNotice(n.pluginId)).catch(() => undefined);
        status = await api.status();
        updateShellBadges();
      });
      return h(
        'div',
        { class: 'notice', role: 'status' },
        h('p', {}, h('strong', {}, `${name}: monitors were stopped ${span}; the gap is recorded.`)),
        h('p', { class: 'hint' }, `${n.label} AegisWin resumed them when it started. The history shows this gap with any Windows evidence.`),
        h('div', { class: 'row' }, dismiss),
      );
    }),
    ...reviews.map((r) => {
      const name = plugins.find((p) => p.id === r.pluginId)?.name ?? r.pluginId;
      const message = h('div');
      const rewrite = h('button', { class: 'primary' }, 'Rewrite it from my saved settings');
      rewrite.addEventListener('click', async () => {
        try {
          await busy(rewrite, () => api.rewriteRuntime(r.pluginId));
          status = await api.status();
          toast(`${name}: runtime file rewritten from your saved settings.`);
          updateShellBadges();
        } catch (e) {
          replace(message, errorNotice(asError(e)));
        }
      });
      return h(
        'div',
        { class: 'notice error', role: 'alert' },
        h('p', {}, h('strong', {}, `${name}: its runtime file was changed outside AegisWin and has been set aside.`)),
        h('p', {}, `What differed: ${r.differences.join(', ')}.`),
        h('p', { class: 'hint' }, 'AegisWin will not monitor while locked or resume from that file. Your saved settings are unchanged. If you did not expect this, something on this PC may have edited the data folder; the set-aside copy is kept next to it as a .rejected.json file.'),
        message,
        h('div', { class: 'row' }, rewrite),
      );
    }),
  );
}

function renderTab(): void {
  if (!mainEl) return;
  const content =
    activeTab.startsWith('plugin:') ? pluginTab(activeTab.slice(7))
    : activeTab === 'approvals' ? approvalsTab()
    : activeTab === 'mcp' ? mcpTab()
    : activeTab === 'llm' ? llmTab()
    : settingsTab();
  replace(mainEl, shellParts?.reviews ?? null, content);
}

// ---- polling for approval requests ------------------------------------------

function ticketSignature(list: TicketView[]): string {
  return list.map((t) => `${t.ticketId}:${t.status}:${t.queuePosition ?? ''}:${(t.steps ?? []).map((s) => s.status).join(',')}`).join('|');
}

function askedFor(t: TicketView): string | null {
  if (t.plan?.origin === 'owner') return null;
  return t.plan ? `An AI agent proposes an action plan with ${t.steps?.length ?? 0} step(s). Open Approvals to review it.` : `An AI agent is asking to run "${t.toolName}". Open Approvals to decide.`;
}

function startPolling(): void {
  stopPolling();
  pollTimer = window.setInterval(async () => {
    try {
      // The vault can lock without the UI asking (idle auto-lock, tray Lock).
      const now = await api.status();
      status = now;
      if (!now.unlocked) return route();
      const next = await api.listTickets();
      const before = new Set(tickets.filter((t) => t.status === 'pending_approval').map((t) => t.ticketId));
      for (const t of next) {
        const text = t.status === 'pending_approval' && !before.has(t.ticketId) ? askedFor(t) : null;
        if (text) toast(text);
      }
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
  const monitors = pluginId === 'usage-monitor';
  return h(
    'div',
    { class: 'stack' },
    h('div', {}, h('h2', {}, plugin.name), h('p', { class: 'hint' }, plugin.description)),
    planDraftPanel(),
    monitors ? monitorPanel(monitorDeps(pluginId)) : null,
    monitors ? h('h3', {}, 'Other tools') : null,
    ...plugin.tools.filter((t) => !t.appOnly && !(monitors && MONITOR_TOOLS.has(t.id))).map((tool) => toolCard(plugin, tool)),
  );
}

function monitorDeps(pluginId: string) {
  const find = (id: string) => plugins.find((p) => p.id === pluginId)?.tools.find((t) => t.id === id);
  return {
    tool: find,
    run: async (toolId: string, args: Record<string, unknown>, button: HTMLButtonElement): Promise<ToolRun> => {
      const plugin = plugins.find((p) => p.id === pluginId);
      const tool = find(toolId);
      if (!plugin || !tool) return { ok: false, error: { code: 'UNKNOWN_TOOL', message: 'This tool is not available. Check the plugin in Settings.' } };
      return invokeTool(plugin, tool, args, button);
    },
    peek: async (toolId: string): Promise<unknown> => {
      try {
        const out = await api.runTool(pluginId, toolId, {}, null);
        return out.status === 'completed' ? out.result : null;
      } catch {
        return null;
      }
    },
    llmDestination: () => {
      const e = settings?.llm.endpoint;
      return e ? { host: e.host, offLan: !e.isLan || e.relayed } : null;
    },
  };
}

function toolBadges(tool: ToolView): HTMLElement {
  return h(
    'div',
    { class: 'badges' },
    tool.readOnly ? h('span', { class: 'badge ok' }, 'read-only') : h('span', { class: 'badge warn' }, 'makes changes'),
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
  let add: HTMLButtonElement | null = null;
  if (tool.planEligible) {
    const addButton = h('button', {}, 'Add to plan');
    addButton.disabled = !tool.available || planDraft.length >= MAX_PLAN_STEPS;
    addButton.addEventListener('click', () => {
      const read = form.read();
      if ('error' in read) return replace(result, errorNotice({ code: 'INVALID_ARGUMENTS', message: read.error }));
      planDraft.push({ tool: tool.mcpName, name: tool.name, args: read.args });
      toast(`${tool.name} added to your plan (step ${planDraft.length} of ${MAX_PLAN_STEPS}).`);
      renderTab();
    });
    add = addButton;
  }
  return h(
    'section',
    { class: 'card' },
    h('div', { class: 'tool-head' }, h('div', {}, h('h3', {}, tool.name), h('p', { class: 'hint' }, tool.description)), toolBadges(tool)),
    Object.keys(tool.inputSchema.properties ?? {}).some((k) => k !== 'dryRun') ? form.element : null,
    h('div', { class: 'row', style: 'margin-top:0.8rem' }, run, dry, add),
    result,
  );
}

/** The plan the owner is building. "Review and run" opens it as a plan ticket,
 * checked and dry-run by the engine, to approve with the PIN on the Approvals tab. */
function planDraftPanel(): HTMLElement | null {
  if (planDraft.length === 0) return null;
  const title = h('input', { type: 'text', maxlength: 80, id: 'plan-title' });
  const reasoning = h('textarea', { rows: 2, maxlength: 600, id: 'plan-reasoning' });
  const message = h('div');
  const review = h('button', { class: 'primary' }, 'Review and run');
  const discard = h('button', {}, 'Clear plan');
  review.addEventListener('click', async () => {
    try {
      const ticket = await busy(review, () =>
        api.proposePlan({ title: title.value.trim() || undefined, reasoning: reasoning.value.trim() || undefined, steps: planDraft.map((s) => ({ tool: s.tool, args: s.args })) }),
      );
      planDraft = [];
      tickets = await api.listTickets();
      if (!tickets.some((t) => t.ticketId === ticket.ticketId)) tickets = [ticket, ...tickets];
      updateShellBadges();
      selectTab('approvals');
    } catch (e) {
      const err = asError(e);
      if (err.code === 'VAULT_LOCKED') return handleError(e);
      replace(message, errorNotice(err));
    }
  });
  discard.addEventListener('click', () => {
    planDraft = [];
    renderTab();
  });
  const steps = h('ol', {});
  planDraft.forEach((s, i) => {
    const remove = h('button', { class: 'link' }, 'Remove');
    remove.addEventListener('click', () => {
      planDraft.splice(i, 1);
      renderTab();
    });
    append(steps, h('li', {}, h('strong', {}, s.name), ' ', h('code', {}, JSON.stringify(s.args)), ' ', remove));
  });
  return h(
    'section',
    { class: 'card stack' },
    h('h3', {}, `Your plan: ${planDraft.length} of ${MAX_PLAN_STEPS} steps`),
    h('p', { class: 'hint' }, 'Steps run one at a time, in this order, and the plan stops at the first failure. Review and run checks every step and shows the exact commands; nothing runs until you approve it with your PIN.'),
    steps,
    h('div', { class: 'grid2' }, h('div', {}, h('label', { for: 'plan-title' }, 'Title (optional)'), title), h('div', {}, h('label', { for: 'plan-reasoning' }, 'Notes for yourself (optional)'), reasoning)),
    message,
    h('div', { class: 'row' }, review, discard),
  );
}

/** Runs a tool from the app, asking for the PIN or Off-LAN trust when needed. `error: null` means cancelled or already handled. */
async function invokeTool(plugin: PluginView, tool: ToolView, args: Record<string, unknown>, button: HTMLButtonElement): Promise<ToolRun> {
  const dryRun = args.dryRun === true;
  if (tool.requiresAdmin && !status.elevated && !dryRun) return { ok: false, error: { code: 'REQUIRES_ADMIN', message: `${tool.name} needs administrator rights.` } };
  let pin: string | null = null;
  if (tool.effectivePolicy === 'pin_required' && !dryRun) {
    pin = await askPin(`Run "${tool.name}"?`, tool.description, 'Run');
    if (pin === null) return { ok: false, error: null };
  }
  try {
    const outcome = await busy(button, () => api.runTool(plugin.id, tool.id, args, pin));
    // The app's own calls never wait for approval; that is only for agents.
    return outcome.status === 'completed' ? { ok: true, value: outcome.result } : { ok: false, error: null };
  } catch (e) {
    const err = asError(e);
    if (err.code === 'VAULT_LOCKED') {
      await handleError(e);
      return { ok: false, error: null };
    }
    if (err.code === 'OFF_LAN_TRUST_REQUIRED' && (await askTrust(plugin))) return invokeTool(plugin, tool, args, button);
    return { ok: false, error: err };
  }
}

async function runTool(plugin: PluginView, tool: ToolView, args: Record<string, unknown>, resultEl: HTMLElement, button: HTMLButtonElement): Promise<void> {
  const r = await invokeTool(plugin, tool, args, button);
  if (r.ok) showResult(resultEl, plugin, tool, r.value);
  else if (r.error?.code === 'REQUIRES_ADMIN') replace(resultEl, h('div', { class: 'result' }, adminNotice(tool.name)));
  else if (r.error) replace(resultEl, h('div', { class: 'result' }, errorNotice(r.error)));
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
  queued: ['approved, waiting its turn', 'accent'],
  running: ['running', 'accent'],
  approved: ['approved', 'ok'],
  declined: ['declined', ''],
  execution_failed: ['failed', 'danger'],
  locked_out: ['locked (wrong PINs)', 'danger'],
  expired: ['expired', ''],
  cancelled: ['cancelled', ''],
};

const STEP_TEXT: Record<string, [string, string]> = {
  pending: ['not started', ''],
  running: ['running', 'accent'],
  succeeded: ['done', 'ok'],
  failed: ['failed', 'danger'],
  skipped: ['skipped (an earlier step failed)', ''],
  cancelled: ['cancelled', ''],
};

/** Waiting for the owner, then in progress (running, then queued in turn), then finished. */
function approvalsTab(): HTMLElement {
  const pending = tickets.filter((t) => t.status === 'pending_approval');
  const active = tickets.filter((t) => t.status === 'running' || t.status === 'queued');
  active.sort((a, b) => (a.status === 'running' ? 0 : a.queuePosition ?? 99) - (b.status === 'running' ? 0 : b.queuePosition ?? 99));
  const done = tickets.filter((t) => t.status !== 'pending_approval' && !active.includes(t));
  return h(
    'div',
    { class: 'stack' },
    h('div', {}, h('h2', {}, 'Approvals'), h('p', { class: 'hint' }, 'When an AI agent calls a tool that needs your PIN, or proposes a plan of several repairs, the request waits here. The agent can also show you a browser link for the same request. Requests expire after 30 minutes (plans after 10) and are forgotten when AegisWin locks. Approved changes run one at a time, in the order you approve them.')),
    pending.length === 0 && active.length === 0 ? h('div', { class: 'card' }, h('p', {}, 'No requests are waiting.')) : null,
    pending.length ? h('h3', {}, 'Waiting for you') : null,
    ...pending.map(ticketCard),
    active.length ? h('h3', {}, 'In progress') : null,
    ...active.map(ticketCard),
    done.length ? h('h3', {}, 'Earlier requests') : null,
    ...done.map(ticketCard),
    approvalRecordCard(),
  );
}

/** Kept across re-renders of the tab (the list refreshes every 2 seconds); dropped on lock. */
let recordCard: HTMLElement | null = null;

const RECORD_LABELS: Record<string, string> = {
  created: 'Requested',
  decided: 'Decided',
  change_started: 'Change started',
  change_finished: 'Change finished',
  finished: 'Ended',
  cancelled: 'Cancelled',
  cancel_requested: 'Stop asked',
  pruned: 'Removed by retention',
  purged: 'Record deleted',
  integrity: 'Integrity problem',
};

const asText = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : JSON.stringify(v));

function recordText(e: ApprovalRecordEvent): string {
  const plan = e.plan as { title?: string; titleLabel?: string; hash?: string; steps?: unknown[] } | undefined;
  switch (e.event) {
    case 'created':
      return plan
        ? `${asText(e.toolName)} from ${asText(e.origin)}${plan.title ? `, titled "${plan.title}" (${asText(plan.titleLabel)})` : ''}, fingerprint ${asText(plan.hash).slice(0, 12)}`
        : `${asText(e.toolName)} (${asText(e.tool)}) from ${asText(e.origin)}, arguments ${asText(e.args)}`;
    case 'decided':
      return `${e.lockedOut ? `Locked after too many wrong ${e.via === 'device code' ? 'codes' : 'PINs'}` : e.approved ? 'Approved' : 'Declined'} via ${asText(e.via)}${e.comment ? `. Note: ${asText(e.comment)}` : ''}`;
    case 'change_started':
      return `${asText(e.toolName)}${e.step ? ` (step ${asText(e.step)})` : ''}${e.origin ? ` from ${asText(e.origin)}` : ''}, arguments ${asText(e.args)}`;
    case 'change_finished':
      return `${asText(e.tool)}${e.step ? ` (step ${asText(e.step)})` : ''}: ${asText(e.outcome).replace('_', ' ')}${e.error ? `. ${asText(e.error)}` : ''}`;
    case 'finished':
      return `${asText(e.status).replace('_', ' ')}${e.reason ? `. ${asText(e.reason)}` : ''}`;
    case 'cancelled':
      return `from ${asText(e.from)}${e.reason ? `. ${asText(e.reason)}` : ''}`;
    case 'pruned':
      return e.to ? `${asText(e.segment)}: events ${asText(e.from)} to ${asText(e.to)}, past the days kept` : `${asText(e.segment)}, from before integrity checks`;
    case 'purged':
      return `${asText(e.files)} file(s) deleted with your PIN; the record starts again here`;
    case 'integrity':
      return asText(e.problem);
    default:
      return '';
  }
}

/** The durable approval record (ADR 0003 §7): reading and deleting it need the PIN. App only. */
function approvalRecordCard(): HTMLElement {
  if (recordCard) return recordCard;
  const result = h('div', { class: 'stack', 'aria-live': 'polite' });
  const days = h('select', { id: 'record-days' }, ...[1, 7, 30, 90].map((d) => h('option', { value: d }, d === 1 ? 'the last day' : `the last ${d} days`)));
  days.value = '7';
  const show = h('button', { class: 'primary' }, 'Show record (PIN)');
  show.addEventListener('click', async () => {
    const pin = await askPin('Show the approval record?', 'The record of every request, decision and change is encrypted; your PIN opens it.', 'Show');
    if (!pin) return;
    try {
      const v = await busy(show, () => api.readApprovalRecord(pin, Number(days.value)));
      const problems = v.files.filter((f) => f.status !== 'ok');
      const check = v.integrity;
      setKeep(v.retention.maxDays);
      replace(
        result,
        check
          ? h(
              'div',
              { class: check.ok ? 'notice ok' : 'notice error', role: check.ok ? 'status' : 'alert' },
              h('p', {}, check.line),
              check.problems.length > 1 ? h('ul', {}, ...check.problems.map((p) => h('li', {}, p))) : null,
            )
          : null,
        h('p', { class: 'hint' }, `The last ${v.days} day(s), newest first. Kept for ${v.retention.maxDays} days.`),
        problems.length ? h('div', { class: 'notice error' }, `${problems.length} record file(s) could not be read fully: ${problems.map((f) => `${f.name} (${f.status})`).join(', ')}.`) : null,
        v.events.length === 0 ? h('p', {}, 'Nothing recorded in this period.') : null,
        v.events.length
          ? h(
              'table',
              {},
              h('tbody', {}, ...v.events.map((e) => h('tr', e.unverified ? { class: 'unverified', title: 'Failed the integrity check' } : {}, h('td', {}, new Date(e.at).toLocaleString()), h('td', {}, RECORD_LABELS[e.event] ?? e.event), h('td', { class: 'mono' }, asText(e.ticketId).slice(0, 8)), h('td', {}, recordText(e))))),
            )
          : null,
        v.omitted ? h('p', { class: 'hint' }, `${v.omitted} older event(s) not shown.`) : null,
      );
    } catch (e) {
      replace(result, errorNotice(asError(e)));
    }
  });
  const keepDays = [7, 14, 30, 60, 90];
  const keep = h('select', { id: 'record-keep' }, ...keepDays.map((d) => h('option', { value: d }, `${d} days`)));
  keep.value = '90';
  const setKeep = (days: number): void => {
    if (!keepDays.includes(days)) keep.append(h('option', { value: days }, `${days} days`));
    keep.value = String(days);
  };
  const saveKeep = h('button', {}, 'Keep (PIN)');
  saveKeep.addEventListener('click', async () => {
    const days = Number(keep.value);
    const pin = await askPin(`Keep the approval record for ${days} days?`, 'Older files are removed now. The record notes what was removed, so the gap is not reported as tampering.', 'Keep');
    if (!pin) return;
    try {
      const kept = await busy(saveKeep, () => api.setApprovalRetention(pin, days));
      toast(`The approval record is kept for ${kept.maxDays} days.`);
      status = await api.status();
      updateShellBadges();
    } catch (e) {
      replace(result, errorNotice(asError(e)));
    }
  });
  const purge = h('button', { class: 'danger' }, 'Delete the record (PIN)');
  purge.addEventListener('click', async () => {
    if (!(await confirmDialog('Delete the approval record?', 'Every record file is deleted and the record gets a new key, so deleted files cannot be read even if recovered. This cannot be undone.', 'Delete'))) return;
    const pin = await askPin('Delete the approval record?', 'Enter your PIN to delete it.', 'Delete');
    if (!pin) return;
    try {
      const removed = await busy(purge, () => api.deleteApprovalRecord(pin));
      replace(result, h('div', { class: 'notice ok' }, `Approval record deleted (${removed} file(s)).`));
      toast('Approval record deleted.');
    } catch (e) {
      replace(result, errorNotice(asError(e)));
    }
  });
  recordCard = h(
    'section',
    { class: 'card stack', id: 'approval-record' },
    h('h3', {}, 'Approval record'),
    h(
      'p',
      { class: 'hint' },
      'AegisWin keeps an encrypted record of every request, your decision, and each change it made, with its outcome, even after a request is forgotten. Only your PIN can read it, and agents cannot. Requests that expire unanswered show only as requested.',
    ),
    h('div', { class: 'row' }, h('label', { for: 'record-days' }, 'Show'), days, show),
    result,
    h('div', { class: 'row' }, h('label', { for: 'record-keep' }, 'Keep for'), keep, saveKeep, purge),
  );
  return recordCard;
}

/** Refreshes the list after a decision or cancel, so the card shows its new state. */
async function reloadTickets(): Promise<void> {
  tickets = await api.listTickets();
  updateShellBadges();
  renderTab();
}

/** A PIN-free button that only withdraws or stops. */
function cancelButton(t: TicketView, label: string, message: HTMLElement): HTMLButtonElement {
  const button = h('button', {}, label);
  button.addEventListener('click', async () => {
    try {
      await busy(button, () => api.cancelTicket(t.ticketId));
      await reloadTickets();
    } catch (e) {
      replace(message, errorNotice(asError(e)));
      await reloadTickets().catch(() => undefined);
    }
  });
  return button;
}

/** Draws a QR code from its SVG path data, element by element. */
function qrSvg(qr: DeviceCodeView['qr']): SVGSVGElement {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${qr.size} ${qr.size}`);
  svg.setAttribute('width', '180');
  svg.setAttribute('height', '180');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'QR code for the device page');
  svg.setAttribute('shape-rendering', 'crispEdges');
  const bg = document.createElementNS(ns, 'rect');
  bg.setAttribute('width', String(qr.size));
  bg.setAttribute('height', String(qr.size));
  bg.setAttribute('fill', '#fff');
  const dark = document.createElementNS(ns, 'path');
  dark.setAttribute('d', qr.path);
  dark.setAttribute('fill', '#000');
  svg.append(bg, dark);
  return svg;
}

/** Shows a one-time code, link and QR code for approving on another device. */
function deviceCodeButton(t: TicketView): Node[] {
  const area = h('div', { class: 'stack' });
  const button = h('button', {}, 'Approve on another device');
  button.addEventListener('click', async () => {
    try {
      const c = await busy(button, () => api.showDeviceCode(t.ticketId));
      replace(
        area,
        h(
          'div',
          { class: 'card stack device-code' },
          h('p', {}, 'On your phone or other device, open this page (or scan the code), check the request, and type this code to approve:'),
          h('p', { class: 'device-code-value' }, h('code', {}, c.code)),
          h('div', { class: 'row' }, qrSvg(c.qr), h('div', { class: 'stack grow' }, h('code', {}, c.url), h('button', { onclick: () => copyText(c.url) }, 'Copy link'))),
          h('p', { class: 'hint' }, `The code works once, for this request only, until ${new Date(c.expiresAt).toLocaleTimeString()}. Asking for a new one replaces it. The page never asks for your PIN.`),
        ),
      );
    } catch (e) {
      replace(area, errorNotice(asError(e)));
    }
  });
  return [h('div', { class: 'row' }, button), area];
}

/** PIN and note fields with Approve and Decline; a plan's approval names its hash. */
function decisionForm(t: TicketView, approveLabel: string): Node[] {
  const pin = h('input', { type: 'password', autocomplete: 'off', id: `pin-${t.ticketId}` });
  const comment = h('textarea', { rows: 2, maxlength: 500, id: `comment-${t.ticketId}` });
  const message = h('div');
  const approve = h('button', { class: 'primary' }, approveLabel);
  const decline = h('button', {}, 'Decline');
  const decide = async (yes: boolean, button: HTMLButtonElement) => {
    if (!pin.value) return replace(message, errorNotice({ code: 'PIN_REQUIRED', message: 'Enter your PIN to approve or decline.' }));
    try {
      await busy(button, () => api.decideTicket(t.ticketId, yes, pin.value, comment.value.trim() || null, t.plan?.hash ?? null));
      pin.value = '';
      comment.value = '';
      await reloadTickets();
    } catch (e) {
      pin.value = '';
      const err = asError(e);
      replace(message, errorNotice(err));
      if (err.code === 'CONFLICT' || err.code === 'NOT_FOUND' || (err.code === 'PIN_LOCKED_OUT' && err.message.includes('request'))) {
        await reloadTickets();
      }
    }
  };
  approve.addEventListener('click', () => decide(true, approve));
  decline.addEventListener('click', () => decide(false, decline));
  return [
    h('div', { class: 'grid2' }, h('div', {}, h('label', { for: `pin-${t.ticketId}` }, 'Your PIN'), pin, h('div', { class: 'hint' }, `${t.attemptsRemaining} attempt(s) left for this request`)), h('div', {}, h('label', { for: `comment-${t.ticketId}` }, 'Note for the agent (optional)'), comment)),
    h('p', { class: 'hint' }, 'AegisWin only asks for your PIN in this window. A web page asking for it is not AegisWin.'),
    message,
    h('div', { class: 'row', style: 'margin-top:0.6rem' }, approve, decline),
    ...(settings?.mcp.deviceApproval && settings.mcp.status.running ? deviceCodeButton(t) : []),
  ];
}

function decidedNotes(t: TicketView): Node[] {
  const out: Node[] = [];
  if (t.decidedVia) out.push(h('p', { class: 'hint' }, `Decided ${t.decidedVia === 'device code' ? 'on another device' : 'in the app'}${t.comment ? `: "${t.comment}"` : ''}`));
  if (t.error) out.push(errorNotice(t.error));
  return out;
}

/** Supplied text, kept apart from what AegisWin wrote and labelled with who wrote it. */
function suppliedText(label: string, ...parts: Array<HTMLElement | null>): HTMLElement {
  return h('div', { class: 'ai-text' }, h('div', { class: 'hint' }, label), ...parts);
}

/** The plan review (ADR 0003 §2): AegisWin's summary and steps, then the supplied text. */
function planCard(t: TicketView, plan: NonNullable<TicketView['plan']>): HTMLElement {
  const [base, tone] = STATUS_TEXT[t.status] ?? [t.status, ''];
  const pending = t.status === 'pending_approval';
  const steps = t.steps ?? [];
  const head = h(
    'div',
    { class: 'tool-head' },
    h('div', {}, h('h3', {}, t.toolName), h('p', { class: 'hint' }, `${plan.origin === 'owner' ? 'Your plan' : 'From an AI agent'} · requested ${new Date(t.createdAt).toLocaleString()}${pending ? ` · expires ${new Date(plan.expiresAt).toLocaleTimeString()}` : ''}`)),
    h('div', { class: 'badges' }, t.requiresAdmin ? h('span', { class: 'badge danger' }, 'administrator') : null, h('span', { class: `badge ${tone}` }, t.status === 'queued' && t.queuePosition ? `${base} (#${t.queuePosition})` : base)),
  );
  const body: Node[] = [head, h('p', {}, h('strong', {}, plan.summary))];
  if (plan.origin !== 'owner') body.push(h('p', { class: 'hint' }, 'Plan fingerprint: ', h('code', {}, plan.shortHash), '. If the agent told you one, it should match.'));
  body.push(h('p', { class: 'hint' }, 'The steps run one at a time, in this order. The plan stops at the first failure, and changes made by earlier steps stay: Windows repairs cannot be undone.'));
  const list = h('ol', { class: 'stack' });
  for (const s of steps) {
    const [stepText, stepTone] = STEP_TEXT[s.status] ?? [s.status, ''];
    append(
      list,
      h(
        'li',
        {},
        h(
          'div',
          { class: 'tool-head' },
          h('div', {}, h('strong', {}, s.toolName), h('span', { class: 'hint' }, ` · ${s.pluginId}`)),
          h('div', { class: 'badges' }, s.requiresAdmin ? h('span', { class: 'badge danger' }, 'administrator') : null, pending ? null : h('span', { class: `badge ${stepTone}` }, stepText)),
        ),
        h('p', {}, s.toolDescription),
        h('div', { class: 'hint' }, 'Arguments'),
        h('pre', {}, JSON.stringify(s.args, null, 2)),
        h('div', { class: 'hint' }, 'Commands it will run'),
        h('pre', {}, s.commands.length ? s.commands.join('\n') : '(the dry run listed no commands)'),
        s.reasoning ? suppliedText(plan.suppliedLabel, h('p', {}, s.reasoning)) : null,
        s.error ? errorNotice(s.error) : null,
        s.result !== undefined ? h('details', {}, h('summary', {}, 'Result'), renderValue(s.result), rawJson(s.result)) : null,
      ),
    );
  }
  body.push(list);
  const { title, reasoning } = plan;
  if (title || reasoning) body.push(suppliedText(plan.suppliedLabel, title ? h('p', {}, h('strong', {}, title)) : null, reasoning ? h('p', {}, reasoning) : null));
  for (const flag of plan.flags) body.push(h('div', { class: 'notice' }, flag));
  if (plan.stopReason) body.push(h('div', { class: 'notice' }, plan.stopReason));
  const message = h('div');
  if (pending) {
    body.push(...decisionForm(t, `Approve and run ${steps.length} step${steps.length === 1 ? '' : 's'}`));
  } else {
    body.push(...decidedNotes(t));
    if (t.status === 'running') body.push(message, h('div', { class: 'row' }, cancelButton(t, 'Stop after this step', message)));
    if (t.status === 'queued') body.push(message, h('div', { class: 'row' }, cancelButton(t, 'Cancel before it starts', message)));
  }
  return h('section', { class: 'card ticket' }, ...body);
}

function ticketCard(t: TicketView): HTMLElement {
  if (t.plan) return planCard(t, t.plan);
  const [base, tone] = STATUS_TEXT[t.status] ?? [t.status, ''];
  const label = t.status === 'queued' && t.queuePosition ? `${base} (#${t.queuePosition})` : base;
  const head = h(
    'div',
    { class: 'tool-head' },
    h('div', {}, h('h3', {}, t.toolName), h('p', { class: 'hint' }, `${t.pluginId} · requested ${new Date(t.createdAt).toLocaleString()}`)),
    h('div', { class: 'badges' }, t.requiresAdmin ? h('span', { class: 'badge danger' }, 'administrator') : null, h('span', { class: `badge ${tone}` }, label)),
  );
  const body: Node[] = [head, h('p', {}, t.toolDescription)];
  if (t.review) {
    body.push(
      h('div', { class: 'hint' }, 'What this does (written by AegisWin from the arguments)'),
      h('ul', {}, ...t.review.lines.map((line) => h('li', {}, line))),
      ...t.review.warnings.map((w) => h('div', { class: 'notice' }, w)),
    );
  }
  body.push(h('div', { class: 'hint' }, 'Arguments'), h('pre', {}, JSON.stringify(t.args, null, 2)));
  if (t.status === 'pending_approval') {
    body.push(...decisionForm(t, 'Approve and run'));
  } else {
    body.push(...decidedNotes(t));
    if (t.result !== undefined) body.push(h('details', {}, h('summary', {}, 'Result'), renderValue(t.result), rawJson(t.result)));
    if (t.status === 'queued') {
      const message = h('div');
      body.push(message, h('div', { class: 'row' }, cancelButton(t, 'Cancel before it starts', message)));
    }
  }
  return h('section', { class: 'card ticket' }, ...body);
}

// ---- MCP --------------------------------------------------------------------

function mcpTab(): HTMLElement {
  const container = h('div', { class: 'stack' }, h('h2', {}, 'MCP server'), h('p', { class: 'hint' }, 'Lets AI agents such as Claude call AegisWin tools over the Model Context Protocol. Tools set to “needs my PIN” wait until you approve them on the Approvals tab; the rest run right away. Repairs need your PIN by default.'));
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
      s.localUrl
        ? h('div', {}, h('div', { class: 'hint' }, 'AI clients on this PC can keep using'), h('div', { class: 'row' }, h('code', { class: 'grow' }, s.localUrl), h('button', { onclick: () => copyText(s.localUrl!) }, 'Copy URL')))
        : null,
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

  const deviceCard = h('section', { class: 'card stack' });
  const renderDevice = () => {
    const m = settings!.mcp;
    const toggle = h('button', { class: m.deviceApproval ? '' : 'primary' }, m.deviceApproval ? 'Turn off' : 'Turn on (PIN)');
    toggle.addEventListener('click', async () => {
      try {
        if (m.deviceApproval) {
          await busy(toggle, () => api.setDeviceApproval(false, null));
        } else {
          const pin = await askPin('Approve from another device?', 'Each request then gets an “Approve on another device” button that shows a one-time code. Anyone who can reach the MCP server could open the page, but only the code approves.', 'Turn on');
          if (pin === null) return;
          await busy(toggle, () => api.setDeviceApproval(true, pin));
        }
        settings = await api.getSettings();
        renderDevice();
      } catch (e) {
        await handleError(e);
      }
    });
    replace(
      deviceCard,
      h('div', { class: 'row' }, h('h3', { class: 'grow' }, 'Approve from another device'), h('span', { class: `badge ${m.deviceApproval ? 'ok' : ''}` }, m.deviceApproval ? 'on' : 'off'), toggle),
      h('p', { class: 'hint' }, 'Off by default and turned off again whenever AegisWin locks. When on, a request can be approved from a phone or other PC with a one-time code shown here; declining needs no code. AegisWin never asks for your PIN on a web page.'),
      m.deviceApprovalNotice ? h('div', { class: 'notice' }, m.deviceApprovalNotice) : null,
    );
  };
  renderDevice();

  const tokenArea = h('div', { class: 'stack' });
  const reveal = h('button', {}, 'Show token and setup commands');
  reveal.addEventListener('click', async () => {
    const pin = await askPin('Show the MCP token?', 'Anyone with this token can ask AegisWin to run tools (changes still need your PIN). Only paste it into AI clients you trust.', 'Show');
    if (pin === null) return;
    try {
      const token = await api.revealMcpToken(pin);
      // Clients on this PC always use 127.0.0.1; a LAN bind adds a URL for other devices.
      const { mcp: m } = settings!;
      const lan = m.host !== '127.0.0.1';
      const thisPc = m.status.localUrl ?? (lan ? null : m.status.url) ?? `http://127.0.0.1:${m.port}/mcp`;
      const network = lan ? (m.status.url ?? `http://${m.host}:${m.port}/mcp`) : null;
      const claudeCode = (url: string) => `claude mcp add --transport http aegis-win ${url} --header "Authorization: Bearer ${token}"`;
      const json = (url: string) => JSON.stringify({ mcpServers: { 'aegis-win': { type: 'http', url, headers: { Authorization: `Bearer ${token}` } } } }, null, 2);
      const snippet = (label: string, text: string, button: string) => h('div', {}, h('div', { class: 'hint' }, label), h('pre', {}, text), h('button', { onclick: () => copyText(text) }, button));
      replace(
        tokenArea,
        h('div', { class: 'row' }, h('code', { class: 'grow' }, token), h('button', { onclick: () => copyText(token) }, 'Copy token')),
        snippet(lan ? 'Claude Code on this PC' : 'Claude Code', claudeCode(thisPc), 'Copy command'),
        snippet(lan ? 'JSON config on this PC (clients that support HTTP servers)' : 'JSON config (clients that support HTTP servers)', json(thisPc), 'Copy JSON'),
        network ? snippet('Claude Code on another device on your network', claudeCode(network), 'Copy command') : null,
        network ? snippet('JSON config on another device on your network', json(network), 'Copy JSON') : null,
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

  return h('div', { class: 'stack' }, container, statusCard, configCard, deviceCard, tokenCard, gatesCard());
}

function gatesCard(): HTMLElement {
  const rows = plugins
    .filter((p) => p.installed)
    .flatMap((p) =>
      p.tools.filter((t) => !t.appOnly).map((t) => {
        const select = h('select', { 'aria-label': `Gate for ${t.name}` }, h('option', { value: 'auto' }, 'runs immediately'), h('option', { value: 'pin_required' }, 'needs my PIN'));
        select.value = t.effectivePolicy;
        select.addEventListener('change', async () => {
          const policy = select.value as 'auto' | 'pin_required';
          let pin: string | null = null;
          if (policy === 'auto' && t.effectivePolicy === 'pin_required') {
            pin = await askPin(`Let agents run "${t.name}" without asking?`, t.readOnly ? 'This tool only reads information.' : 'This tool makes changes. Agents will be able to run it without your approval.', 'Allow');
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
        return h('tr', {}, h('td', {}, t.name, h('div', { class: 'hint mono' }, t.mcpName)), h('td', {}, t.readOnly ? 'read-only' : 'makes changes', t.requiresAdmin ? ', administrator' : ''), h('td', {}, select));
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
  const context = h('input', { type: 'number', id: 'llm-context', min: '2048', max: '131072', step: '1024', value: String(llm.contextTokens) });
  const firstWait = h('input', { type: 'number', id: 'llm-first-wait', min: '30', max: '900', step: '10', value: String(llm.firstTokenSecs) });
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
      settings = await busy(save, () => api.updateSettings({ llmBaseUrl: baseUrl.value, llmModel: model.value, llmContextTokens: Number(context.value), llmFirstTokenSecs: Number(firstWait.value) }));
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
      // Ollama lists "name:latest" for a model saved as plain "name".
      const saved = settings!.llm.model;
      const installed = out.models.some((m) => m === saved || m === `${saved}:latest` || `${m}:latest` === saved);
      replace(
        models,
        out.models.length && !installed ? h('div', { class: 'badge warn' }, `The saved model "${saved}" is not on this server. Pick one below, then Save.`) : null,
        ...out.warnings.map((w) => h('div', { class: 'badge warn' }, w)),
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
    h('section', { class: 'card' }, h('h3', {}, 'Endpoint'), h('label', { for: 'llm-url' }, 'Base URL'), baseUrl, h('div', { class: 'hint' }, 'Ollama: http://127.0.0.1:11434/v1 · LM Studio: http://127.0.0.1:1234/v1'), h('label', { for: 'llm-model' }, 'Model'), model, h('label', { for: 'llm-context' }, 'Context window (tokens)'), context, h('div', { class: 'hint' }, 'How much the model reads at once. 8192 suits most local models; raise it for long monitor chats if your model allows. AegisWin sets it on Ollama; on other servers, match what the model is loaded with.'), h('label', { for: 'llm-first-wait' }, 'First answer wait (seconds)'), firstWait, h('div', { class: 'hint' }, 'How long to wait for the model to start answering; loading a large model can take minutes. Once it answers, AegisWin allows 60 seconds between pieces and 10 minutes in all.'), h('div', { style: 'margin-top:0.6rem' }, classification), h('div', { class: 'row', style: 'margin-top:0.8rem' }, save, test), models),
    h('section', { class: 'card' }, h('div', { class: 'row' }, h('h3', { class: 'grow' }, 'API key'), keyState), h('p', { class: 'hint' }, 'Stored encrypted in the vault and never shown again. Local servers usually need none.'), key, h('div', { class: 'row', style: 'margin-top:0.6rem' }, saveKey, clearKey)),
    h('section', { class: 'card' }, h('h3', {}, 'Off-LAN permission'), h('p', { class: 'hint' }, 'An endpoint outside your network only receives data from plugins you allow, after personal details are scrubbed. Changing the endpoint to a different host clears these permissions.'), trustBody),
  );
}

// ---- settings ---------------------------------------------------------------

/** Sets a new passphrase (ADR 0004 §3.2), optionally keeping a short PIN on this PC. */
function vaultKeyCard(): HTMLElement {
  const choice = keyChoice;
  keyChoice = null;
  const card = h('div');
  const current = h('input', { type: 'password', id: 'key-current', autocomplete: 'current-password' });
  const chooser = passphraseChooser();
  const pcPin = pcPinOption(
    choice === 'pc' || status.thisPcPin,
    choice === 'pc' ? 'To keep typing your current PIN on this PC, enter it here too.' : status.thisPcPin ? 'A new passphrase replaces the PIN for this PC; enter it again to keep it.' : undefined,
  );
  const message = h('div');
  const submit = h('button', { class: 'primary', type: 'submit' }, 'Set passphrase');
  const form = h(
    'form',
    { class: 'card stack', id: 'vault-key' },
    h('h3', {}, status.needsPassphrase ? 'Choose a passphrase' : 'Change passphrase'),
    h('label', { for: 'key-current' }, status.needsPassphrase ? 'Current PIN' : 'Current passphrase or PIN for this PC'),
    current,
    chooser.element,
    pcPin.element,
    message,
    h('div', { class: 'row end' }, submit),
  );
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const next = chooser.read();
    if (typeof next !== 'string') return replace(message, errorNotice({ code: 'PIN_TOO_WEAK', message: next.error }));
    const pin = pcPin.read();
    if (pin !== null && typeof pin !== 'string') return replace(message, errorNotice({ code: 'PIN_TOO_WEAK', message: pin.error }));
    try {
      status = await busy(submit, () => api.changePassphrase(current.value, next, pin));
      current.value = '';
      toast('Passphrase set. Your AegisWin folder is now encrypted with a new key.');
      updateShellBadges();
      selectTab('settings');
    } catch (err) {
      current.value = '';
      replace(message, errorNotice(asError(err)));
    }
  });
  replace(card, form);
  return card;
}

/** The short PIN for this PC (ADR 0004 §3.3): set, change, or forget. */
function thisPcCard(): HTMLElement {
  const card = h('section', { class: 'card stack' });
  const render = () => {
    const current = h('input', { type: 'password', id: 'pc-current', autocomplete: 'current-password' });
    const pins = pinPair('pc-set', status.thisPcPin ? 'New PIN for this PC' : 'PIN for this PC');
    const message = h('div');
    const save = h('button', { class: 'primary', type: 'submit' }, status.thisPcPin ? 'Change PIN' : 'Set PIN');
    const form = h('form', { class: 'stack' }, h('label', { for: 'pc-current' }, 'Current passphrase or PIN'), current, pins.element, message, h('div', { class: 'row end' }, save));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pin = pins.read();
      if (typeof pin !== 'string') return replace(message, errorNotice({ code: 'PIN_TOO_WEAK', message: pin.error }));
      try {
        status = await busy(save, () => api.setThisPcPin(current.value, pin));
        toast('PIN for this PC saved.');
        render();
      } catch (err) {
        current.value = '';
        replace(message, errorNotice(asError(err)));
      }
    });
    const forget = h('button', { type: 'button' }, 'Forget this PC');
    forget.addEventListener('click', async () => {
      const ok = await confirmDialog('Forget this PC?', 'This deletes the short PIN for this PC. Only your passphrase will open AegisWin until you set a PIN again.', 'Forget this PC');
      if (!ok) return;
      try {
        status = await busy(forget, () => api.forgetThisPc());
        render();
      } catch (err) {
        replace(message, errorNotice(asError(err)));
      }
    });
    replace(
      card,
      h('div', { class: 'row' }, h('h3', { class: 'grow' }, 'Short PIN on this PC'), h('span', { class: `badge ${status.thisPcPin ? 'ok' : ''}` }, status.thisPcPin ? 'on' : 'off'), status.thisPcPin ? forget : null),
      h('p', { class: 'hint' }, PC_PIN_LIMITS),
      status.needsPassphrase ? h('p', { class: 'hint' }, 'Choose a passphrase first.') : form,
    );
  };
  render();
  return card;
}

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

  const autoLock = h('select', { id: 'auto-lock' }, ...[5, 15, 30, 60].map((m) => h('option', { value: m }, `${m} minutes`)));
  autoLock.value = String(settings?.autoLockMinutes ?? 15);
  autoLock.addEventListener('change', async () => {
    try {
      settings = await api.updateSettings({ autoLockMinutes: Number(autoLock.value) });
      toast('Auto-lock updated.');
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

  const keyCard = vaultKeyCard();
  const pcCard = thisPcCard();

  return h(
    'div',
    { class: 'stack' },
    h('h2', {}, 'Settings'),
    h('section', { class: 'card' }, h('h3', {}, 'Display'), h('label', { for: 'ui-scale' }, 'Text size'), h('div', { class: 'row' }, scale, scaleLabel)),
    h(
      'section',
      { class: 'card' },
      h('h3', {}, 'Security'),
      h('label', { for: 'auto-lock' }, 'Lock automatically after no use for'),
      autoLock,
      h('p', { class: 'hint' }, 'Clicks, typing, and entering your PIN count as use. Nothing an AI agent does counts. Running monitors keep going while locked.'),
    ),
    h('section', { class: 'stack' }, h('h3', {}, 'Plugins and components'), selector.element, h('div', { class: 'row end' }, savePlugins)),
    autostartCard(),
    keyCard,
    pcCard,
    h(
      'section',
      { class: 'card' },
      h('h3', {}, 'About'),
      h('dl', { class: 'kv' }, h('dt', {}, 'Version'), h('dd', {}, status.version), h('dt', {}, 'Data folder'), h('dd', { class: 'mono' }, status.dataDir), h('dt', {}, 'Running as'), h('dd', {}, status.elevated ? 'administrator' : 'standard user')),
    ),
  );
}

/** The opt-in Startup shortcut (ADR 0002 §6). Turning it on needs the PIN; off does not. */
function autostartCard(): HTMLElement {
  const body = h('div', { class: 'stack' }, h('p', { class: 'hint' }, 'Checking…'));
  const card = h(
    'section',
    { class: 'card', id: 'autostart' },
    h('h3', {}, 'Start with Windows'),
    body,
    h(
      'p',
      { class: 'hint' },
      'This only adds a shortcut named "AegisWin Monitor" to your Startup folder; nothing goes in the registry. If you delete or move this AegisWin folder, it cannot remove that shortcut: turn it off in Task Manager > Startup apps, or delete it from the Startup folder.',
    ),
  );
  const show = (view: AutostartView): void => {
    const message = h('div');
    const fail = (e: unknown) => replace(message, errorNotice(asError(e)));
    const enable = async (button: HTMLButtonElement): Promise<void> => {
      const pin = await askPin('Start AegisWin when you sign in?', 'At sign-in AegisWin starts in the tray, locked, and resumes your running monitors.', 'Turn on');
      if (!pin) return;
      try {
        show(await busy(button, () => api.enableAutostart(pin, false)));
      } catch (e) {
        const err = asError(e);
        if (err.code !== 'CONFLICT') return fail(err);
        if (!(await confirmDialog('Replace the other shortcut?', err.message, 'Replace'))) return;
        try {
          show(await busy(button, () => api.enableAutostart(pin, true)));
        } catch (again) {
          fail(again);
        }
      }
    };
    const remove = async (button: HTMLButtonElement): Promise<void> => {
      try {
        show(await busy(button, () => api.disableAutostart()));
      } catch (e) {
        fail(e);
      }
    };
    const action = (label: string, run: (b: HTMLButtonElement) => Promise<void>, primary = false): HTMLButtonElement => {
      const b = h('button', primary ? { class: 'primary' } : {}, label);
      b.addEventListener('click', () => void run(b));
      return b;
    };
    const parts: HTMLElement[] = [];
    if (view.state === 'on') {
      parts.push(h('p', {}, 'On: when you sign in, AegisWin starts in the tray, locked, and resumes your running monitors.'), h('div', { class: 'row' }, action('Turn off', remove)));
    } else if (view.state === 'off') {
      parts.push(h('p', {}, 'Off: monitors resume only when you start AegisWin yourself.'));
      if (view.wanted) parts.push(h('div', { class: 'row' }, action('Turn on (PIN)', enable, true)));
      else parts.push(h('p', { class: 'hint' }, 'Save a monitor on the Usage Monitor tab first.'));
    } else {
      const what = view.state === 'different' ? `It starts ${view.target}${view.arguments ? ` ${view.arguments}` : ''}, not this copy.` : `It could not be read (${view.reason}).`;
      parts.push(
        h('div', { class: 'notice error', role: 'alert' }, h('p', {}, h('strong', {}, 'A Startup shortcut named AegisWin Monitor points somewhere else.')), h('p', {}, what), h('p', { class: 'hint' }, 'This happens when the AegisWin folder moved, a USB drive got a new letter, or another copy set it up.')),
        h('div', { class: 'row' }, ...(view.wanted ? [action('Update to this copy (PIN)', enable, true)] : []), action('Remove', remove)),
      );
    }
    replace(body, ...parts, h('p', { class: 'hint mono' }, view.shortcut), message);
  };
  api.getAutostart().then(show, (e) => replace(body, errorNotice(asError(e))));
  return card;
}

// ---- start ------------------------------------------------------------------

/** Tells the idle auto-lock the owner is here, at most every 30 seconds. */
let lastActivity = 0;
function noteActivity(): void {
  if (!status?.unlocked || Date.now() - lastActivity < 30_000) return;
  lastActivity = Date.now();
  api.noteActivity().catch(() => {});
}
document.addEventListener('pointerdown', noteActivity, true);
document.addEventListener('keydown', noteActivity, true);

async function boot(): Promise<void> {
  try {
    await refreshStatus();
    route();
  } catch (e) {
    replace(root, h('div', { class: 'center' }, h('div', { class: 'card narrow stack' }, brand(), errorNotice(asError(e)), h('p', { class: 'hint' }, 'AegisWin must be started as the desktop app (npm run tauri:dev), not in a regular browser.'))));
  }
}

void boot();
