// The usage monitor's own screen (ADR 0002): saved monitors, the AI monitor
// creator chat, and the rule editor. Every rule shown here is described by
// AegisWin's code (propose_monitor / list_monitors), never by AI text, and
// nothing starts without activate_monitor, which needs the PIN.

import type { AegisError, ToolView } from './api';
import { confirmDialog, h, replace, toast } from './dom';
import { renderValue } from './render';

export type ToolRun = { ok: true; value: unknown } | { ok: false; error: AegisError | null };

export interface MonitorDeps {
  tool(id: string): ToolView | undefined;
  /** Runs a usage-monitor tool, asking for the PIN or Off-LAN trust when the engine needs it. `error: null` means the owner cancelled. */
  run(toolId: string, args: Record<string, unknown>, button: HTMLButtonElement): Promise<ToolRun>;
  /** Where the first chat message would go, from the LLM settings. */
  llmDestination(): { host: string; offLan: boolean } | null;
}

/** Tools this screen handles; the plugin tab does not show generic forms for them. */
export const MONITOR_TOOLS = new Set(['propose_monitor', 'activate_monitor', 'list_monitors', 'pause_monitor', 'delete_monitor', 'monitor_chat_start', 'monitor_chat_reply', 'monitor_chat_cancel', 'read_monitor_history', 'configure_history_retention', 'purge_telemetry_history']);

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const lines = (v: unknown): string[] => arr(v).map(str).filter(Boolean);

function errorBox(e: AegisError): HTMLElement {
  return h('div', { class: 'notice error', role: 'alert' }, e.message);
}

// Kept across tab switches; forgotten when the app re-routes (lock, unlock).
let panel: HTMLElement | null = null;

export function forgetMonitorPanel(): void {
  panel = null;
}

export function monitorPanel(deps: MonitorDeps): HTMLElement {
  if (panel) return panel;
  const list = monitorList(deps);
  const editor = ruleEditor(deps, () => list.refresh());
  list.onAdjust = (rule, id) => editor.load(rule, id);
  const chat = monitorChat(deps, (rule) => editor.load(rule, null), () => list.refresh());
  const hint = h('p', { class: 'hint' }, 'While a monitor runs, closing this window keeps AegisWin running in the tray, and locking keeps the monitor going: it then records only to the encrypted history, which nothing can read until you unlock. Pause or resume from the tray icon; Quit there to stop.');
  const history = historyCard(deps);
  list.onRetention = history.showRetention;
  panel = h('div', { class: 'stack' }, hint, list.element, chat, editor.element, history.element);
  return panel;
}

// ---- code-written review -----------------------------------------------------

/** The description and privacy flags AegisWin wrote from the rule itself. */
function reviewView(review: unknown): HTMLElement {
  const r = obj(review);
  return h(
    'div',
    { class: 'stack' },
    h('div', { class: 'hint' }, 'What this monitor does (written by AegisWin from the rule)'),
    h('ul', {}, ...lines(r.description).map((l) => h('li', {}, l))),
    ...arr(r.privacyFlags).map((f) => h('div', { class: 'notice' }, str(obj(f).explanation))),
  );
}

function replayView(replay: unknown): HTMLElement | null {
  const r = obj(replay);
  if (typeof r.samples !== 'number') return null;
  const summary =
    r.samples === 0
      ? 'There are no recorded samples to check it against yet.'
      : `Over ${r.samples} recorded samples (${new Date(str(r.from)).toLocaleTimeString()} to ${new Date(str(r.to)).toLocaleTimeString()}) it would have fired ${r.wouldHaveFired} time(s).`;
  const hits = arr(r.firstHits);
  return h('div', {}, h('p', {}, summary), h('p', { class: 'hint' }, str(r.note)), hits.length ? h('details', {}, h('summary', {}, 'When it would have fired'), renderValue(hits)) : null);
}

/** Text an AI wrote, always labelled as such and kept apart from the review. */
function aiText(label: string, text: string, warning?: string): HTMLElement {
  return h('div', { class: 'ai-text' }, h('div', { class: 'hint' }, label), h('p', {}, text), warning ? h('div', { class: 'notice' }, warning) : null);
}

/** A checked, not-yet-running rule: review, replay, reasoning, and the PIN-gated start. */
function proposalView(deps: MonitorDeps, proposal: unknown, replaceId: string | null, actions: { adjust?: () => void; started: () => void }): HTMLElement {
  const p = obj(proposal);
  const rule = p.rule;
  const reasoning = obj(p.reasoning);
  const message = h('div');
  const start = h('button', { class: 'primary' }, replaceId ? `Replace monitor ${replaceId} (PIN)` : 'Start this monitor (PIN)');
  start.addEventListener('click', async () => {
    const args: Json = { rule };
    if (replaceId) args.replaceId = replaceId;
    const r = await deps.run('activate_monitor', args, start);
    if (r.ok) {
      toast(`Monitor ${str(obj(r.value).id)} is running.`);
      replace(message, h('div', { class: 'notice ok' }, `Monitor ${str(obj(r.value).id)} is running. It watches and records while AegisWin runs, also while locked.`));
      start.disabled = true;
      actions.started();
    } else if (r.error) replace(message, errorBox(r.error));
  });
  const adjust = actions.adjust ? h('button', { onclick: actions.adjust }, 'Adjust in the editor') : null;
  return h(
    'div',
    { class: 'stack proposal' },
    h('h4', {}, str(obj(p.review).name) || 'Proposed monitor'),
    reviewView(p.review),
    replayView(p.replay),
    str(reasoning.text) ? aiText(str(reasoning.label), str(reasoning.text), str(reasoning.warning) || undefined) : null,
    h('p', { class: 'hint' }, 'Nothing runs until you start it.'),
    message,
    h('div', { class: 'row' }, start, adjust),
  );
}

// ---- saved monitors ------------------------------------------------------------

function monitorList(deps: MonitorDeps): { element: HTMLElement; refresh(): void; onAdjust: (rule: unknown, id: string) => void; onRetention: (r: Json) => void } {
  const body = h('div', { class: 'stack' });
  const refreshButton = h('button', {}, 'Refresh');
  const self = {
    element: h('section', { class: 'card stack' }, h('div', { class: 'row' }, h('h3', { class: 'grow' }, 'Your monitors'), refreshButton), body),
    onAdjust: (_rule: unknown, _id: string) => {},
    onRetention: (_r: Json) => {},
    refresh: () => void load(),
  };
  const load = async () => {
    const r = await deps.run('list_monitors', {}, refreshButton);
    if (!r.ok) return r.error ? replace(body, errorBox(r.error)) : undefined;
    const v = obj(r.value);
    const monitors = arr(v.monitors).map(obj);
    if (v.historyRetention) self.onRetention(obj(v.historyRetention));
    replace(
      body,
      h('p', { class: 'hint' }, str(v.note)),
      str(v.loadError) ? errorBox({ code: 'FAILED', message: str(v.loadError) }) : null,
      monitors.length === 0 ? h('p', {}, 'No monitors yet. Describe one to the AI below, or build one in the editor.') : null,
      ...monitors.map((m) => monitorCard(deps, m, self)),
    );
  };
  refreshButton.addEventListener('click', () => void load());
  void load();
  return self;
}

function monitorCard(deps: MonitorDeps, m: Json, list: { refresh(): void; onAdjust: (rule: unknown, id: string) => void }): HTMLElement {
  const id = str(m.id);
  const paused = m.paused === true;
  const problems = lines(m.problems);
  const state = m.running === true ? h('span', { class: 'badge ok' }, 'running') : paused ? h('span', { class: 'badge' }, 'paused') : h('span', { class: 'badge warn' }, 'not running');
  const message = h('div');
  const pause = h('button', {}, paused ? 'Resume (PIN)' : 'Pause (PIN)');
  pause.addEventListener('click', async () => {
    const r = await deps.run('pause_monitor', { id, paused: !paused }, pause);
    if (r.ok) list.refresh();
    else if (r.error) replace(message, errorBox(r.error));
  });
  const del = h('button', { class: 'danger' }, 'Delete (PIN)');
  del.addEventListener('click', async () => {
    if (!(await confirmDialog(`Delete monitor ${id}?`, 'Its rule is removed. Hits recorded so far stay in the encrypted history until it is purged or they age out.', 'Delete'))) return;
    const r = await deps.run('delete_monitor', { id }, del);
    if (r.ok) list.refresh();
    else if (r.error) replace(message, errorBox(r.error));
  });
  const adjust = m.rule ? h('button', { onclick: () => list.onAdjust(m.rule, id) }, 'Adjust') : null;
  const hits = Number(m.hitsSinceUnlock ?? 0);
  return h(
    'div',
    { class: 'monitor' },
    h('div', { class: 'tool-head' }, h('h4', {}, `${str(m.name) || 'Unreadable rule'} `, h('span', { class: 'hint' }, id)), h('div', { class: 'badges' }, state)),
    m.review ? reviewView(m.review) : null,
    ...problems.map((p) => h('div', { class: 'notice' }, p)),
    h('p', { class: 'hint' }, hits ? `${hits} hit(s) since unlock, last at ${new Date(str(m.lastHit)).toLocaleString()}.` : 'No hits since unlock.'),
    message,
    h('div', { class: 'row' }, pause, adjust, del),
  );
}

// ---- encrypted history -----------------------------------------------------------

const KIND_LABELS: Record<string, string> = {
  session_start: 'Monitoring started',
  session_stop: 'Monitoring stopped',
  spike: 'Resource spike',
  foreground: 'App in the foreground',
  monitor_hit: 'Monitor fired',
  paused: 'Paused from the tray',
  resumed: 'Resumed from the tray',
};

const when = (v: unknown): string => (str(v) ? new Date(str(v)).toLocaleString() : 'now');

function eventText(e: Json): string {
  switch (e.kind) {
    case 'session_start':
      return `launched ${str(e.launch) || 'manually'}`;
    case 'session_stop':
      return str(e.reason);
    case 'spike':
      return `${str(e.process)} (${str(e.type)}): ${e.cpuPercent ?? '?'}% CPU, ${e.ramMb ?? '?'} MB`;
    case 'foreground':
      return str(e.process);
    case 'monitor_hit':
      return `${str(e.name)} (${str(e.monitorId)})${lines(e.matched).length ? `: ${lines(e.matched).join('; ')}` : ''}`;
    default:
      return '';
  }
}

function gapView(g: Json): HTMLElement {
  const evidence = arr(g.evidence).map(obj);
  return h(
    'div',
    { class: `notice ${g.kind === 'unexpected' ? 'error' : ''}` },
    h('p', {}, h('strong', {}, `${when(g.from)} to ${when(g.to)}`), ` ${str(g.label)}`),
    evidence.length
      ? h('ul', {}, ...evidence.map((e) => h('li', {}, `${when(e.time)}: ${str(e.meaning)} (event ${e.eventId}, ${str(e.provider)})${str(e.message) ? ` ${str(e.message)}` : ''}`)))
      : null,
  );
}

/** The monitor's encrypted timeline: reading it, its limits, and purging it all need the PIN. */
function historyCard(deps: MonitorDeps): { element: HTMLElement; showRetention(r: Json): void } {
  const result = h('div', { class: 'stack', 'aria-live': 'polite' });
  const days = h('select', { id: 'history-days' }, ...[1, 7, 14, 30, 90].map((d) => h('option', { value: d }, d === 1 ? 'the last day' : `the last ${d} days`)));
  const show = h('button', { class: 'primary' }, 'Show history (PIN)');
  show.addEventListener('click', async () => {
    const r = await deps.run('read_monitor_history', { days: Number(days.value) }, show);
    if (!r.ok) return r.error ? replace(result, errorBox(r.error)) : undefined;
    const v = obj(r.value);
    const events = arr(v.events).map(obj).reverse();
    const gaps = arr(v.gaps).map(obj).reverse();
    const omitted = Number(v.omitted ?? 0);
    replace(
      result,
      h('p', { class: 'hint' }, `From ${when(v.from)} to ${when(v.to)}. ${str(v.note)}`),
      ...lines(v.problems).map((p) => h('div', { class: 'notice error' }, p)),
      h('h4', {}, gaps.length ? `Times AegisWin was not monitoring (${gaps.length})` : 'No gaps in monitoring'),
      ...gaps.map(gapView),
      h('h4', {}, `Events, newest first (${events.length})`),
      events.length === 0 ? h('p', {}, 'Nothing recorded in this period.') : null,
      events.length
        ? h('table', {}, h('tbody', {}, ...events.map((e) => h('tr', {}, h('td', {}, when(e.at)), h('td', {}, KIND_LABELS[str(e.kind)] ?? str(e.kind)), h('td', {}, eventText(e))))))
        : null,
      omitted ? h('p', { class: 'hint' }, `${omitted} older event(s) not shown.`) : null,
    );
  });

  const maxDays = h('input', { type: 'number', id: 'history-max-days', min: 1, max: 90, value: 14 });
  const maxMb = h('input', { type: 'number', id: 'history-max-mb', min: 8, max: 512, value: 64 });
  const limitsMessage = h('div');
  const save = h('button', {}, 'Save limits (PIN)');
  save.addEventListener('click', async () => {
    const r = await deps.run('configure_history_retention', { maxDays: Number(maxDays.value), maxMb: Number(maxMb.value) }, save);
    if (r.ok) replace(limitsMessage, h('div', { class: 'notice ok' }, str(obj(r.value).note) || 'Saved.'));
    else if (r.error) replace(limitsMessage, errorBox(r.error));
  });

  const purge = h('button', { class: 'danger' }, 'Delete all history (PIN)');
  purge.addEventListener('click', async () => {
    if (!(await confirmDialog('Delete all monitor history?', 'Every history file is deleted and the history gets a new key, so deleted files cannot be read even if recovered. This cannot be undone.', 'Delete'))) return;
    const r = await deps.run('purge_telemetry_history', {}, purge);
    if (r.ok) {
      replace(result, h('div', { class: 'notice ok' }, `History deleted (${Number(obj(r.value).historyFilesRemoved ?? 0)} file(s)).`));
      toast('Monitor history deleted.');
    } else if (r.error) replace(result, errorBox(r.error));
  });

  const element = h(
    'section',
    { class: 'card stack' },
    h('h3', {}, 'History'),
    h('p', { class: 'hint' }, 'While a monitor runs, AegisWin keeps an encrypted record of sessions, spikes, foreground apps and monitor hits on this PC. Only your PIN can read it. Process names only, never window titles.'),
    h('div', { class: 'row' }, h('label', { for: 'history-days' }, 'Show'), days, show),
    result,
    h('h4', {}, 'Keep history for'),
    h('div', { class: 'grid2' }, h('div', {}, h('label', { for: 'history-max-days' }, 'At most (days, 1 to 90)'), maxDays), h('div', {}, h('label', { for: 'history-max-mb' }, 'At most (MB, 8 to 512)'), maxMb)),
    limitsMessage,
    h('div', { class: 'row' }, save, purge),
  );
  // The saved limits arrive with the monitor list (it loads first, before any edit).
  const showRetention = (r: Json) => {
    if (typeof r.maxDays === 'number' && document.activeElement !== maxDays) maxDays.value = String(r.maxDays);
    if (typeof r.maxMb === 'number' && document.activeElement !== maxMb) maxMb.value = String(r.maxMb);
  };
  return { element, showRetention };
}

// ---- AI monitor creator -------------------------------------------------------

function destinationText(d: unknown): string {
  const v = obj(d);
  if (str(v.problem)) return `The LLM is not usable right now: ${str(v.problem)}`;
  return v.offLan === true ? `${str(v.host)}, outside your local network (personal details are scrubbed first)` : `${str(v.host)}, on your local network`;
}

function monitorChat(deps: MonitorDeps, adjust: (rule: unknown) => void, started: () => void): HTMLElement {
  const log = h('div', { class: 'stack chat-log' });
  const message = h('div');
  const step = h('div', { class: 'stack' });
  const card = h(
    'section',
    { class: 'card stack' },
    h('h3', {}, 'Describe a monitor to the AI'),
    h('p', { class: 'hint' }, 'Say what you want to watch in your own words. The AI may ask up to three rounds of questions, then proposes a rule. AegisWin checks the rule and describes it; nothing runs until you start it with your PIN.'),
    log,
    message,
    step,
  );
  const say = (who: string, text: string) => log.appendChild(h('div', { class: 'chat-line' }, h('strong', {}, `${who}: `), text));
  const where = (out: Json) => {
    const sent = obj(out.sentTo);
    if (str(sent.host)) log.appendChild(h('p', { class: 'hint' }, `Sent to ${str(sent.model)} at ${destinationText(sent)}.`));
  };

  /** Runs one chat step with every button in the step disabled. */
  const send = async (toolId: string, args: Json, button: HTMLButtonElement) => {
    const buttons = Array.from(step.querySelectorAll('button')).filter((b) => b !== button);
    buttons.forEach((b) => (b.disabled = true));
    const r = await deps.run(toolId, args, button);
    buttons.forEach((b) => (b.disabled = false));
    replace(message, r.ok || !r.error ? null : errorBox(r.error));
    if (r.ok) show(obj(r.value));
  };

  const cancelButton = () => {
    const b = h('button', {}, 'End conversation');
    b.addEventListener('click', async () => {
      const r = await deps.run('monitor_chat_cancel', {}, b);
      if (r.ok || r.error) startForm();
    });
    return b;
  };

  const show = (out: Json) => {
    where(out);
    const next = h('p', { class: 'hint' }, `Your next reply goes to ${destinationText(out.nextSendGoesTo)}.`);
    switch (out.status) {
      case 'questions': {
        const qs = arr(out.questions).map(obj);
        const inputs = qs.map((q, i) => {
          const input = h('input', { type: 'text', maxlength: 300, id: `chat-answer-${i}`, 'aria-label': str(q.text) });
          const choices = lines(q.choices).map((c) => h('button', { type: 'button', class: 'chip', onclick: () => (input.value = c) }, c));
          return { q, input, element: h('div', {}, h('label', { for: `chat-answer-${i}` }, str(q.text)), choices.length ? h('div', { class: 'row' }, ...choices) : null, input) };
        });
        const answer = h('button', { class: 'primary' }, 'Send answers');
        answer.addEventListener('click', () => {
          const answers = inputs.map((i) => i.input.value.trim());
          qs.forEach((q, n) => {
            say('AI asked', str(q.text));
            say('You', answers[n] || '(skipped)');
          });
          void send('monitor_chat_reply', { answers }, answer);
        });
        const now = h('button', {}, 'Propose now');
        now.addEventListener('click', () => void send('monitor_chat_reply', { proposeNow: true }, now));
        replace(
          step,
          h('p', { class: 'hint' }, `Round ${out.round} of ${out.maxRounds}. ${str(out.note)}`),
          ...lines(out.dropped).map((d) => h('div', { class: 'notice' }, d)),
          ...inputs.map((i) => i.element),
          next,
          h('div', { class: 'row' }, answer, now, cancelButton()),
        );
        inputs[0]?.input.focus();
        return;
      }
      case 'requestRunningApps': {
        const yes = h('button', { class: 'primary' }, 'Yes, share app names');
        const no = h('button', {}, 'No');
        yes.addEventListener('click', () => {
          say('You', 'Shared running app names.');
          void send('monitor_chat_reply', { shareRunningApps: true }, yes);
        });
        no.addEventListener('click', () => {
          say('You', 'Declined to share app names.');
          void send('monitor_chat_reply', { shareRunningApps: false }, no);
        });
        replace(step, h('h4', {}, str(out.consent)), aiText('The AI says why (AI-generated, may be wrong)', str(out.reason)), h('p', { class: 'hint' }, str(out.note)), next, h('div', { class: 'row' }, yes, no, cancelButton()));
        return;
      }
      case 'proposal':
        say('AI', 'Proposed a monitor.');
        replace(step, proposalView(deps, out.proposal, null, { adjust: () => adjust(obj(out.proposal).rule), started }), h('div', { class: 'row' }, startOver()));
        return;
      case 'unsupported':
        replace(step, aiText('The AI says monitors cannot do this (AI-generated, may be wrong)', str(out.reason)), h('div', { class: 'row' }, startOver()));
        return;
      default: {
        const retry = h('button', { class: 'primary' }, 'Try again');
        retry.addEventListener('click', () => void send('monitor_chat_reply', {}, retry));
        const now = h('button', {}, 'Propose now');
        now.addEventListener('click', () => void send('monitor_chat_reply', { proposeNow: true }, now));
        replace(step, errorBox({ code: 'FAILED', message: str(out.message) || 'The AI did not answer usefully.' }), str(out.problem) ? h('p', { class: 'hint' }, `Problem: ${str(out.problem)}`) : null, next, h('div', { class: 'row' }, retry, now, cancelButton()));
      }
    }
  };

  const startOver = () => h('button', { onclick: () => startForm() }, 'Start a new conversation');

  const startForm = () => {
    replace(log);
    replace(message);
    const tool = deps.tool('monitor_chat_start');
    if (!tool) return replace(step, h('p', { class: 'hint' }, 'The AI monitor creator is not available.'));
    const request = h('textarea', { rows: 3, maxlength: 1000, id: 'chat-request', placeholder: 'For example: my game freezes on Friday nights' });
    const go = h('button', { class: 'primary' }, 'Ask the AI');
    go.addEventListener('click', () => {
      const text = request.value.trim();
      if (!text) return request.focus();
      say('You', text);
      void send('monitor_chat_start', { request: text }, go);
    });
    const d = deps.llmDestination();
    replace(
      step,
      h('label', { for: 'chat-request' }, 'What do you want to watch?'),
      request,
      h('p', { class: 'hint' }, d ? `Your text and answers go to ${d.host}${d.offLan ? ', outside your local network (personal details are scrubbed first)' : ', on your local network'}.` : 'Set up an LLM in the LLM tab first.'),
      h('div', { class: 'row' }, go),
    );
  };
  startForm();
  return card;
}

// ---- rule editor ----------------------------------------------------------------

type FieldKind = 'text' | 'number' | 'channel';
const CONDITIONS: Record<string, { label: string; fields: Array<[string, string, FieldKind]> }> = {
  process_cpu: { label: 'An app uses a lot of CPU', fields: [['process', 'App (for example game.exe, or * for any)', 'text'], ['atLeastPercent', 'At least % of total CPU', 'number'], ['forSeconds', 'For at least (seconds)', 'number']] },
  process_memory: { label: 'An app uses a lot of memory', fields: [['process', 'App (for example game.exe, or * for any)', 'text'], ['atLeastMb', 'At least (MB)', 'number'], ['forSeconds', 'For at least (seconds)', 'number']] },
  system_cpu: { label: 'Total CPU is high', fields: [['atLeastPercent', 'At least %', 'number'], ['forSeconds', 'For at least (seconds)', 'number']] },
  system_memory: { label: 'Total memory use is high', fields: [['atLeastPercent', 'At least %', 'number'], ['forSeconds', 'For at least (seconds)', 'number']] },
  event: { label: 'A Windows event is logged', fields: [['channel', 'Log', 'channel'], ['eventId', 'Event ID', 'number'], ['provider', 'Source (optional)', 'text']] },
  crash: { label: 'An app crashes or hangs', fields: [['process', 'App (for example game.exe)', 'text']] },
  foreground: { label: 'An app is in the foreground', fields: [['process', 'App (for example game.exe)', 'text']] },
};
const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

interface ConditionRow {
  element: HTMLElement;
  read(): Json | string;
}

function conditionRow(initial: Json, remove: (row: ConditionRow) => void): ConditionRow {
  const values: Json = { ...initial };
  const type = h('select', { 'aria-label': 'Condition' }, ...Object.entries(CONDITIONS).map(([k, c]) => h('option', { value: k }, c.label)));
  type.value = CONDITIONS[str(initial.type)] ? str(initial.type) : 'crash';
  const fields = h('div', { class: 'grid2' });
  let readers: Array<() => [string, unknown] | string | null> = [];
  const draw = () => {
    readers = [];
    replace(
      fields,
      ...CONDITIONS[type.value].fields.map(([key, label, kind]) => {
        const current = values[key];
        const input =
          kind === 'channel'
            ? h('select', { 'aria-label': label }, ...['Application', 'System', 'Setup'].map((c) => h('option', { value: c }, c)))
            : h('input', { type: kind === 'number' ? 'number' : 'text', 'aria-label': label, maxlength: kind === 'text' ? 260 : undefined });
        if (current !== undefined && current !== null) input.value = String(current);
        input.addEventListener('input', () => (values[key] = input.value));
        readers.push(() => {
          const raw = input.value.trim();
          if (raw === '') return key === 'provider' ? null : `${label} is required.`;
          if (kind !== 'number') return [key, raw];
          const n = Number(raw);
          return Number.isFinite(n) ? [key, n] : `${label} must be a number.`;
        });
        return h('div', {}, h('div', { class: 'hint' }, label), input);
      }),
    );
  };
  type.addEventListener('change', draw);
  draw();
  const row: ConditionRow = {
    element: h('div', { class: 'condition' }, h('div', { class: 'row' }, type, h('button', { type: 'button', class: 'link', onclick: () => remove(row) }, 'Remove')), fields),
    read() {
      const out: Json = { type: type.value };
      for (const r of readers) {
        const v = r();
        if (typeof v === 'string') return v;
        if (v) out[v[0]] = v[1];
      }
      return out;
    },
  };
  return row;
}

function ruleEditor(deps: MonitorDeps, started: () => void): { element: HTMLElement; load(rule: unknown, replaceId: string | null): void } {
  const form = h('div', { class: 'stack' });
  const result = h('div', { 'aria-live': 'polite' });
  const element = h(
    'section',
    { class: 'card stack' },
    h('h3', {}, 'Rule editor'),
    h('p', { class: 'hint' }, 'Build a monitor yourself, or adjust one. Check it to see what AegisWin will do with it, then start it with your PIN. Any change needs a new check.'),
    form,
    result,
  );
  // Any edit invalidates the last check, so only a checked rule can be started.
  element.addEventListener('input', (e) => {
    if (form.contains(e.target as Node)) replace(result);
  });
  element.addEventListener('change', (e) => {
    if (form.contains(e.target as Node)) replace(result);
  });

  const load = (rule: unknown, replaceId: string | null) => {
    const r = obj(rule);
    const schedule = obj(r.schedule);
    const trigger = obj(r.trigger);
    const mode = Array.isArray(trigger.all) ? 'all' : 'any';
    const name = h('input', { type: 'text', id: 'rule-name', maxlength: 60, value: str(r.name) });
    const start = h('input', { type: 'text', id: 'rule-start', maxlength: 5, placeholder: 'HH:MM', value: str(schedule.startTime) || '00:00' });
    const end = h('input', { type: 'text', id: 'rule-end', maxlength: 5, placeholder: 'HH:MM', value: str(schedule.endTime) || '00:00' });
    const chosen = new Set(lines(schedule.days));
    const days = DAYS.map((d) => ({ d, box: h('input', { type: 'checkbox', id: `rule-day-${d}`, checked: chosen.has(d) }) }));
    const match = h('select', { id: 'rule-match' }, h('option', { value: 'any' }, 'any condition is true'), h('option', { value: 'all' }, 'all conditions are true at once'));
    match.value = mode;
    const cooldown = h('input', { type: 'number', id: 'rule-cooldown', min: 60, max: 86400, value: typeof r.cooldownSeconds === 'number' ? r.cooldownSeconds : 600 });
    const notify = h('select', { id: 'rule-notify' }, h('option', { value: 'tray' }, 'record it and notify me in the tray'), h('option', { value: 'none' }, 'only record it'));
    notify.value = r.notify === 'none' ? 'none' : 'tray';

    const rows: ConditionRow[] = [];
    const rowsEl = h('div', { class: 'stack' });
    const add = h('button', { type: 'button' }, 'Add a condition');
    const removeRow = (row: ConditionRow) => {
      rows.splice(rows.indexOf(row), 1);
      row.element.remove();
      add.disabled = rows.length >= 8;
      replace(result);
    };
    const addRow = (c: Json) => {
      const row = conditionRow(c, removeRow);
      rows.push(row);
      rowsEl.appendChild(row.element);
      add.disabled = rows.length >= 8;
    };
    add.addEventListener('click', () => {
      addRow({ type: 'crash' });
      replace(result);
    });
    const initial = arr(trigger[mode]).map(obj);
    (initial.length ? initial : [{ type: 'crash' }]).forEach(addRow);

    const read = (): Json | string => {
      const conditions: Json[] = [];
      for (const row of rows) {
        const c = row.read();
        if (typeof c === 'string') return c;
        conditions.push(c);
      }
      if (conditions.length === 0) return 'Add at least one condition.';
      const rule: Json = {
        version: 1,
        name: name.value.trim(),
        schedule: { startTime: start.value.trim(), endTime: end.value.trim(), ...(days.some((x) => x.box.checked) ? { days: days.filter((x) => x.box.checked).map((x) => x.d) } : {}) },
        trigger: { [match.value]: conditions },
        cooldownSeconds: Number(cooldown.value),
        notify: notify.value,
      };
      return rule;
    };

    const check = h('button', { class: 'primary' }, 'Check this rule');
    check.addEventListener('click', async () => {
      const rule = read();
      if (typeof rule === 'string') return replace(result, errorBox({ code: 'INVALID_ARGUMENTS', message: rule }));
      const r = await deps.run('propose_monitor', { rule }, check);
      if (!r.ok) return r.error ? replace(result, errorBox(r.error)) : undefined;
      const out = obj(r.value);
      if (out.valid !== true) return replace(result, h('div', { class: 'notice error', role: 'alert' }, h('p', {}, 'This rule is not valid:'), h('ul', {}, ...lines(out.problems).map((p) => h('li', {}, p)))));
      replace(result, proposalView(deps, out, replaceId, { started }));
    });
    const asNew = () => {
      const rule = read();
      if (typeof rule === 'string') return replace(result, errorBox({ code: 'INVALID_ARGUMENTS', message: rule }));
      load(rule, null);
    };
    const newRule = replaceId ? h('button', { type: 'button', class: 'link', onclick: asNew }, 'Save as a new monitor instead') : null;
    replace(
      form,
      replaceId ? h('div', { class: 'notice' }, `Adjusting monitor ${replaceId}. Starting it replaces that monitor's rule and keeps its id. `, newRule) : null,
      h('div', { class: 'grid2' }, h('div', {}, h('label', { for: 'rule-name' }, 'Name'), name), h('div', {}, h('label', { for: 'rule-notify' }, 'When it fires'), notify)),
      h('div', { class: 'grid2' }, h('div', {}, h('label', { for: 'rule-start' }, 'Active from (24-hour)'), start), h('div', {}, h('label', { for: 'rule-end' }, 'Until (same time = all day)'), end)),
      h('div', {}, h('div', { class: 'hint' }, 'Days (none ticked means every day)'), h('div', { class: 'row' }, ...days.map((x) => h('label', { class: 'inline', for: `rule-day-${x.d}` }, x.box, x.d[0].toUpperCase() + x.d.slice(1))))),
      h('div', { class: 'grid2' }, h('div', {}, h('label', { for: 'rule-match' }, 'Fire when'), match), h('div', {}, h('label', { for: 'rule-cooldown' }, 'Wait before firing again (seconds, 60 to 86400)'), cooldown)),
      rowsEl,
      h('div', { class: 'row' }, add, check),
    );
    replace(result);
    if (rule !== null) element.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  load(null, null);
  return { element, load };
}
