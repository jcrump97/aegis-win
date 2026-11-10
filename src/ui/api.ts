// Typed wrappers around the Tauri commands in src-tauri/src/main.rs.
// Shapes mirror the camelCase serde views in aegis-core; none carry secrets
// except revealMcpToken, which needs the PIN, and showDeviceCode, whose
// one-time code is shown once and works for 5 minutes.

import { invoke } from '@tauri-apps/api/core';

export type GatePolicy = 'auto' | 'pin_required';

/** A one-time code for approving one request on another device. */
export interface DeviceCodeView {
  code: string;
  expiresAt: string;
  url: string;
  /** One SVG path of 1x1 squares in a `size` x `size` viewBox. */
  qr: { size: number; path: string };
}

export interface AegisError {
  code: string;
  message: string;
}

export interface Status {
  vaultExists: boolean;
  unlocked: boolean;
  firstRunCompleted: boolean;
  elevated: boolean;
  version: string;
  dataDir: string;
  pinLockoutSeconds: number;
  uiScale: number;
  /** The change running now and how many wait their turn (one at a time). */
  change: { running: string | null; queued: number };
  /** Runtime files set aside at unlock because they did not match the vault. */
  runtimeReviews: RuntimeReview[];
  /** Shown after unlock: monitoring was not running before this launch resumed it. */
  resumeNotices: ResumeNotice[];
  /** The vault key is a short PIN from before passphrases; the owner must choose (ADR 0004 D2). */
  needsPassphrase: boolean;
  /** A short PIN on this PC can unlock (ADR 0004 §3.3). Known while locked. */
  thisPcPin: boolean;
  /** The approval record is full, so agent requests are refused (ADR 0004 §4.5). */
  approvalRecordFull: boolean;
  /** Approval record events not written yet; they go in before the next one (§4.6). */
  unwrittenRecords: number;
}

/** A guide for a passphrase being typed; the rule enforced is the length. */
export interface PassphraseStrength {
  score: number;
  bits: number;
  longEnough: boolean;
  warning: string | null;
  suggestions: string[];
}

export interface ResumeNotice {
  pluginId: string;
  /** When monitoring stopped (RFC 3339), if the history still has it. */
  from: string | null;
  /** When this launch started monitoring again (RFC 3339). */
  to: string;
  /** Why it was not running, in a plain sentence. */
  label: string;
}

/** One event of the durable approval record (ADR 0003 §7); fields depend on `event`. */
export interface ApprovalRecordEvent {
  event: 'created' | 'decided' | 'change_started' | 'change_finished' | 'finished' | 'cancelled' | 'cancel_requested' | string;
  at: string;
  ticketId?: string | null;
  /** Its event number in the record (ADR 0004 §4.1); missing for events from before integrity checks. */
  seq?: number;
  /** It failed the integrity check: shown in red. */
  unverified?: boolean;
  [field: string]: unknown;
}

/** What checking the whole record found (ADR 0004 §4.4). */
export interface RecordIntegrity {
  ok: boolean;
  /** The one line shown above the table. */
  line: string;
  problems: string[];
  verified: number;
  legacy: number;
}

export interface ApprovalRecord {
  days: number;
  retention: { maxDays: number; maxMb: number };
  events: ApprovalRecordEvent[];
  omitted: number;
  files: { name: string; status: string }[];
  integrity?: RecordIntegrity;
}

/** The Startup shortcut (`AegisWin Monitor.lnk`), app only. */
export type AutostartView = { shortcut: string; wanted: boolean | null } & (
  | { state: 'off' }
  | { state: 'on' }
  | { state: 'different'; target: string; arguments: string }
  | { state: 'unreadable'; reason: string }
);

export interface RuntimeReview {
  pluginId: string;
  /** What differed, in words ("history key", "monitoring settings", ...). */
  differences: string[];
}

export interface JsonSchema {
  type?: string;
  description?: string;
  enum?: unknown[];
  default?: unknown;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  maxItems?: number;
  items?: JsonSchema;
  properties?: Record<string, JsonSchema>;
  required?: string[];
}

export interface ComponentView {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
}

export interface ToolView {
  id: string;
  name: string;
  description: string;
  requiresAdmin: boolean;
  readOnly: boolean;
  component: string | null;
  available: boolean;
  defaultGatePolicy: GatePolicy;
  effectivePolicy: GatePolicy;
  mcpName: string;
  /** Reached only from the app, never listed for agents. */
  appOnly: boolean;
  /** Can be a step of an action plan. */
  planEligible: boolean;
  inputSchema: JsonSchema;
}

export interface PluginView {
  id: string;
  name: string;
  version: string;
  description: string;
  installed: boolean;
  optionalInstallDefault: boolean;
  usesLlm: boolean;
  trustedOffLan: boolean;
  subComponents: ComponentView[];
  tools: ToolView[];
}

export type TicketStatus =
  | 'pending_approval'
  | 'queued'
  | 'running'
  | 'approved'
  | 'declined'
  | 'execution_failed'
  | 'locked_out'
  | 'expired'
  | 'cancelled';

export type StepStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'skipped' | 'cancelled';

/** One step of an action plan, described by AegisWin's code. */
export interface PlanStep {
  index: number;
  tool: string;
  pluginId: string;
  toolId: string;
  toolName: string;
  toolDescription: string;
  requiresAdmin: boolean;
  args: unknown;
  /** Supplied by whoever wrote the plan; shown under `PlanMeta.suppliedLabel`. */
  reasoning?: string;
  /** The commands it runs, from the plugin's code; covered by the plan's hash (ADR 0004 §5). */
  commands: string[];
  status: StepStatus;
  result?: unknown;
  error?: AegisError;
}

/** A plan the owner builds in the app; the engine checks it like an agent's. */
export interface PlanRequest {
  title?: string;
  reasoning?: string;
  steps: Array<{ tool: string; args: Record<string, unknown> }>;
}

export interface PlanMeta {
  title?: string;
  reasoning?: string;
  origin: 'agent' | 'owner';
  suppliedLabel: string;
  /** Approving must send this back. */
  hash: string;
  shortHash: string;
  summary: string;
  flags: string[];
  expiresAt: string;
  stopReason?: string;
}

export interface CallReview {
  lines: string[];
  warnings: string[];
}

export interface TicketView {
  ticketId: string;
  pluginId: string;
  toolId: string;
  toolName: string;
  toolDescription: string;
  requiresAdmin: boolean;
  args: unknown;
  /** What the call does, written by the plugin's code from the arguments. */
  review?: CallReview;
  /** The exact commands it runs, checked again just before they run (ADR 0004 §5). */
  commands?: string[];
  createdAt: string;
  status: TicketStatus;
  /** While queued: 1 means it runs next. */
  queuePosition?: number;
  attemptsRemaining: number;
  comment: string | null;
  decidedVia: string | null;
  result?: unknown;
  error?: AegisError;
  /** Present for action plans only. */
  plan?: PlanMeta;
  steps?: PlanStep[];
}

export type RunOutcome = { status: 'completed'; result: unknown } | { status: 'pending_approval'; ticket: TicketView };

export interface Endpoint {
  host: string;
  isLan: boolean;
  https: boolean;
  /** LAN host, but the model runs in Ollama's cloud. */
  relayed: boolean;
}

export interface McpStatus {
  running: boolean;
  url: string | null;
  /** The URL for clients on this PC (127.0.0.1 even when bound to a LAN address). */
  localUrl: string | null;
  firewallRule: boolean;
  note: string | null;
  /** The LAN listener's certificate when it serves HTTPS (ADR 0004 §2). */
  tls: McpTls | null;
  /** A LAN bind serving plain HTTP because the owner chose it. */
  plainHttp: boolean;
  certificateNotice: string | null;
}

export interface McpTls {
  /** SHA-256, upper-case hex in groups of 4. */
  fingerprint: string;
  /** YYYY-MM-DD; null for the owner's own certificate. */
  notAfter: string | null;
  own: boolean;
  certPath: string;
  certPem: string;
}

export interface SettingsView {
  uiScale: number;
  autoLockMinutes: number;
  llm: { baseUrl: string; model: string; hasApiKey: boolean; contextTokens: number; firstTokenSecs: number; endpoint: Endpoint | null; endpointError: string | null };
  mcp: { enabled: boolean; host: string; port: number; openFirewall: boolean; plainHttp: boolean; deviceApproval: boolean; deviceApprovalNotice: string | null; status: McpStatus; suggestedLanHost: string | null };
}

export interface SettingsUpdate {
  uiScale?: number;
  autoLockMinutes?: number;
  llmBaseUrl?: string;
  llmModel?: string;
  llmContextTokens?: number;
  llmFirstTokenSecs?: number;
  mcpEnabled?: boolean;
  mcpHost?: string;
  mcpPort?: number;
  mcpOpenFirewall?: boolean;
}

export interface LlmTest {
  endpoint: Endpoint;
  models: string[];
  ollama: boolean;
  modelContextLimit: number | null;
  warnings: string[];
}

export function isAegisError(e: unknown): e is AegisError {
  return typeof e === 'object' && e !== null && 'code' in e && 'message' in e;
}

/** Normalizes anything thrown by invoke into an AegisError. */
export function asError(e: unknown): AegisError {
  if (isAegisError(e)) return e;
  return { code: 'INTERNAL', message: e instanceof Error ? e.message : String(e) };
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw asError(e);
  }
}

export const api = {
  status: () => call<Status>('status'),
  setupVault: (pin: string) => call<Status>('setup_vault', { pin }),
  unlockVault: (pin: string) => call<Status>('unlock_vault', { pin }),
  lockVault: () => call<Status>('lock_vault'),
  noteActivity: () => call<void>('note_activity'),
  changePassphrase: (current: string, next: string, pcPin: string | null) => call<Status>('change_passphrase', { current, next, pcPin }),
  setThisPcPin: (current: string, pin: string) => call<Status>('set_this_pc_pin', { current, pin }),
  forgetThisPc: () => call<Status>('forget_this_pc'),
  passphraseStrength: (text: string) => call<PassphraseStrength>('passphrase_strength', { text }),
  getSettings: () => call<SettingsView>('get_settings'),
  updateSettings: (update: SettingsUpdate) => call<SettingsView>('update_settings', { update }),
  setLlmApiKey: (key: string) => call<void>('set_llm_api_key', { key }),
  testLlm: () => call<LlmTest>('test_llm'),
  listPlugins: () => call<PluginView[]>('list_plugins'),
  setInstalled: (selection: Record<string, string[]>) => call<PluginView[]>('set_installed', { selection }),
  setGatePolicy: (pluginId: string, toolId: string, policy: GatePolicy, pin: string | null) =>
    call<GatePolicy>('set_gate_policy', { pluginId, toolId, policy, pin }),
  grantLlmTrust: (pluginId: string, pin: string) => call<void>('grant_llm_trust', { pluginId, pin }),
  revokeLlmTrust: (pluginId: string) => call<void>('revoke_llm_trust', { pluginId }),
  rewriteRuntime: (pluginId: string) => call<void>('rewrite_runtime', { pluginId }),
  dismissResumeNotice: (pluginId: string) => call<void>('dismiss_resume_notice', { pluginId }),
  readApprovalRecord: (pin: string, days: number) => call<ApprovalRecord>('read_approval_record', { pin, days }),
  deleteApprovalRecord: (pin: string) => call<number>('delete_approval_record', { pin }),
  setApprovalRetention: (pin: string, days: number) => call<{ maxDays: number; maxMb: number }>('set_approval_retention', { pin, days }),
  getAutostart: () => call<AutostartView>('get_autostart'),
  enableAutostart: (pin: string, replace: boolean) => call<AutostartView>('enable_autostart', { pin, replace }),
  disableAutostart: () => call<AutostartView>('disable_autostart'),
  runTool: (pluginId: string, toolId: string, args: unknown, pin: string | null) =>
    call<RunOutcome>('run_tool', { pluginId, toolId, args, pin }),
  listTickets: () => call<TicketView[]>('list_tickets'),
  decideTicket: (ticketId: string, approve: boolean, pin: string, comment: string | null, planHash: string | null) =>
    call<TicketView>('decide_ticket', { ticketId, approve, pin, comment, planHash }),
  setDeviceApproval: (on: boolean, pin: string | null) => call<void>('set_device_approval', { on, pin }),
  showDeviceCode: (ticketId: string) => call<DeviceCodeView>('show_device_code', { ticketId }),
  cancelTicket: (ticketId: string) => call<TicketView>('cancel_ticket', { ticketId }),
  proposePlan: (request: PlanRequest) => call<TicketView>('propose_plan', { request }),
  startMcp: () => call<McpStatus>('start_mcp'),
  setMcpPlainHttp: (on: boolean, pin: string | null) => call<McpStatus>('set_mcp_plain_http', { on, pin }),
  resetMcpCertificate: (pin: string) => call<McpStatus>('reset_mcp_certificate', { pin }),
  stopMcp: () => call<McpStatus>('stop_mcp'),
  revealMcpToken: (pin: string) => call<string>('reveal_mcp_token', { pin }),
  rotateMcpToken: () => call<void>('rotate_mcp_token'),
  restartAsAdmin: () => call<void>('restart_as_admin'),
};
