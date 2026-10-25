// Typed wrappers around the Tauri commands in src-tauri/src/main.rs.
// Shapes mirror the camelCase serde views in aegis-core; none carry secrets
// except revealMcpToken, which needs the PIN.

import { invoke } from '@tauri-apps/api/core';

export type GatePolicy = 'auto' | 'pin_required';

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
  | 'running'
  | 'approved'
  | 'declined'
  | 'execution_failed'
  | 'locked_out'
  | 'expired';

export interface TicketView {
  ticketId: string;
  pluginId: string;
  toolId: string;
  toolName: string;
  toolDescription: string;
  requiresAdmin: boolean;
  args: unknown;
  createdAt: string;
  status: TicketStatus;
  attemptsRemaining: number;
  comment: string | null;
  decidedVia: string | null;
  result?: unknown;
  error?: AegisError;
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
  firewallRule: boolean;
  note: string | null;
}

export interface SettingsView {
  uiScale: number;
  llm: { baseUrl: string; model: string; hasApiKey: boolean; endpoint: Endpoint | null; endpointError: string | null };
  mcp: { enabled: boolean; host: string; port: number; openFirewall: boolean; status: McpStatus; suggestedLanHost: string | null };
}

export interface SettingsUpdate {
  uiScale?: number;
  llmBaseUrl?: string;
  llmModel?: string;
  mcpEnabled?: boolean;
  mcpHost?: string;
  mcpPort?: number;
  mcpOpenFirewall?: boolean;
}

export interface LlmTest {
  endpoint: Endpoint;
  models: string[];
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
  changePin: (current: string, next: string) => call<void>('change_pin', { current, next }),
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
  runTool: (pluginId: string, toolId: string, args: unknown, pin: string | null) =>
    call<RunOutcome>('run_tool', { pluginId, toolId, args, pin }),
  listTickets: () => call<TicketView[]>('list_tickets'),
  decideTicket: (ticketId: string, approve: boolean, pin: string, comment: string | null) =>
    call<TicketView>('decide_ticket', { ticketId, approve, pin, comment }),
  startMcp: () => call<McpStatus>('start_mcp'),
  stopMcp: () => call<McpStatus>('stop_mcp'),
  revealMcpToken: (pin: string) => call<string>('reveal_mcp_token', { pin }),
  rotateMcpToken: () => call<void>('rotate_mcp_token'),
  restartAsAdmin: () => call<void>('restart_as_admin'),
};
