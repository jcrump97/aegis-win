/**
 * AegisWin Central LLM Service
 * - Connects to local Ollama, LM Studio, or any OpenAI-compatible API (/v1/chat/completions)
 * - Classifies endpoints as On-LAN vs Off-LAN
 * - Enforces per-plugin external trust warning before any plugin sends data off-LAN
 * - Scrubs user PIN and credentials from all outbound prompts
 * - When calling an Off-LAN endpoint, runs deterministic PII & Host sanitization
 *   (redacting C:\Users\<Name>, OS username, machine hostname, and UNC paths)
 */
import os from 'node:os';

export function isLanAddress(urlString) {
  try {
    const parsed = new URL(urlString);
    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');

    if (
      host === 'localhost' ||
      host === '::1' ||
      host === '0:0:0:0:0:0:0:1' ||
      host.endsWith('.local') ||
      host.endsWith('.lan') ||
      host.endsWith('.home') ||
      host.endsWith('.internal')
    ) {
      return true;
    }

    const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4Match) {
      const [_, a, b, c, d] = ipv4Match.map(Number);
      if ([a, b, c, d].some((octet) => octet > 255)) return false;
      if (a === 127) return true;
      if (a === 10) return true;
      if (a === 192 && b === 168) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      if (a === 169 && b === 254) return true;
      return false;
    }

    if (host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80:')) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

export function scrubHostAndPiiForOffLan(text) {
  if (typeof text !== 'string') return text;
  let scrubbed = text;

  // 1. Redact Windows User Profile paths: C:\Users\<Username>\...
  scrubbed = scrubbed.replace(/([A-Za-z]:\\Users\\)([^\\/"'\s]+)/gi, '$1<REDACTED_USER>');

  // 2. Redact SMB UNC server/share paths: \Server\Share
  scrubbed = scrubbed.replace(/\\\\([A-Za-z0-9._-]+)\\([A-Za-z0-9$._-]+)/g, '\\\\<REDACTED_HOST>\\<REDACTED_SHARE>');

  // 3. Redact current OS username and hostname if >= 3 chars
  try {
    const currentUser = os.userInfo().username;
    if (currentUser && currentUser.length >= 3) {
      scrubbed = scrubbed.split(currentUser).join('<REDACTED_USER>');
    }
  } catch {}

  try {
    const currentHost = os.hostname();
    if (currentHost && currentHost.length >= 3) {
      scrubbed = scrubbed.split(currentHost).join('<REDACTED_HOST>');
    }
  } catch {}

  return scrubbed;
}

export class CentralLlmService {
  constructor(vault, transport = null) {
    this.vault = vault;
    this.transport = transport || this._defaultFetchTransport.bind(this);
  }

  evaluatePluginAccess(pluginId) {
    const state = this.vault.getState();
    const { baseUrl } = state.llmConfig;
    const onLan = isLanAddress(baseUrl);

    if (onLan) {
      return {
        allowed: true,
        isOffLan: false,
        baseUrl,
        reason: 'Endpoint is on the local network (LAN/localhost).',
      };
    }

    const trustedList = state.trustedExternalLlmPlugins || [];
    const isPluginTrusted = trustedList.includes(pluginId);

    if (!isPluginTrusted) {
      return {
        allowed: false,
        isOffLan: true,
        requiresTrustPrompt: true,
        code: 'OFF_LAN_TRUST_REQUIRED',
        pluginId,
        baseUrl,
        warningMessage: `Security Warning: Plugin "${pluginId}" is attempting to send system diagnostic data to an external Off-LAN LLM endpoint (${baseUrl}). Sensitive host details or logs could leave your home network. Do you trust "${pluginId}" for external LLM calls?`,
      };
    }

    return {
      allowed: true,
      isOffLan: true,
      baseUrl,
      reason: `Plugin "${pluginId}" has been explicitly trusted by the user for Off-LAN LLM requests.`,
    };
  }

  grantPluginExternalTrust(pluginId) {
    this.vault.updateState((s) => {
      const set = new Set(s.trustedExternalLlmPlugins || []);
      set.add(pluginId);
      s.trustedExternalLlmPlugins = Array.from(set);
      return s;
    });
    return true;
  }

  revokePluginExternalTrust(pluginId) {
    this.vault.updateState((s) => {
      s.trustedExternalLlmPlugins = (s.trustedExternalLlmPlugins || []).filter((id) => id !== pluginId);
      return s;
    });
    return true;
  }

  async analyze({ pluginId, systemPrompt, userPrompt, temperature = 0.2 }) {
    if (!pluginId) {
      throw new Error('pluginId is required for LLM service calls.');
    }

    const access = this.evaluatePluginAccess(pluginId);
    if (!access.allowed) {
      const err = new Error(access.warningMessage);
      err.code = access.code;
      err.details = access;
      throw err;
    }

    const { llmConfig } = this.vault.getState();
    let safeSystem = this.vault.scrubForExternalOutput(systemPrompt || 'You are a Windows system diagnostics assistant.');
    let safeUser = this.vault.scrubForExternalOutput(userPrompt || '');

    // Automatically scrub Windows usernames, profile paths, UNC shares, and hostnames when going Off-LAN
    if (access.isOffLan) {
      safeSystem = scrubHostAndPiiForOffLan(safeSystem);
      safeUser = scrubHostAndPiiForOffLan(safeUser);
    }

    const endpoint = `${llmConfig.baseUrl.replace(/\/+$/, '')}/chat/completions`;
    const headers = {
      'Content-Type': 'application/json',
    };
    if (llmConfig.apiKey) {
      headers['Authorization'] = `Bearer ${llmConfig.apiKey}`;
    }

    const payload = {
      model: llmConfig.model,
      temperature,
      messages: [
        { role: 'system', content: safeSystem },
        { role: 'user', content: safeUser },
      ],
    };

    const response = await this.transport(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    return {
      pluginId,
      endpoint,
      isOffLan: access.isOffLan,
      piiScrubbed: access.isOffLan,
      model: llmConfig.model,
      content: response.choices?.[0]?.message?.content || '',
    };
  }

  async _defaultFetchTransport(url, options) {
    const res = await fetch(url, options);
    if (!res.ok) {
      throw new Error(`LLM HTTP Error ${res.status}: ${await res.text()}`);
    }
    return res.json();
  }
}
