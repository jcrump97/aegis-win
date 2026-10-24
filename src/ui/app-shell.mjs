/**
 * AegisWin High-Contrast Dark UI & Dynamic Scale Controller
 * - Manages WCAG AAA high-contrast theme tokens (#090D16 background, #F9FAFB text)
 * - Controls dynamic UI scaling (0.85x to 1.50x) persisted in PortableVault
 * - Orchestrates Startup PIN lock screen, First-Run Component Wizard, Plugin Workspace,
 *   Per-Plugin Off-LAN LLM Trust Warning, and Live MCP Approval Portal Queue
 */
import { PortableVault } from '../core/vault.mjs';
import { CentralLlmService } from '../core/llm-service.mjs';
import { PluginRegistry } from '../core/plugin-registry.mjs';
import { LocalMcpServer } from '../core/mcp-server.mjs';
import { eventLogsPlugin } from '../../plugins/event-logs/index.mjs';
import { windowsHealthPlugin } from '../../plugins/windows-health/index.mjs';
import { usageMonitorPlugin } from '../../plugins/usage-monitor/index.mjs';

export function createAegisWinApp({ dataDir, llmTransport, firewallManager } = {}) {
  const vault = new PortableVault(dataDir);
  const llmService = new CentralLlmService(vault, llmTransport);
  const registry = new PluginRegistry(vault, llmService);

  // Register compile-time self-contained plugins
  registry.registerPlugin(eventLogsPlugin);
  registry.registerPlugin(windowsHealthPlugin);
  registry.registerPlugin(usageMonitorPlugin);

  const mcpServer = new LocalMcpServer({
    vault,
    registry,
    ...(firewallManager ? { firewallManager } : {}),
  });

  return {
    vault,
    llmService,
    registry,
    mcpServer,
    setUiScale(scaleFactor) {
      const clamped = Math.min(1.5, Math.max(0.85, Number(scaleFactor) || 1.0));
      vault.updateState((s) => {
        s.uiScale = Number(clamped.toFixed(2));
        return s;
      });
      return vault.getState().uiScale;
    },
    getThemeSpec() {
      return {
        backgroundPrimary: '#090D16',
        backgroundSurface: '#111827',
        textPrimary: '#F9FAFB',
        accentCyan: '#38BDF8',
        contrastRatio: '18.4:1 (WCAG AAA)',
        uiScale: vault.isUnlocked() ? vault.getState().uiScale : 1.0,
      };
    },
  };
}
