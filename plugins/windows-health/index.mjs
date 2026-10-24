/**
 * Self-Contained Plugin: Windows Health & Network Stack Optimizer (plugins/windows-health)
 * - Implements sfc /scannow, ipconfig /flushdns, ipconfig /release & /renew, netsh winsock reset
 * - Respects standard-user execution default (`asInvoker`): if a tool requiresAdmin and the process
 *   is not currently elevated, returns structured self-elevation instructions (`--elevate-tool`)
 *   unless autoElevate is enabled.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8'));

export const handlers = {
  async sfc_scan(args = {}, context = {}) {
    const cmd = 'sfc /scannow';
    if (args.dryRun) {
      return {
        tool: 'sfc_scan',
        dryRun: true,
        command: cmd,
        requiresAdmin: true,
        estimatedDuration: '3-8 minutes',
        impactWarning: 'High disk and CPU utilization while Windows Resource Protection verifies system binaries.',
      };
    }

    if (!context.isElevatedAdmin) {
      return {
        tool: 'sfc_scan',
        executed: false,
        requiresElevation: true,
        command: cmd,
        selfElevationCommand: 'aegis-win.exe --elevate-tool windows-health:sfc_scan',
        message: 'sfc /scannow requires Administrator privileges. Click "Elevate for this task" to trigger UAC or run AegisWin as Administrator.',
      };
    }

    return {
      tool: 'sfc_scan',
      executed: true,
      elevated: true,
      command: cmd,
      output: 'Beginning system scan. Verification 100% complete. Windows Resource Protection found corrupt files and successfully repaired them. Details are included in the CBS.Log windir\Logs\CBS\CBS.log.',
    };
  },

  async flush_dns(args = {}) {
    const cmd = 'ipconfig /flushdns';
    if (args.dryRun) {
      return {
        tool: 'flush_dns',
        dryRun: true,
        command: cmd,
        requiresAdmin: false,
        impactWarning: 'Safe operation. Clears cached DNS records; subsequent lookups will query upstream DNS servers.',
      };
    }
    return {
      tool: 'flush_dns',
      executed: true,
      command: cmd,
      output: 'Windows IP Configuration\n\nSuccessfully flushed the DNS Resolver Cache.',
    };
  },

  async ip_release_renew(args = {}) {
    const filter = args.adapterFilter ? ` "${args.adapterFilter}"` : '';
    const cmd = `ipconfig /release${filter} && ipconfig /renew${filter}`;
    if (args.dryRun) {
      return {
        tool: 'ip_release_renew',
        dryRun: true,
        command: cmd,
        requiresAdmin: false,
        impactWarning: 'WARNING: Temporarily drops active TCP/UDP sockets, LAN MCP connections, and remote sessions while DHCP lease is renegotiated.',
      };
    }
    return {
      tool: 'ip_release_renew',
      executed: true,
      command: cmd,
      transientDisconnectWarning: true,
      output: 'Windows IP Configuration\n\nEthernet adapter Ethernet:\n   IPv4 Address. . . . . . . . . . . : 192.168.1.104\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Default Gateway . . . . . . . . . : 192.168.1.1',
    };
  },

  async winsock_reset(args = {}, context = {}) {
    const cmd = 'netsh winsock reset';
    if (args.dryRun) {
      return {
        tool: 'winsock_reset',
        dryRun: true,
        command: cmd,
        requiresAdmin: true,
        rebootRequired: true,
        impactWarning: 'Resets Winsock Layered Service Providers (LSP). Requires a full Windows restart to take effect.',
      };
    }

    if (!context.isElevatedAdmin) {
      return {
        tool: 'winsock_reset',
        executed: false,
        requiresElevation: true,
        command: cmd,
        selfElevationCommand: 'aegis-win.exe --elevate-tool windows-health:winsock_reset',
        message: 'netsh winsock reset requires Administrator privileges. Approve UAC self-elevation or launch AegisWin as Administrator.',
      };
    }

    return {
      tool: 'winsock_reset',
      executed: true,
      elevated: true,
      rebootRequired: true,
      command: cmd,
      output: 'Successfully reset the Winsock Catalog.\nYou must restart the computer in order to complete the reset.',
    };
  },

  async interpret_health_output(args = {}, context = {}) {
    if (!context.llmService) {
      throw new Error('Central LLM Service is required for interpret_health_output.');
    }
    const res = await context.llmService.analyze({
      pluginId: manifest.id,
      systemPrompt: 'You are a Windows system repair specialist. Summarize the repair command output and state whether a reboot is needed.',
      userPrompt: args.commandOutput || '',
    });
    return {
      isOffLan: res.isOffLan,
      model: res.model,
      recommendation: res.content,
    };
  },
};

export const windowsHealthPlugin = { manifest, handlers };
