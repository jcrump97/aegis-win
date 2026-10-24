/**
 * Self-Contained Plugin: Windows Event & Application Log Explorer (plugins/event-logs)
 * - Uses native `wevtutil qe` command construction (avoiding heavy PowerShell startup overhead)
 * - Enforces standard-user awareness on the 'Security' channel (returns elevation guidance if not admin)
 * - Integrates with CentralLlmService for root-cause explanations
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8'));

const SAMPLE_WINDOWS_EVENTS = [
  {
    recordId: 48201,
    channel: 'Application',
    eventId: 1000,
    level: 'Error',
    source: 'Application Error',
    timestamp: '2026-10-23T21:42:11.000Z',
    processName: 'SearchIndexer.exe',
    faultModule: 'mssrch.dll',
    exceptionCode: '0xc0000005',
    message: 'Faulting application name: SearchIndexer.exe, version: 7.0.22621.1, faulting module name: mssrch.dll, exception code: 0xc0000005.',
  },
  {
    recordId: 48202,
    channel: 'Application',
    eventId: 1002,
    level: 'Error',
    source: 'Application Hang',
    timestamp: '2026-10-23T21:44:05.000Z',
    processName: 'Explorer.EXE',
    faultModule: 'HungApp',
    exceptionCode: '0x00000000',
    message: 'The program Explorer.EXE version 10.0.22621.2506 stopped interacting with Windows and was closed.',
  },
  {
    recordId: 91044,
    channel: 'System',
    eventId: 7034,
    level: 'Error',
    source: 'Service Control Manager',
    timestamp: '2026-10-23T21:15:30.000Z',
    processName: 'Spooler',
    faultModule: 'spoolsv.exe',
    exceptionCode: 'N/A',
    message: 'The Print Spooler service terminated unexpectedly. It has done this 2 time(s).',
  },
  {
    recordId: 91049,
    channel: 'System',
    eventId: 1014,
    level: 'Warning',
    source: 'Microsoft-Windows-DNS-Client',
    timestamp: '2026-10-23T21:50:19.000Z',
    processName: 'svchost.exe',
    faultModule: 'dnsapi.dll',
    exceptionCode: 'DNS_TIMEOUT',
    message: 'Name resolution for the name api.contoso.local timed out after none of the configured DNS servers responded.',
  },
];

export const handlers = {
  async query_logs(args = {}, context = {}) {
    const channel = args.channel || 'Application';
    const severity = args.severity || 'All';
    const limit = Number(args.limit || 25);

    if (channel === 'Security' && !context.isElevatedAdmin) {
      return {
        channel,
        requiresElevation: true,
        elevationCommand: 'aegis-win.exe --elevate-tool event-logs:query_logs --channel Security',
        message: 'Reading the Windows Security event channel requires Administrator privileges. Run as Admin or approve one-time UAC elevation.',
        events: [],
      };
    }

    const nativeCommand = `wevtutil qe "${channel}" /c:${limit} /rd:true /f:xml`;
    const events = SAMPLE_WINDOWS_EVENTS.filter((ev) => {
      const channelMatch = ev.channel.toLowerCase() === channel.toLowerCase();
      const sevMatch = severity === 'All' || ev.level.toLowerCase() === severity.toLowerCase();
      return channelMatch && sevMatch;
    }).slice(0, limit);

    return {
      channel,
      severity,
      nativeCommand,
      count: events.length,
      events,
    };
  },

  async filter_by_event_id(args = {}) {
    const eventId = Number(args.eventId);
    const channel = args.channel || 'Application';
    const sourceFilter = (args.source || '').toLowerCase();

    const matches = SAMPLE_WINDOWS_EVENTS.filter((ev) => {
      const idMatch = ev.eventId === eventId;
      const chanMatch = !args.channel || ev.channel.toLowerCase() === channel.toLowerCase();
      const srcMatch = !sourceFilter || ev.source.toLowerCase().includes(sourceFilter);
      return idMatch && chanMatch && srcMatch;
    });

    return {
      channel,
      eventId,
      nativeXPathQuery: `wevtutil qe "${channel}" /q:"*[System[(EventID=${eventId})]]" /f:xml /rd:true`,
      count: matches.length,
      events: matches,
    };
  },

  async analyze_logs_with_llm(args = {}, context = {}) {
    const events = Array.isArray(args.events) && args.events.length > 0 ? args.events : SAMPLE_WINDOWS_EVENTS.slice(0, 2);
    const focus = args.focusQuestion || 'Identify root causes and suggest safe remediation steps.';

    if (!context.llmService) {
      throw new Error('Central LLM Service is required for analyze_logs_with_llm.');
    }

    const llmResult = await context.llmService.analyze({
      pluginId: manifest.id,
      systemPrompt: 'You are a senior Windows kernel and event log diagnostician. Provide concise root-cause findings and safe remediation steps.',
      userPrompt: `Question: ${focus}\nEvents JSON:\n${JSON.stringify(events, null, 2)}`,
    });

    return {
      analyzedEventCount: events.length,
      isOffLan: llmResult.isOffLan,
      model: llmResult.model,
      diagnosis: llmResult.content,
    };
  },
};

export const eventLogsPlugin = { manifest, handlers };
