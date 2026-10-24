# AegisWin Self-Contained Plugin Specification

Every plugin in `plugins/<plugin-id>/` is a self-contained module compiled into the portable executable.

## 1. Required Files per Plugin Directory
Each `plugins/<plugin-id>/` directory MUST contain:
1. `manifest.json` — Declarative metadata, installable sub-components (if modular), and tool schemas with default gating policies.
2. `index.mjs` — Tool execution handlers, dry-run impact evaluators, and UI state descriptors.
3. `README.md` — Human and agent documentation detailing commands, Windows APIs used, privilege requirements, and edge cases.
4. `tests/<plugin-id>.test.mjs` — Automated unit and integration tests executed on every commit by `scripts/ci-runner.mjs`.

## 2. `manifest.json` Schema
```json
{
  "id": "windows-health",
  "name": "Windows Health & Network Optimizer",
  "version": "1.0.0",
  "description": "Executes core Windows repair and network stack reset utilities.",
  "optionalInstallDefault": true,
  "usesLlm": true,
  "tools": [
    {
      "id": "flush_dns",
      "name": "Flush DNS Resolver Cache",
      "description": "Clears the Windows DNS client resolver cache via ipconfig /flushdns.",
      "requiresAdmin": false,
      "defaultGatePolicy": "pin_required",
      "inputSchema": {
        "type": "object",
        "properties": {
          "dryRun": { "type": "boolean", "default": false }
        }
      }
    }
  ]
}
```

## 3. Tool Gate Policy Values
- `"auto"`: Executes immediately when invoked from the UI or MCP server (ideal for read-only log queries or telemetry snapshots).
- `"pin_required"`: Requires explicit human approval via the local `/approve/<ticket-id>` PIN-gated web page when called over MCP (or PIN confirmation modal in the UI). Users can customize every tool's gate policy in Settings.
