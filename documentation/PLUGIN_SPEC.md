# AegisWin Self-Contained Plugin Specification

Every plugin in `plugins/<plugin-id>/` is a self-contained module compiled into the portable executable.

> **Migration status**: plugins are moving from Node.js prototypes (`index.mjs`) to Rust crates, per [ADR 0001](adr/0001-rust-core.md). New plugins MUST use the Rust layout in §1. A plugin that has not been ported yet keeps its legacy layout (§1.1) until its port PR.

## 1. Required Files per Plugin Directory (Rust)
Each `plugins/<plugin-id>/` directory MUST contain:
1. `Cargo.toml`: a workspace member crate named `aegis-plugin-<plugin-id>` that depends on `aegis-core`.
2. `manifest.json`: declarative metadata, installable sub-components (if modular), and tool schemas with default gate policies. Embedded at compile time with `include_str!` and validated by `aegis-core` at startup.
3. `src/lib.rs`: implements the `aegis_core::Plugin` trait: tool execution handlers, dry-run impact evaluators, and UI state descriptors.
4. `README.md`: human and agent documentation covering commands, Windows APIs used, privilege requirements, and edge cases.
5. `tests/<plugin-id>.rs`: integration tests run by `cargo test --workspace` on every commit.

Plugins are registered at compile time in `src-tauri`. There is no runtime loading of plugin code.

### 1.1 Legacy Layout (Node.js prototype, until ported)
`manifest.json`, `index.mjs`, `README.md`, and `tests/<plugin-id>.test.mjs`. The port PR deletes `index.mjs` and the `.test.mjs` suite once the Rust tests cover the same behavior.

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

Every tool MUST declare `requiresAdmin: boolean` and `defaultGatePolicy: "auto" | "pin_required"`. The schema is unchanged by the Rust port.

## 3. Tool Gate Policy Values
- `"auto"`: Executes immediately when invoked from the UI or MCP server (ideal for read-only log queries or telemetry snapshots).
- `"pin_required"`: Requires explicit human approval via the local `/approve/<ticket-id>` PIN-gated web page when called over MCP (or PIN confirmation modal in the UI). Users can customize every tool's gate policy in Settings.

## 4. Talking to Windows
1. **Prefer documented Win32 APIs** through Microsoft's `windows` crate (e.g. `EvtQuery`/`EvtRender` for event logs, PDH for performance counters) over spawning processes.
2. **When a system binary is unavoidable** (e.g. `sfc.exe`, `netsh.exe`), launch it by absolute path under `%SystemRoot%\System32` with an argument vector (`std::process::Command::new(path).args([...])`). Never go through `cmd /c`, PowerShell, or string-built command lines, and never resolve via `PATH`.
3. **Validate every tool input** against `inputSchema` and an allow-list (e.g. event channel names) before it reaches an API or argument vector.
4. **Never return canned output as if it were real.** Tool results come from the OS. A tool that cannot run says so (`executed: false` with a reason).
