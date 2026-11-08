# AegisWin Self-Contained Plugin Specification

Every plugin in `plugins/<plugin-id>/` is a self-contained module compiled into the portable executable.

> Plugins are Rust crates ([ADR 0001](adr/0001-rust-core.md)). The Node.js prototypes have been removed.

## 1. Required Files per Plugin Directory
Each `plugins/<plugin-id>/` directory MUST contain:
1. `Cargo.toml`: a workspace member crate named `aegis-plugin-<plugin-id>` that depends on `aegis-core`.
2. `manifest.json`: declarative metadata, installable sub-components (if modular), and tool schemas with default gate policies. Embedded at compile time with `include_str!` and validated by `aegis-core` at startup.
3. `src/lib.rs`: implements the `aegis_core::Plugin` trait: tool execution handlers, dry-run impact evaluators, and UI state descriptors.
4. `README.md`: human and agent documentation covering commands, Windows APIs used, privilege requirements, and edge cases.
5. `tests/<plugin-id>.rs`: integration tests run by `cargo test --workspace` on every commit.

Plugins are registered at compile time in `src-tauri`. There is no runtime loading of plugin code.

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
      "readOnly": false,
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

Every tool MUST declare `requiresAdmin: boolean`, `defaultGatePolicy: "auto" | "pin_required"`, and `readOnly: boolean` (sent to MCP clients as `readOnlyHint`). A tool that belongs to an optional sub-component also names it in `component`, and fails with `COMPONENT_DISABLED` while that component is off. A tool only the AegisWin app may call sets `appOnly: true` (default `false`): it is left out of MCP `tools/list`, and an MCP call gets the same `unknown tool` error as a tool that does not exist, so agents cannot find or reach it. Its gate still applies in the app, and the app's generic tool forms and gate settings leave it out (the engine's plugin view reports `appOnly`), so the plugin's own screen is the only way in. Unknown fields are rejected.

### 2.1 Naming
- Plugin ids: lowercase letters, digits and `-`. Tool ids: lowercase letters, digits and `_`. Neither may contain `__`.
- Internally a tool is `plugin:tool` (gate overrides use this key). Over MCP it is `plugin__tool`, because MCP clients only accept names matching `^[a-zA-Z0-9_-]{1,64}$`; the combined name must fit in 64 characters.

### 2.2 `inputSchema` subset
`aegis-core::schema` enforces exactly these keywords: `type` (`object`, `string`, `integer`, `number`, `boolean`, `array`), `properties`, `required`, `additionalProperties: false`, `enum`, `minimum`, `maximum`, `minLength`, `maxLength`, `items`, `maxItems`, `default`, `description`. A manifest using any other keyword fails validation at startup, so a schema never looks stricter than what is enforced. Defaults are filled in before the tool runs. Anything the subset cannot express (such as a character allow-list) is validated in the tool itself.

### 2.3 `dryRun`
A tool that declares a boolean `dryRun` property MUST make `dryRun: true` side-effect free: it describes the commands it would run and their impact, and runs nothing. Dry runs skip the PIN and admin gates.

## 3. Tool Gate Policy Values
- `"auto"`: Executes immediately when invoked from the UI or MCP server (ideal for read-only log queries or telemetry snapshots).
- `"pin_required"`: Requires explicit human approval via the local `/approve/<ticket-id>` PIN-gated web page when called over MCP (or PIN confirmation modal in the UI). Users can change every tool's gate policy on the app's MCP server tab; loosening a gate to `auto` needs the PIN.
- **Describing a gated call.** When raw arguments are hard to judge (for example a monitor rule as JSON), the plugin implements `Plugin::review_call`, which returns a `CallReview` of plain sentences and warnings written by its own code from the validated arguments. The engine stores it on the approval ticket, and the browser page and the app show it, escaped, above the raw arguments. It must never repeat AI- or agent-supplied reasoning as if it were a description; names the agent chose are quoted.

## 4. Talking to Windows
1. **Prefer documented Win32 APIs** through Microsoft's `windows` crate (e.g. `EvtQuery`/`EvtRender` for event logs, PDH for performance counters) over spawning processes.
2. **When a system binary is unavoidable** (e.g. `sfc.exe`, `netsh.exe`), launch it by absolute path under `%SystemRoot%\System32` with an argument vector (`std::process::Command::new(path).args([...])`). Never go through `cmd /c`, PowerShell, or string-built command lines, and never resolve via `PATH`.
3. **Validate every tool input** against `inputSchema` and an allow-list (e.g. event channel names) before it reaches an API or argument vector.
4. **Never return canned output as if it were real.** Tool results come from the OS. A tool that cannot run says so (`executed: false` with a reason).

## 5. Plugin Data in the Vault
A plugin that must remember owner-approved configuration (such as `usage-monitor`'s monitor rules, ADR 0002) uses the `PluginStore` the engine hands it in `ToolContext::store` on every tool call and in `UnlockContext::store` on `on_unlock`.
1. **Own records only.** The engine binds each store to the calling plugin's id. A plugin cannot open another plugin's records.
2. **Encrypted, and only while unlocked.** Records live inside `vault.enc.json` (AES-256-GCM). Every call fails with `VAULT_LOCKED` while the vault is locked and with `PLUGIN_DISABLED` while the plugin is uninstalled. Uninstalling keeps the records; installing again makes them reachable again. The store holds no data or secret itself, so keeping a handle in a background thread is safe.
3. **Small and rare.** Keys are 1-64 characters of `a-z`, `0-9`, `_`, `-`. One plugin's records are capped at 256 KiB, and a write over the cap is refused with nothing changed. Each write re-encrypts and saves the vault, so the store is for configuration that changes when the owner acts, never for telemetry.
4. **Gating is the tool's job.** The store does not ask for the PIN. A tool that changes what a plugin records or does must declare `defaultGatePolicy: "pin_required"`.
5. **Never store the PIN** or any credential in plugin data, and never return records verbatim to an LLM without the scrubbing in `SECURITY_MODEL.md` §6.
