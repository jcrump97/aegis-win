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

Every tool MUST declare `requiresAdmin: boolean`, `defaultGatePolicy: "auto" | "pin_required"`, and `readOnly: boolean` (sent to MCP clients as `readOnlyHint`). A `readOnly: false` call, unless it is a `dryRun: true` call, runs only when no other such call is running ([ADR 0003 §5.1](adr/0003-action-plans.md)), so mark a tool read-only only if it changes nothing on Windows or in AegisWin. A tool may set `planEligible: true` (default `false`) to be a step of an action plan ([ADR 0003 §4](adr/0003-action-plans.md)); the manifest is rejected at startup unless that tool is `pin_required` by default, `readOnly: false`, not `appOnly`, and declares a boolean `dryRun`. Leave it off for tools with their own review screen (monitor management) and for destructive one-offs such as purging history. A tool that belongs to an optional sub-component also names it in `component`, and fails with `COMPONENT_DISABLED` while that component is off. A tool only the AegisWin app may call sets `appOnly: true` (default `false`): it is left out of MCP `tools/list`, and an MCP call gets the same `unknown tool` error as a tool that does not exist, so agents cannot find or reach it. Its gate still applies in the app, and the app's generic tool forms and gate settings leave it out (the engine's plugin view reports `appOnly`), so the plugin's own screen is the only way in. Unknown fields are rejected.

### 2.1 Naming
- Plugin ids: lowercase letters, digits and `-`. Tool ids: lowercase letters, digits and `_`. Neither may contain `__`.
- Internally a tool is `plugin:tool` (gate overrides use this key). Over MCP it is `plugin__tool`, because MCP clients only accept names matching `^[a-zA-Z0-9_-]{1,64}$`; the combined name must fit in 64 characters.

### 2.2 `inputSchema` subset
`aegis-core::schema` enforces exactly these keywords: `type` (`object`, `string`, `integer`, `number`, `boolean`, `array`), `properties`, `required`, `additionalProperties: false`, `enum`, `minimum`, `maximum`, `minLength`, `maxLength`, `items`, `maxItems`, `default`, `description`. A manifest using any other keyword fails validation at startup, so a schema never looks stricter than what is enforced. Defaults are filled in before the tool runs. Anything the subset cannot express (such as a character allow-list) is validated in the tool itself.

### 2.3 `dryRun`
A tool that declares a boolean `dryRun` property MUST make `dryRun: true` side-effect free: it describes the commands it would run and their impact, and runs nothing. Dry runs skip the PIN and admin gates. A `planEligible` tool's dry run SHOULD return the commands as a `commands` array of strings, which the plan review shows. When a real run does not succeed but returns normally, it MUST say so with `"success": false`: a plan treats that as a failed step and stops.

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

## 6. History Streams and Locked Work ([ADR 0002 §5](adr/0002-ai-monitor-creator.md))
A plugin that keeps a record over time (such as `usage-monitor`'s timeline) uses the `HistoryHandle` in `ToolContext::history` and `UnlockContext::history`.
1. **Own stream only.** The handle is bound to the plugin's id; the stream is named after it. The id `approvals` is reserved for the engine's own stream.
2. **Write-only while locked.** `append` seals one JSON object (the engine adds `at`) and keeps working after the vault locks, once the stream has a key (created in the vault the first time the stream is written while unlocked). `read`, `purge`, `retention` and `set_retention` need the vault unlocked and the plugin installed.
3. **Records are small and summarized.** At most 64 KiB each. Write events and periodic summaries, never raw high-rate samples. Process names only, never window titles.
4. **Purge replaces the key.** `purge` deletes every file of the stream and gives it a new keypair, so a deleted file recovered from the disk cannot be read later.
5. **Locked work is declared.** `set_runtime(Some(section))` saves what the plugin runs while locked in the vault and writes it, with the stream's public key and retention, to `./data/runtime/<plugin>.json`. On every unlock the engine compares that file with the vault before any plugin starts; a file that differs (other than the tray's `paused` flag), cannot be read, or was never written by AegisWin is moved aside and waits for the owner. `set_runtime(None)` removes the file. Uninstalling a plugin removes it too.
6. **Running while locked.** When the vault locks and the plugin has declared work (and its file is not waiting for review), the engine calls `run_locked(&LockedContext)` instead of `on_lock`. `LockedContext.runtime` is the vault's copy of the section, never the file. The plugin must drop everything `on_lock` drops, may keep running only what the section describes, and writes only to its history. The default calls `on_lock` and runs nothing. `set_paused` (tray, no PIN) and `on_exit(ExitReason::Quit | Shutdown)` let it record a pause and a clean stop; `on_exit` is called before the final `on_lock`. **At launch** the engine also calls `run_locked`, with `launch: Some(Launch::Manual | Autostart)` and the section read from the runtime file, which is checked only at the next unlock: validate it as untrusted input. `resume_notice` is asked once after each unlock; return the gap before a launch resume, or `None`. `UnlockContext.paused` carries the tray pause.
7. **Gating is the tool's job.** The handle does not ask for the PIN. A tool that reads, purges, or changes the retention of a stream declares `defaultGatePolicy: "pin_required"`.
