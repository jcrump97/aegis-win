# Plugin: Windows Event & Application Log Explorer (`event-logs`)

## Purpose
Provides low-overhead exploration of Windows `Application`, `System`, and `Security` event logs along with AI-assisted root-cause diagnostics via the Central LLM Service.

## Skeptical Efficiency Rationale
Instead of spawning `powershell.exe -Command "Get-WinEvent ..."` (which incurs a 400–900ms CLR startup penalty per query and frequently triggers EDR command-line inspection), this plugin constructs native `wevtutil qe <Channel> /q:"<XPath>" /f:xml /rd:true` queries or calls `EvtQuery` directly via the Tauri Rust bridge.

## Tools & Default Gating
| Tool ID | Requires Admin | Default Gate Policy | Description |
| :--- | :--- | :--- | :--- |
| `query_logs` | `false` (`true` for `Security`) | `auto` | Queries recent events from Application, System, or Security channels. |
| `filter_by_event_id` | `false` | `auto` | Filters channel records by exact Event ID (e.g., `1000`, `1002`, `7034`). |
| `analyze_logs_with_llm` | `false` | `auto` (with Off-LAN plugin trust check) | Sends selected event records to the Central LLM Service. |
