# Plugin: `usage-monitor`

Finds the app behind slowdowns, freezes and crashes. While AegisWin is unlocked, a background thread samples every process every 5 seconds and records what crosses your thresholds inside a daily watch window, and checks every monitor you have saved.

## Sub-components (chosen in the first-run wizard)

| Component | What it records |
| :--- | :--- |
| `usage-monitor:resource-spikes` | Processes at or above the CPU % (share of total CPU) or memory (MB) threshold, at most once per process and kind per minute. |
| `usage-monitor:crash-correlator` | Application Error (1000) and Application Hang (1002) events from the last 24 hours, each with the spikes of the same process in the 10 minutes before it. |
| `usage-monitor:active-window` | The process that owns the foreground window, each time it changes. Process names only, never window titles. |

The sampler only runs when `resource-spikes` or `active-window` is enabled, or a saved monitor is running.

## Tools

| Tool | MCP name | Gate |
| :--- | :--- | :--- |
| `configure_watch_window` | `usage-monitor__configure_watch_window` | pin_required |
| `propose_monitor` | `usage-monitor__propose_monitor` | auto (read-only) |
| `activate_monitor` | `usage-monitor__activate_monitor` | pin_required |
| `list_monitors` | `usage-monitor__list_monitors` | auto (read-only) |
| `pause_monitor` | `usage-monitor__pause_monitor` | pin_required |
| `delete_monitor` | `usage-monitor__delete_monitor` | pin_required |
| `capture_diagnostic_snapshot` | `usage-monitor__capture_diagnostic_snapshot` | auto (read-only) |
| `analyze_clues_with_llm` | `usage-monitor__analyze_clues_with_llm` | auto (read-only) |
| `purge_telemetry_history` | `usage-monitor__purge_telemetry_history` | pin_required |

- Watch window: 24-hour `HH:MM` start and end, local time. It wraps past midnight when the end is earlier than the start; equal start and end means all day (the default). Defaults: CPU 85 %, memory 2048 MB, all processes.
- Changing the watch window needs your PIN: an AI agent over MCP gets an approval request instead of changing it, because the window decides what gets recorded.
- Snapshot: system CPU and memory, top 10 processes by CPU and by memory, recorded spikes, correlated crash and hang events, foreground changes, and monitor hits. Disabled components show as `"component disabled"`.

## Monitors

A monitor is a rule that says when something worth recording happens, for example "game.exe uses 80 % CPU for 30 seconds while an Application Hang is logged, on Friday and Saturday evenings". The rule language is defined in [ADR 0002 §1](../../documentation/adr/0002-ai-monitor-creator.md).

- **Anyone can propose, only you can start.** `propose_monitor` checks a rule and returns the description AegisWin writes from the rule itself, its privacy flags, a replay, and any problems. It saves nothing. `activate_monitor`, `pause_monitor`, and `delete_monitor` need your PIN, so an AI agent gets an approval request that shows the full rule it wants to run.
- **Monitors only watch.** A hit is recorded in memory (shown in the snapshot and counted in `list_monitors`). A monitor never runs anything or changes Windows.
- **Components still decide.** A rule that needs a turned-off component is refused, and a saved monitor stops while its component is off, then runs again when it is back.
- **Replay.** A proposal shows how often the rule would have fired on the samples kept in memory for the last 30 minutes of the watch window. Event and crash conditions are checked against the event logs as they are when you propose. Few samples means little was checked; it is not a prediction.
- **Limits.** 20 monitors, 1-8 conditions each, all evaluated on the shared 5-second sample. Event and crash conditions read the logs they need every 15 seconds and count for 10 minutes after the event.

## Privacy

- Telemetry is kept in memory only, in ring buffers of 500 entries. It is never written to `./data`, and it is cleared when the vault locks or with `purge_telemetry_history`.
- The watch window settings also reset when the vault locks.
- Saved monitors are kept inside the encrypted vault (`documentation/PLUGIN_SPEC.md` §5), so they survive a restart. Their hits are telemetry: memory only, cleared on lock and by `purge_telemetry_history`, which keeps the monitors themselves.
- For replay, the last 30 minutes of samples inside the watch window are kept in memory: process names with CPU and memory (only those at 1 % CPU or 64 MB and up, the lowest a rule can use) and system load while `resource-spikes` is on, and the foreground process name while `active-window` is on. They are cleared on lock and by `purge_telemetry_history` and are never sent to the LLM.

## How it talks to Windows

- Per-process CPU and memory: the `sysinfo` crate (Win32 process snapshots under the hood). No processes are spawned.
- Foreground app: `GetForegroundWindow` + `GetWindowThreadProcessId`.
- Crash events: `aegis_core::os::eventlog` on the Application log; monitors with event conditions also read the System or Setup log, only for the event ids they name.

## Tests

`cargo test -p aegis-plugin-usage-monitor`: watch-window maths, spike detection and cooldown, component gating, crash correlation, a real snapshot of this machine, sampler start/stop on unlock/lock, LLM analysis against a loopback mock, the rule language (`src/rules.rs`), saved monitors (`src/monitors.rs`), replay (`src/replay.rs`), the AI creator's reply format, question filter, and consistency check (`src/creator.rs`), and the monitor tools' PIN gates through the real engine (`tests/monitors.rs`).
