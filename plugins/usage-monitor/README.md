# Plugin: `usage-monitor`

Finds the app behind slowdowns, freezes and crashes. While AegisWin is unlocked, a background thread samples every process every 5 seconds and records what crosses your thresholds inside a daily watch window.

## Sub-components (chosen in the first-run wizard)

| Component | What it records |
| :--- | :--- |
| `usage-monitor:resource-spikes` | Processes at or above the CPU % (share of total CPU) or memory (MB) threshold, at most once per process and kind per minute. |
| `usage-monitor:crash-correlator` | Application Error (1000) and Application Hang (1002) events from the last 24 hours, each with the spikes of the same process in the 10 minutes before it. |
| `usage-monitor:active-window` | The process that owns the foreground window, each time it changes. Process names only, never window titles. |

The sampler only runs when `resource-spikes` or `active-window` is enabled.

## Tools

| Tool | MCP name | Gate |
| :--- | :--- | :--- |
| `configure_watch_window` | `usage-monitor__configure_watch_window` | auto |
| `capture_diagnostic_snapshot` | `usage-monitor__capture_diagnostic_snapshot` | auto (read-only) |
| `analyze_clues_with_llm` | `usage-monitor__analyze_clues_with_llm` | auto (read-only) |
| `purge_telemetry_history` | `usage-monitor__purge_telemetry_history` | pin_required |

- Watch window: 24-hour `HH:MM` start and end, local time. It wraps past midnight when the end is earlier than the start; equal start and end means all day (the default). Defaults: CPU 85 %, memory 2048 MB, all processes.
- Snapshot: system CPU and memory, top 10 processes by CPU and by memory, recorded spikes, correlated crash and hang events, and foreground changes. Disabled components show as `"component disabled"`.

## Privacy

- Telemetry is kept in memory only, in ring buffers of 500 entries. It is never written to `./data`, and it is cleared when the vault locks or with `purge_telemetry_history`.
- The watch window settings also reset when the vault locks.

## How it talks to Windows

- Per-process CPU and memory: the `sysinfo` crate (Win32 process snapshots under the hood). No processes are spawned.
- Foreground app: `GetForegroundWindow` + `GetWindowThreadProcessId`.
- Crash events: `aegis_core::os::eventlog` on the Application log.

## Tests

`cargo test -p aegis-plugin-usage-monitor`: watch-window maths, spike detection and cooldown, component gating, crash correlation, a real snapshot of this machine, sampler start/stop on unlock/lock, and LLM analysis against a loopback mock.
