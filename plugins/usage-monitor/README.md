# Plugin: `usage-monitor`

Finds the app behind slowdowns, freezes and crashes. While AegisWin is unlocked, a background thread samples every process every 5 seconds and records what crosses your thresholds inside a daily watch window, and checks every monitor you have saved. Running monitors keep going while AegisWin is locked.

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
| `read_monitor_history` | `usage-monitor__read_monitor_history` | pin_required (read-only) |
| `configure_history_retention` | `usage-monitor__configure_history_retention` | pin_required |
| `purge_telemetry_history` | `usage-monitor__purge_telemetry_history` | pin_required |
| `monitor_chat_start`, `monitor_chat_reply`, `monitor_chat_cancel` | none: in the app only | auto (read-only) |

- Watch window: 24-hour `HH:MM` start and end, local time. It wraps past midnight when the end is earlier than the start; equal start and end means all day (the default). Defaults: CPU 85 %, memory 2048 MB, all processes.
- Changing the watch window needs your PIN: an AI agent over MCP gets an approval request instead of changing it, because the window decides what gets recorded.
- Snapshot: system CPU and memory, top 10 processes by CPU and by memory, recorded spikes, correlated crash and hang events, foreground changes, and monitor hits. Disabled components show as `"component disabled"`.

## Monitors

A monitor is a rule that says when something worth recording happens, for example "game.exe uses 80 % CPU for 30 seconds while an Application Hang is logged, on Friday and Saturday evenings". The rule language is defined in [ADR 0002 §1](../../documentation/adr/0002-ai-monitor-creator.md).

- **Anyone can propose, only you can start.** `propose_monitor` checks a rule and returns the description AegisWin writes from the rule itself, its privacy flags, a replay, and any problems. It saves nothing. `activate_monitor`, `pause_monitor`, and `delete_monitor` need your PIN, so an AI agent gets an approval request that shows the full rule it wants to run and the description AegisWin writes from it, with privacy warnings.
- **Monitors only watch.** A hit is kept in memory (shown in the snapshot and counted in `list_monitors`) and written to the encrypted history. A monitor never runs anything or changes Windows.
- **Components still decide.** A rule that needs a turned-off component is refused, and a saved monitor stops while its component is off, then runs again when it is back.
- **Describe it to the AI (in the app).** The chat tools send your description and answers to the configured LLM, which asks up to 3 rounds of questions and then proposes a rule, shown like any proposal. It can ask once to see running app names; nothing is sent unless you agree. Each step says whether it went to an on-LAN or Off-LAN LLM. AI agents over MCP cannot see or call these tools.
- **In the app.** The Usage Monitor tab lists your monitors (pause, resume, and delete need your PIN), holds the AI chat, and has a rule editor for building a rule or adjusting a saved one (`list_monitors` returns each stored rule for this). The editor checks a rule with `propose_monitor` and shows the review; any edit discards that check, so only a rule you have just seen described can be started, and starting it needs your PIN. The AI's reasoning appears only in a box labelled as AI-written, apart from the description AegisWin writes.
- **Replay.** A proposal shows how often the rule would have fired on the samples kept in memory for the last 30 minutes of the watch window. Event and crash conditions are checked against the event logs as they are when you propose. Few samples means little was checked; it is not a prediction.
- **Limits.** 20 monitors, 1-8 conditions each, all evaluated on the shared 5-second sample. Event and crash conditions read the logs they need every 15 seconds and count for 10 minutes after the event.

## History

While the sampler runs, the plugin writes an encrypted timeline through its `HistoryHandle` (`documentation/PLUGIN_SPEC.md` §6, ADR 0002 §5) to `./data/history/usage-monitor/`:

- **Records:** `session_start` (launch kind, boot time, version), a `heartbeat` every 60 seconds, `session_stop` (why it stopped), each recorded `spike` (process, pid, kind, CPU %, MB), each `foreground` change (process name), and each `monitor_hit`. Raw 5-second samples are never written.
- **Reading** (`read_monitor_history`, PIN): the last 1 to 90 days. Events newest first (heartbeats left out, at most 2000), the gaps worked out from the records, and System log events found inside each gap as evidence (Kernel-Power 41, 42 and 107; User32 1074, which keeps who asked for the shutdown; EventLog 6008). Values are never filled in across a gap. Damaged, cut-off, or foreign-key files are listed as problems. Events recorded while AegisWin itself was running a repair are labelled "during AegisWin repair: <tool>" (from the engine's approval record; ADR 0003 §5).
- **Gaps:** heartbeats more than 2 minutes apart are sleep; a `session_stop` followed by a new start is a stop (lock, quit, shutdown, or a change of monitoring settings); a new start with no stop before it is unexpected (crash or power loss).
- **Retention** (`configure_history_retention`, PIN): 14 days or 64 MB by default, adjustable within 1-90 days and 8-512 MB. Oldest files go first.
- **Runtime file:** `./data/runtime/usage-monitor.json` lists the running monitors and enabled components with the stream's public key, which is what a locked AegisWin will need to keep writing. It is removed when nothing runs. On every unlock it is checked against the vault; if it was changed, the app shows a warning and nothing resumes from it until you rewrite it from your saved settings.
- **In the app:** the History card on the Usage Monitor tab shows the timeline, sets the limits, and deletes everything.

There are no crash records: crashes and hangs come from the Application log in the snapshot.

## While locked

- **Running monitors keep going** when AegisWin locks (*locked, monitoring*). Only the monitors listed in the vault's copy of the runtime section run, never one read from the file on disk. While locked the plugin keeps nothing in memory: no spikes, foreground apps, replay samples, or hit list. It writes only monitor hits and the heartbeat to the encrypted history, which it cannot read back.
- **Nothing runs locked** when no monitor runs (a lock then ends the session with "monitoring stopped") or when the runtime file is waiting for your review.
- **Pause from the tray** (Pause monitoring / Resume monitoring, no PIN) stops the sampler and records `paused`, then `resumed`; the history shows the time in between as paused by you. The pause also holds across a lock and an unlock.
- **Stop reasons:** quitting (tray Quit, closing the window, restarting as administrator) records `quit`; Windows ending the session records `shutdown`.
- **At launch** AegisWin resumes the monitors listed in the runtime file, locked, before you unlock (`session_start` says `manual`, or `autostart` for the Startup shortcut's `--background`). The rules are validated again. The file is checked against your saved settings at the next unlock; if it was changed, it is set aside and the monitors run from your settings instead. A tray pause kept in the file carries over.
- **After unlock** a banner says when monitors were stopped before this launch and why (from the last 14 days of history), until you dismiss it.

## Privacy

- In memory, telemetry is kept in ring buffers of 500 entries, only while unlocked, and cleared when the vault locks or with `purge_telemetry_history`.
- On disk, it is only in the encrypted history above. Only the PIN can read it; AegisWin itself cannot read it while locked. Process names only, never window titles.
- `purge_telemetry_history` (PIN) clears memory, deletes every history file, and gives the history a new key, so a deleted file recovered from the disk cannot be read. Saved monitors are kept.
- The watch window settings reset when the vault locks.
- Saved monitors are kept inside the encrypted vault (`documentation/PLUGIN_SPEC.md` §5), so they survive a restart.
- For replay, the last 30 minutes of samples inside the watch window are kept in memory: process names with CPU and memory (only those at 1 % CPU or 64 MB and up, the lowest a rule can use) and system load while `resource-spikes` is on, and the foreground process name while `active-window` is on. They are cleared on lock and by `purge_telemetry_history` and are never sent to the LLM.

## How it talks to Windows

- Per-process CPU and memory: the `sysinfo` crate (Win32 process snapshots under the hood). No processes are spawned.
- Foreground app: `GetForegroundWindow` + `GetWindowThreadProcessId`.
- Crash events: `aegis_core::os::eventlog` on the Application log; monitors with event conditions also read the System or Setup log, only for the event ids they name.

## Tests

`cargo test -p aegis-plugin-usage-monitor`: watch-window maths, spike detection and cooldown, component gating, crash correlation, a real snapshot of this machine, sampler start/stop on unlock/lock, LLM analysis against a loopback mock, the rule language (`src/rules.rs`), saved monitors (`src/monitors.rs`), replay (`src/replay.rs`), the AI creator's reply format, question filter, and consistency check (`src/creator.rs`), the in-app chat against a loopback LLM mock, including retries, the round limit, app-name consent, and that agents cannot reach it (`src/chat.rs`, `tests/chat.rs`), the monitor tools' PIN gates through the real engine (`tests/monitors.rs`), the timeline's gaps and evidence (`src/timeline.rs`), and the encrypted history, runtime file, purge, and retention through the real engine (`tests/history.rs`).
