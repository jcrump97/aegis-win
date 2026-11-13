# Plugin: `event-logs`

Reads Windows event logs and asks the LLM service to explain them. Every tool is read-only and `auto` by default.

| Tool | MCP name | What it does |
| :--- | :--- | :--- |
| `query_logs` | `event-logs__query_logs` | Newest events from `Application`, `System`, `Setup` or `Security` at or above a minimum severity (`Critical`, `Error`, `Warning`, `Information`, `All`), optionally limited to the last N hours. |
| `filter_by_event_id` | `event-logs__filter_by_event_id` | Events with one Event ID, optionally from one source (provider), e.g. `1000` / `Application Error`. |
| `analyze_logs_with_llm` | `event-logs__analyze_logs_with_llm` | Sends up to 100 events plus an optional question to the LLM service for a root-cause explanation. |

## How it talks to Windows

- `EvtQuery` / `EvtNext` / `EvtRender` (system properties) / `EvtFormatMessage` from `wevtapi.dll`, through `aegis_core::os::eventlog`. No `wevtutil` process and no XML parsing.
- Results are newest first. Each event has `recordId`, `timeCreated` (UTC, RFC 3339), `provider`, `eventId`, `level`, `levelName` and the formatted `message` (capped at 4000 characters; `null` when the provider has no message resources on this PC).
- The computer name is not returned.

## Input safety

- Channels come from a fixed allow-list; anything else is rejected before a query is built.
- The XPath filter is built only from typed integers and a source name restricted to letters, digits, spaces and `. _ - ( ) /`, so it cannot be injected.

## Privileges

- `Application`, `System` and `Setup` are readable by standard users.
- `Security` needs administrator rights. As a standard user the tool fails with `REQUIRES_ADMIN`, and the UI offers "Restart as administrator".

## LLM use

`analyze_logs_with_llm` goes through the plugin's engine-bound `LlmHandle`. Off-LAN endpoints require the user to trust `event-logs` first, and the payload is scrubbed of user and host names. See `documentation/SECURITY_MODEL.md` §6.

## Diagnose checks ([ADR 0005](../../documentation/adr/0005-diagnose-this-pc.md))

`run_checks` (`src/checks.rs`) reads the System and Application logs, one query per provider and only the event IDs below, at most 500 events each, newest first. Then nine pure functions turn what was read into findings. The checks count incidents, not events: events within 10 minutes of each other are one incident.

| Check | Read | Finding |
|---|---|---|
| `unexpected_shutdown` | Kernel-Power 41, EventLog 6008 | From one; critical from 3. A restart within 10 minutes of a blue screen counts under `blue_screen`. |
| `blue_screen` | BugCheck 1001 (`Microsoft-Windows-WER-SystemErrorReporting`, and the old `BugCheck` name) | From one; critical from 2. Stop codes read from the message. |
| `app_crashes` | Application Error 1000, Application Hang 1002 | From 3 for one program (`info`); `warning` from 10. |
| `service_failures` | Service Control Manager 7031, 7034, 7000, 7009 | By service; `info`, `warning` from 3. A service that failed to start in the 2 minutes after one Windows start (EventLog 6005), and never otherwise, is left out as a timing problem. |
| `disk_errors` | disk 7, 51, 153; storahci and stornvme 129; Ntfs 55, 98 (Critical, Error and Warning only: Ntfs 98 is also logged as Information for a healthy volume) | From one; critical for a bad block (7), file system damage (55), or 5 incidents. |
| `hardware_errors` | WHEA-Logger 17, 18, 19, 47 | From one; critical for a fatal error (18). |
| `display_driver_resets` | Display 4101 | `info`; `warning` from 3. |
| `update_failures` | WindowsUpdateClient 20 | `info`; `warning` from 3. |
| `dns_timeouts` | DNS Client 1014 | From 10 timeouts (`info`), `warning` from 50. Each timeout counts. |

Program and service names come from English event messages. On other languages they are grouped as "could not name". `nextTools` suggests `windows-health:sfc_scan` (shutdowns, blue screens, update failures) and `windows-health:flush_dns` (DNS), so `event-logs` is only valid with `windows-health` compiled in. No admin rights are needed. If a log cannot be read, only the checks that need it are skipped or failed.

## Tests

`cargo test -p aegis-plugin-event-logs`: reads the real Application log, filters by the id and source of a real event, checks channel and source validation, the Security admin path, and LLM analysis against a loopback mock. `tests/checks.rs` runs every check on recorded events (incidents, thresholds, the blue-screen and boot rules, the lookback window, the 500 cap, failed reads), reads this PC's logs once, and runs the checks through the real engine.
