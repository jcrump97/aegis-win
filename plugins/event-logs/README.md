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

## Tests

`cargo test -p aegis-plugin-event-logs`: reads the real Application log, filters by the id and source of a real event, checks channel and source validation, the Security admin path, and LLM analysis against a loopback mock.
