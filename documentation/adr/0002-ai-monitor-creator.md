# ADR 0002: AI-assisted monitor creator, background monitoring, and encrypted monitor history

- **Status**: Accepted (2026-11-07). Phase 0 is implemented (commit `8b7ad4b`); later phases are not.
- **Date**: 2026-11-07
- **Amends**: [ADR 0001](0001-rust-core.md) rejected-option row 13 (telemetry on disk), [GUIDING_PRINCIPLES §2](../GUIDING_PRINCIPLES.md)
- **Plugin**: `usage-monitor` (the encrypted history writer in §5 is a shared `aegis-core` service)
- **Related**: [ADR 0003](0003-action-plans.md) (multi-step action plans; supersedes the PIN grace window and batch approve, see §11)

## Context

`usage-monitor` has one global watch window: a daily time range, a CPU % and memory MB threshold, and an optional process list. A sampler thread runs every 5 seconds while the vault is unlocked. Today:

| Behaviour | Today |
| :--- | :--- |
| Monitors | One, global, configured by hand or by `configure_watch_window` |
| AI role | After the fact only: `analyze_clues_with_llm` explains a snapshot |
| Close window | The process exits; exit locks the vault (`src-tauri/src/main.rs`, `RunEvent::Exit`) |
| Lock | Stops the sampler and clears all telemetry and the watch settings |
| Disk | Telemetry is never written to disk |
| Tray, idle auto-lock, autostart, single instance | None |
| `configure_watch_window` gate | `auto`, so an MCP agent can change what is recorded without the owner knowing (fixed in Phase 0: now `pin_required`) |

Users want to say what they are chasing ("my game stutters around 9pm") and get a monitor that keeps collecting across window closes, locks, and reboots. Users place a great deal of trust in this app, so the AI must never be able to act on its own, and collected data must stay unreadable without the PIN.

## Options considered

1. **Template filler**: the AI fills fields of 3–4 fixed monitor types.
2. **Small rule language**: the AI emits a monitor as JSON in a closed, bounded vocabulary that code validates.
3. **AI-written scripts** (PowerShell, WMI queries).

## Decision

**Option 2.** Option 1 is a subset of it. Option 3 is rejected: it breaks [PLUGIN_SPEC §4](../PLUGIN_SPEC.md) (no shell), invites antivirus flags, and cannot be validated in a way a user could trust.

The governing rule for every part of this design: **the AI proposes, code validates and describes, the owner approves with the PIN.** Monitors only observe and record.

## 1. Rule language (version 1)

```json
{
  "version": 1,
  "name": "Game stutter in the evening",
  "schedule": { "startTime": "20:30", "endTime": "23:30", "days": ["fri", "sat"] },
  "trigger": {
    "all": [
      { "type": "process_cpu", "process": "game.exe", "atLeastPercent": 80, "forSeconds": 30 },
      { "type": "event", "channel": "Application", "eventId": 1002 }
    ]
  },
  "cooldownSeconds": 300,
  "notify": "tray"
}
```

| Condition `type` | Fields | Notes |
| :--- | :--- | :--- |
| `process_cpu` | `process`, `atLeastPercent` 1–100, `forSeconds` 5–3600 | Share of total CPU, as today |
| `process_memory` | `process`, `atLeastMb` 64–1048576, `forSeconds` | |
| `system_cpu` | `atLeastPercent`, `forSeconds` | |
| `system_memory` | `atLeastPercent`, `forSeconds` | |
| `event` | `channel` (`Application`, `System`, `Setup`), `eventId` 0–65535, optional `provider` ≤128 | Security is excluded in v1 (admin only). An event counts as "true" for 10 minutes after it occurs, matching the existing crash correlation window. |
| `crash` | `process` | Application Error 1000 / Application Hang 1002 for that process |
| `foreground` | `process` | Needs the `usage-monitor:active-window` component |

- **Fields**: `process` is an executable name (≤260 characters, no path separators) or `"*"` for any process. `schedule.days` is optional (default every day), and equal start and end means all day, as today. `forSeconds` rounds up to the 5-second sample period. `notify` is `"tray"` or `"none"`.
- **Combinators**: one level only, `all` or `any`, 1–8 conditions. No nesting in v1.
- **Caps**: 20 monitors, a fixed 5-second sample period, `cooldownSeconds` 60–86400. One shared sampler evaluates every monitor; there are no per-monitor threads.
- **What a monitor can do when it fires**: write a `monitor_hit` record and optionally change the tray icon. **There is no action, script, or tool call.** If actions are ever added, a hit may only open a normal approval ticket.
- **Validation**: `aegis-core::schema` checks shape and ranges. Per-type rules it cannot express (field sets per `type`, process-name characters, components enabled) are checked in code, as PLUGIN_SPEC §2.2 already allows. A rule that needs a disabled component is rejected with the reason; a monitor never turns a component on.
- **Privacy flags** shown on review: `foreground` conditions, `"*"` process scope, and all-day schedules.
- The existing watch window becomes a built-in rule named "Default" (Phase 1), so there is one model, not two.

**Rule storage (Phase 1b).** Rules are kept with the new `aegis-core` plugin data store (`PLUGIN_SPEC.md` §5): records inside the encrypted vault, bound to the plugin's id, reachable only while unlocked and installed, capped at 256 KiB per plugin. Uninstalling `usage-monitor` keeps its rules but makes them unreachable until it is installed again; `purge_telemetry_history` does not delete rules. A one-line pointer in `SECURITY_MODEL.md` waits until the owner's pending edits to that file land.

**Decided while implementing the rule language (Phase 1a, `plugins/usage-monitor/src/rules.rs`):**

- **Strict parsing.** Unknown top-level, schedule, or condition fields are rejected, not ignored, so a rule cannot carry anything the description does not show. `HH:MM` must be exactly two-digit hours and minutes.
- **Components.** `process_cpu`, `process_memory`, `system_cpu`, and `system_memory` need `usage-monitor:resource-spikes`. `event` and `crash` need `usage-monitor:crash-correlator`. `foreground` needs `usage-monitor:active-window`.
- **`foreground` needs a named process.** `"*"` is rejected there, since "any app is in the foreground" is always true and only records usage.
- **Hidden characters.** Names, process names, and providers reject control characters and invisible format characters (bidi overrides, zero-width marks), so the review text cannot read differently from the rule. Errors that echo input strip those characters and are length-capped.
- **Names are names.** Process names also reject `\ / : * ? " < > |`. Matching is case-insensitive. A `crash` condition matches the process as a whole word in the event text, so `game.exe` does not match `mygame.exe`.
- **Duration.** `forSeconds` means that many consecutive 5-second samples (rounded up, at least one). Any sample where the condition is false, a tick gap over 15 seconds (sleep, a stalled sampler), the clock moving backwards, or leaving the schedule resets the count. The sample after a gap starts a new count.
- **Schedule.** Times are local. An overnight window belongs to the day it started on: with `days: ["fri"]` and 22:00–02:00, Saturday 01:00 is active and Saturday 23:00 is not.
- **Cooldown.** Measured from the last hit. If the clock moves backwards, the cooldown ends rather than stretching.
- **Duplicate conditions** in one trigger are rejected.

### New and changed tools (`usage-monitor`)

| Tool | Gate | readOnly | Purpose |
| :--- | :--- | :--- | :--- |
| `propose_monitor` | auto | true | Validates a rule. Returns a `proposalId` (memory only, 30-minute expiry, cleared on lock), a code-generated description, privacy flags, and a replay result. Activates nothing. Takes an optional `reasoning` string from an MCP agent. |
| `activate_monitor` | **pin_required** | false | Saves and starts a proposal. Edits are a new proposal that replaces a monitor id. |
| `list_monitors` | auto | true | Active and paused monitors, with code-generated descriptions |
| `delete_monitor`, `pause_monitor` | **pin_required** | false | Weakening monitoring could hide evidence, so it needs the PIN |
| `read_monitor_history` | **pin_required** (open question 2) | true | Decrypted history, needs the vault unlocked |
| `configure_watch_window` | **auto → pin_required** | false | Closes the gap where an agent could quietly change what is recorded (Phase 0). Removed once "Default" is a rule. |
| `purge_telemetry_history` | pin_required (unchanged) | false | Now also deletes history files and replaces the monitor keypair (§6) |

The approval portal and the in-app queue show the **code-generated description and privacy flags** for `activate_monitor`, not only the raw arguments.

**None of these tools is ever plan-eligible** ([ADR 0003 §4](0003-action-plans.md)). Monitor management and purge keep their own single-ticket review, so a monitor can never be switched on or off as one step among others.

## 2. Review screen and the AI's reasoning summary

Each proposal shows two visually separate panels:

1. **"What this monitor does"**: generated by AegisWin from the rule. This is the source of truth.
2. **"Why the AI suggested this (AI-generated, may be wrong)"**: up to 3 bullets, 600 characters in total, rendered as plain text. For an MCP proposal this panel is labelled "Supplied by the requesting agent".

- The reasoning is never parsed for settings.
- It is a summary the model writes, not a dump of its step-by-step reasoning.
- **Consistency check**: if the reasoning names a process or event ID that is not in the rule, the review shows "The AI's explanation mentions things this monitor does not watch."
- **Before activating**, the owner can adjust fields in a form; each edit is validated again. A **replay** shows "this would have fired N times" against recorded history (unlocked only).

## 3. Clarifying-question loop (in-app only)

The loop is driven by Tauri commands (`monitor_chat_start`, `monitor_chat_reply`) and the central LLM service under `usage-monitor`'s `LlmHandle`. External MCP agents do not use it; they hold their own conversation with the user and call `propose_monitor`.

- **Reply format.** Each AI turn must be exactly one of these, validated against a schema:
  - `{ "questions": [ { "text", "choices"? } ] }`
  - `{ "proposal": { "rule", "reasoning" } }`
  - `{ "unsupported": { "reason" } }`, for requests outside the vocabulary such as GPU temperature

  Invalid output gets one retry; a second failure ends the turn with "The AI gave an answer AegisWin could not use."
- **Limits:**
  - at most 3 question rounds, after which the AI must propose or say the request is unsupported
  - at most 3 questions per round, ≤200 characters each
  - up to 4 answer choices per question, plus free text
- **User controls:** the owner can skip any question, or press **Propose now** at any time.
- **Allowed topics:** the monitor only. Which app, the symptom, when it happens, how long it lasts, how severe it is.
- **Code filter.** It is a backstop; the main protection is that the AI cannot act. Questions are dropped, with a visible note, if they contain:
  - URLs
  - requests for passwords, PINs, keys, tokens, or other secrets
  - code or command text
  - requests to run, install, download, or change anything
- **Context.** The AI receives the rule vocabulary, the enabled components, the user's text, and the answers. **Never raw event-log messages**: process names and event text can be controlled by an attacker.
- **One consented lookup.** The AI may request the list of running process names. The owner sees "Let the AI see running app names?" and nothing is sent without that click.
- **Where data goes.** Each round shows whether answers go to an on-LAN or Off-LAN LLM. The existing trust gate and scrubbing ([SECURITY_MODEL §6](../SECURITY_MODEL.md)) apply.
- **Storage.** The conversation lives in Rust memory only, within the LLM service's prompt-size cap, and is cleared on lock.

## 4. App lifecycle: tray and locked-but-monitoring

| State | Vault key | MCP server, tickets, LLM | Sampler + history writer | Can view data |
| :--- | :--- | :--- | :--- | :--- |
| Locked, idle | no | off | off | no |
| **Locked, monitoring** | **no** | off | **on**, from the active rules in `runtime.json` | no |
| Unlocked | yes | as configured | on | yes |

- **Tray icon.** Its state shows: unlocked, locked + monitoring, or idle. Menu: Open, Lock, Pause monitoring, Quit. Uses Tauri's `tray-icon` feature.
- **Closing the window** hides it to the tray when at least one monitor is active; otherwise it quits as today. The first hide shows a one-time notice.
- **Lock** with active monitors goes to *locked, monitoring*: the key is dropped, MCP stops, the firewall rule is removed, and tickets are cleared. **Quit** writes a clean-stop record and exits.
- **Pause monitoring** from the tray needs no PIN, because agents cannot reach the tray. It writes a `paused` record, so the gap is visible and attributed.
- **Single instance per install.** A second launch focuses the running one. This matters for the Startup shortcut and the tray.
- **Plugin trait.** It gains a monitoring-only lifecycle hook, because `on_lock` today means "stop everything".
- **Notifications in v1** are the tray icon and the in-app list. Windows toasts for an unpackaged app usually need an AUMID registry entry, so they are deferred.

### Idle auto-lock

- **Timeout:** default 15 minutes. Options: 5, 15, 30, or 60 minutes. There is no "off".
- **What counts as idle:** no interaction with the AegisWin window or the approval portal. **MCP agent activity does not keep the vault unlocked.**
- **Running tools:** when auto-lock is due, no new queued item or plan step starts. Auto-lock waits for the running step only, then cancels everything queued ([ADR 0003 §5.1](0003-action-plans.md)). Pending, undecided tickets are cleared by the lock, as today.

## 5. Encrypted monitor history on disk

**Where it lives: a shared `aegis-core` history service.** The writer and reader are not part of `usage-monitor`; the plan audit trail in [ADR 0003 §7](0003-action-plans.md) uses them too.
- **Streams**: the service holds named streams, each with **its own keypair and retention**: `usage-monitor` (this ADR) and `approvals` (ADR 0003). Purging or re-keying one stream never touches another.
- **Handles**: the engine gives each plugin a `HistoryHandle` bound to its plugin id, the same pattern as `LlmHandle`. A plugin can only write and read its own stream.
- **Locked writing**: only streams that write while locked (today only `usage-monitor`) keep their public key on disk, in `runtime.json`. Other streams take their public key from the vault while unlocked.

**Scheme: write-only public-key encryption.**
- **Keypair.** A monitor X25519 keypair. The **private key lives only inside the vault** (behind the PIN, zeroized on lock). The **public key** is in `runtime.json` and in the vault.
- **Construction.** HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)), base mode, X25519 + HKDF-SHA256 + AES-256-GCM, from an audited crate. No hand-rolled cryptography.
- **What this gives.** The locked writer can encrypt but never decrypt, so nothing on disk is readable without the PIN, including by AegisWin itself while locked.

Rejected alternatives:
- **DPAPI-protected monitor key**: any process running as the user could decrypt it, which bypasses the PIN.
- **Keeping the vault key in memory while monitoring**: that means never truly locking.

### Files

| File | Contents | Protection |
| :--- | :--- | :--- |
| `./data/monitor/runtime.json` | Format version, `keyId`, the `usage-monitor` stream's public key, active rules, enabled components, paused flag, retention settings | Plaintext, written atomically like the vault. Reveals *what* is monitored, not what was collected. |
| `./data/history/<stream>/seg-YYYYMMDD-NNN.bin` | Header (magic, version, `keyId`, HPKE encapsulated key), then length-prefixed sealed frames. Additional data = header hash + frame index. | Encrypted; one HPKE context per file, wiped from memory when the next file starts |

- **Records**:
  - `session_start`: launch kind (manual or autostart), boot time, app version
  - `heartbeat`: every 60 seconds
  - `session_stop`: reason quit, shutdown, or monitoring stopped
  - `paused` and `resumed`
  - `spike`, `crash`, `foreground`, and `monitor_hit`
  - Raw 5-second samples are not written.
- **Crash safety**: append-only; batches are forced to disk (`sync_data`) every **30 seconds** and on stop. After a power cut, reading stops at the last frame that authenticates and a torn final frame is dropped. Worst case loses about 30 seconds. A bad frame in the middle of an older file marks that file corrupt in the history view; reading continues with the next file.
- **Rotation**: a new file daily or at 4 MB.
- **Retention**: default **14 days or 64 MB**, whichever comes first, oldest files first. Adjustable within 1–90 days and 8–512 MB. Enforced at startup and on rotation; deleting needs no key, so this works while locked.
- **Purge** (PIN): `purge_telemetry_history` deletes every `usage-monitor` file and **replaces that stream's keypair**, so a deleted file recovered from flash storage is useless. The `approvals` stream is untouched.
- **Tamper detection**: on every unlock, the public key, `keyId`, and rules in `runtime.json` are compared with the vault's copies. On a mismatch the app warns, stops resuming from the file, and rewrites it from the vault after the owner reviews.
- **Threat model.** Malware that can write to `./data` as the user can redirect future records or add observe-only rules. Preventing that is out of scope, since it already controls the session; *detection* at the next unlock is in scope. Someone who has only the files (e.g. a lost USB stick) sees the active rules, file dates, and sizes, but no collected data.

## 6. Restart and resume

- **Always on (A):** every launch reads `runtime.json`. If monitors were active and not paused, it resumes them in *locked, monitoring*. After unlock, a banner says "Monitors were stopped from X to Y; the gap is recorded."
- **Opt-in Startup shortcut (B)**, a toggle in Settings:
  - **File**: `AegisWin Monitor.lnk` in the user's Startup folder (`FOLDERID_Startup`), created through the Shell `IShellLink` COM interface (no shell process). Target: the current exe's absolute path, arguments `--background`, working directory the exe's folder.
  - **Enabling needs the PIN**; disabling does not, matching how revoking LLM trust works. The setting is UI-only and is never exposed over MCP.
  - **Removal**: the shortcut is deleted when the toggle is turned off or the last monitor is deleted.
  - **Wrong or dead target**: on each launch, if the shortcut exists but points to a different exe (the stick moved, a new drive letter, another copy), Settings shows **Update** or **Remove**. A shortcut left behind by an install that has since been deleted cannot be detected by that install, so the setting's help text says how to remove it via Task Manager's Startup tab.
  - **If a shortcut from another copy exists**, enabling asks before replacing it.
  - **`--background` launch**: single-instance check, no window, tray only, *locked, monitoring*.
- **Rejected**: Task Scheduler and the HKCU Run key. Both use the registry and are well-known malware persistence techniques that antivirus watches.

## 7. Gap recording

Gaps are computed **when history is read** (unlocked), so no extra plaintext is needed:

| Pattern in the records | Shown as |
| :--- | :--- |
| Heartbeats more than 2 minutes apart, same session | Sleep or hibernate (confirmed by Kernel-Power 42 and 107 when present) |
| `session_stop` followed by a new `session_start` | Clean shutdown or quit, plus who started the restart (System 1074) |
| No `session_stop`, then a new `session_start` | Crash or power loss (System 41 Kernel-Power, 6008) |
| `paused` … `resumed` | Paused by the user |

Timeline example: "Not monitoring 23:14–23:52 (unexpected shutdown, Kernel-Power 41)." Values are never filled in across a gap. Unexpected shutdowns also appear as diagnostic clues in their own right.

**Known risk**: Tauri may not surface `WM_QUERYENDSESSION`/`WM_ENDSESSION`. If so, a hidden message window (through the `windows` crate) writes the `session_stop` record. Without it, a normal shutdown looks unclean, though System 1074 still shows it was intended.

## 8. Documents to amend (during the phase that implements each part)

| Document | Change |
| :--- | :--- |
| `adr/0001-rust-core.md` | Rejected-option row 13: note it is superseded by this ADR (the objection was *plaintext* on disk) |
| `GUIDING_PRINCIPLES.md` | §2: telemetry is persisted encrypted under `./data/history/`; the opt-in Startup shortcut is the one file outside `./data/` |
| `SECURITY_MODEL.md` | New sections: monitor key and HPKE files, *locked, monitoring* state, idle auto-lock, Startup shortcut, AI output treated as untrusted input, question filter. §1: add LLM output and a local attacker with `./data` write access as threat boundaries. §2.1: new PIN-taking commands (`activate_monitor`, enabling the shortcut) |
| `ARCHITECTURE.md` | Tray and the shared history service in the system diagram, the app-state table, a propose → approve sequence diagram, `./data/monitor/` and `./data/history/` in the layout |
| `PLUGIN_SPEC.md` | Plugin trait lifecycle hook for monitoring while locked; `HistoryHandle` (own stream only); monitor tools never set `planEligible` ([ADR 0003](0003-action-plans.md)). §5 plugin data in the vault: done in Phase 1b |
| `plugins/usage-monitor/README.md`, `manifest.json`, `src/lib.rs` header | New tools, persistence and retention, new `purge_telemetry_history` description, `configure_watch_window` gate |
| `README.md` | Feature list: AI monitor creator, tray, background monitoring, Startup shortcut |
| `AUDIT_LEDGER.md` | One row per phase |
| `tests/02-documentation-audit.test.mjs` | This ADR is in `REQUIRED_DOCS` (done when accepted) |

## 9. Implementation plan

Each phase is its own PR with tests, ledger row, and doc updates. Phases 0–2 ship value without any lifecycle or disk changes.

| Phase | Scope | Depends on |
| :--- | :--- | :--- |
| **0. Gate fix** | `configure_watch_window` → `pin_required`; tests; docs | — |
| **1. Rules without AI** | Rule schema and validation, shared evaluator in the sampler, code-generated descriptions, privacy flags, `propose`/`activate`/`list`/`pause`/`delete` tools, rules stored in the vault, "Default" rule migration, approval page shows descriptions, manual rule editor in the UI, replay against in-memory data | 0 |
| **2. AI creator** | Chat commands, reply schema, question loop and limits, question filter, reasoning panel and consistency check, process-list consent, LAN/Off-LAN labelling, tests against a loopback LLM mock | 1 |
| **3. Lifecycle** | Tray, close-to-tray, *locked, monitoring* state and plugin hook, idle auto-lock, single instance, shutdown message handling | 1 |
| **4. Encrypted history** | Shared `aegis-core` history service with per-stream keypairs and `HistoryHandle`, the `usage-monitor` stream, `runtime.json`, segment writer and reader, 30-second flush, retention, purge with key replacement, tamper check, history view, gap detection with System log classification | 3 |
| **5. Resume and Startup shortcut** | Resume on every launch, `--background`, Settings toggle (PIN to enable), shortcut update and removal, replace prompt | 4 |

## 10. Open questions

Decided on 2026-11-07 by taking the written recommendation, except where marked open.

1. **Hide to tray**: lock immediately, or rely on the 15-minute auto-lock? **Decided: rely on auto-lock**, so an owner who hides the window during an agent session is not interrupted.
2. **`read_monitor_history` gate over MCP**: `auto` like `capture_diagnostic_snapshot`, or `pin_required` given up to 90 days of foreground history? **Decided: `pin_required`.**
3. **Event conditions**: poll every 30 seconds with a bookmark through `aegis_core::os::eventlog`, or push through `EvtSubscribe`? **Decided: poll** (reuses existing code, simpler to test).
4. **HPKE crate**: confirm the chosen crate meets the "audited, no hand-rolled cryptography" bar before Phase 4, or compose `x25519-dalek` + `hkdf` + `aes-gcm` exactly per RFC 9180. **Open: a crypto choice the owner decides before Phase 4 starts.**
5. **Caps**: confirm 20 monitors and 8 conditions per monitor. **Decided: 20 monitors, 8 conditions per monitor.**
6. **Windows toast notifications**: stay deferred until there is a way to show them without a registry entry? **Decided: deferred**; v1 uses the tray icon and the in-app list only.
7. **Shutdown messages**: confirm in Phase 3 whether Tauri delivers them or a hidden message window is needed. **Decided: investigated at the start of Phase 3**; the result is recorded here.

## 11. Set aside and dropped

- **PIN grace window ("skip the PIN for 5 minutes"): set aside.**
  - **The blanket version is rejected.** The browser approval page needs no login besides the PIN, and the agent already holds its link, so skipping the PIN would let any agent approve its own requests.
  - **The in-app-only variant is not built.** It would never apply to the browser page or MCP, would still need a click per request, and would exclude admin repairs, purge, monitor management, and the Startup shortcut. After those exclusions it covered almost no tools.
  - It can be revisited later under those constraints.
- **Batch approve (one PIN for several separate pending tickets): dropped.** Superseded by [ADR 0003](0003-action-plans.md) action plans, which add a fixed order, stop-on-failure, and one reviewed, hash-bound list.
