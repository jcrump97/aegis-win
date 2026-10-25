# ADR 0001: Move the AegisWin core from Node.js into the Rust/Tauri backend

- **Status**: Accepted
- **Date**: 2026-10-24
- **Supersedes**: the Node.js `src/core/` + `plugins/*/index.mjs` prototype (ledger commits 3–15)

## Context

The first 15 commits produced a well-tested **prototype** of the AegisWin security design, written as Node.js ES modules:

| Area | Prototype state |
| :--- | :--- |
| Vault & PIN (`src/core/vault.mjs`) | Real logic on `node:crypto` (scrypt, AES-256-GCM, `timingSafeEqual`) |
| MCP server & approval portal (`src/core/mcp-server.mjs`) | Real logic on `node:http` (tickets, CSRF nonce, 3-strike lockout, Host validation) |
| LLM service (`src/core/llm-service.mjs`) | Real logic (LAN classification, per-plugin Off-LAN trust gate, PII scrubber) |
| Plugins (`plugins/*/index.mjs`) | **Simulated**: they build command strings but return canned sample output; nothing touches Windows |
| Tauri backend (`src-tauri/src/main.rs`) | Two placeholder commands |
| UI (`index.html`) | A standalone mockup with its own in-page state, a hardcoded demo PIN, and Tailwind loaded from a CDN |

A Tauri v2 app embeds a **WebView2 webview and a Rust process. It has no Node.js runtime.** None of `src/core/` can run inside the shipped executable: the webview cannot open an HTTP listener, spawn processes, or use `node:crypto`/`node:fs`. The 19 Node tests pass only because they run under a standalone Node.

## Options considered

1. **Port the core into Rust inside the Tauri backend.**
2. **Ship Node.js as a Tauri sidecar** (bundled `node.exe` or a Node single-executable app) and keep the JS core.
3. **Run the core inside the webview.**

## Decision

**Option 1.** All privileged, security-critical, and OS-facing logic lives in Rust inside the single Tauri executable. The webview is a presentation layer that reaches the core only through Tauri `invoke` commands.

### Why not the alternatives

- **Sidecar (2)** breaks [Guiding Principle 2](../GUIDING_PRINCIPLES.md): it adds a second ~80 MB executable next to the app. Packaged Node binaries are a common antivirus false-positive pattern, which is the exact risk AegisWin is designed to avoid. It also adds an IPC hop between the UI and the core.
- **Webview core (3)** is not workable: a webview cannot host the MCP listener or run Windows tools, so that code would end up in Rust anyway. It would also hold the PIN-derived key in the same JS context as the UI, against the PIN Non-Exposure Invariant.

### Consequences

- **Portability**: one `asInvoker` executable, no runtime to ship, nothing written outside `./data/`.
- **Security**: the PIN, its derived key, and decrypted secrets live only in Rust memory and are zeroized on lock or drop. The webview sends the PIN to exactly one command (`unlock_vault`) and never stores it.
- **Real Windows integration**: plugins call documented Win32 APIs through Microsoft's `windows` crate. Where a system binary is unavoidable (e.g. `sfc.exe`), it is launched by absolute path with an argument vector, never through a shell.
- **Cost**: about 1,300 lines of prototype logic are re-implemented in Rust. The plugins have to be implemented for real under any option, so most of this work was unavoidable.
- **Tooling**: contributors need the Rust MSVC toolchain. CI already installs it on `windows-latest`.

## Target layout

```
aegis-win/
├── Cargo.toml                 # [workspace] members = ["src-tauri", "crates/*", "plugins/*"]
├── crates/
│   └── aegis-core/            # vault, PIN KDF, plugin trait + registry + gate policy,
│                              # LLM service + Off-LAN sanitizer, MCP server + approval portal,
│                              # elevation job bridge
├── plugins/<plugin-id>/       # one crate per plugin (see PLUGIN_SPEC.md)
├── src-tauri/                 # thin app binary: Tauri commands, wiring, `--elevate-tool` mode
└── src/ui/                    # TypeScript UI; talks to Rust only via `invoke`
```

Library choices (all pure Rust; no OpenSSL or C dependencies):

| Concern | Crate |
| :--- | :--- |
| PIN KDF | `argon2` (Argon2id) |
| Vault encryption | `aes-gcm` (AES-256-GCM, 12-byte nonce, 16-byte tag) |
| Secret hygiene | `zeroize`, `subtle` (constant-time compare) |
| CSPRNG | `rand` with `OsRng` |
| MCP HTTP server & portal | `axum` on the Tauri-managed `tokio` runtime |
| LLM client | `reqwest` with `rustls` |
| Windows APIs | `windows` (Microsoft) |

Starting with one `aegis-core` crate is deliberate (Guiding Principle 1). Split it only when a concrete need shows up.

## Migration plan

The JS prototype stays in the repo as an **executable specification** until each piece is ported. Each step is its own PR:

1. **Vault & PIN** → `crates/aegis-core::vault`, plus a real startup PIN screen. Removes the demo PIN from the UI.
2. **`event-logs` plugin** (read-only, no admin, `auto` gate): first end-to-end path from UI to Rust to Win32 (`EvtQuery`).
3. **Plugin registry & gate policy engine.**
4. **MCP server & approval portal** (`axum`), with Host validation, CSRF nonce, 3-strike lockout, and bind-aware firewall handling.
5. **LLM service**, Off-LAN trust gate, and PII/host sanitizer.
6. **`windows-health` plugin** and UAC self-elevation (`ShellExecuteExW` `runas` on the app's own exe) with the encrypted job bridge.
7. **`usage-monitor` plugin.**
8. **UI rebuild**: TypeScript on `invoke`, with Tailwind compiled at build time (no CDN). Delete the `index.html` mockup.

**Parity rule for every step:**
- Port the matching JS tests to Rust tests that check the same behavior.
- Delete the JS module and its JS tests in the same PR.
- Record the change in `AUDIT_LEDGER.md`.

The prototype's vault format is **not** carried over; there are no real users or vaults yet.

## Open questions (decide in the step that needs them)

- How the elevated process gets the job-bridge key without asking for the PIN again (step 6).
- React or plain TypeScript for the UI (step 8). `react` is declared in `package.json` but unused.

---

## Amendment 1: plan review before implementation (2026-10-24)

I re-read the whole prototype (core, plugins, UI, tests) before starting the port and checked the plan against the vision. These corrections take precedence over the sections above where they conflict.

### Definition of "basic functioning app"

A Windows user can, from one portable `aegis-win.exe`:

1. Create a PIN on first launch and unlock with it on later launches. Wrong PINs are rate-limited; no PIN is preset.
2. Pick which plugins and components to enable in the first-run wizard.
3. Read **real** Application/System event log entries, filter them by Event ID, and ask an LLM to explain them.
4. Run the repair tools for real (`ipconfig /flushdns`, `/release` + `/renew`, `sfc /scannow`, `netsh winsock reset`). Each one confirms with the PIN, previews its impact with `dryRun`, and gives clear guidance when it needs admin rights.
5. See live CPU/RAM usage by process, recorded spikes, and crash events correlated within a watch window.
6. Start an MCP server that real MCP clients (Claude Code, Claude Desktop, etc.) can connect to. `auto` tools return results directly. `pin_required` tools return an approval link, and the action runs only after the user approves it with the PIN, in the browser or in the app.
7. Point the LLM service at Ollama or LM Studio, or at an external endpoint, which requires per-plugin trust and scrubs PII before sending.
8. Nothing is written outside `./data/`, and nothing is loaded from the internet at runtime.

### Assumptions challenged → corrections

| # | Assumption in the plan or prototype | Problem | Correction |
| :--- | :--- | :--- | :--- |
| 1 | "Nothing is written outside `./data/`" holds automatically with Tauri | WebView2 stores its profile in `%LOCALAPPDATA%\<identifier>\EBWebView` by default | Create the window in code with its WebView2 data directory set to `./data/webview` |
| 2 | Tool names like `event-logs:query_logs` | Claude clients (and the Claude API) only accept tool names matching `^[a-zA-Z0-9_-]{1,64}$`; the colon breaks them | MCP tool names are `<plugin>__<tool>` (e.g. `event-logs__query_logs`) and `aegis__check_ticket`; internal IDs keep `plugin:tool` |
| 3 | The prototype's `/mcp` is MCP | No `initialize` handshake, no `ping`, and results aren't MCP `content` blocks, so real clients can't connect | Implement MCP Streamable HTTP (JSON responses): `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`, with `content` + `structuredContent` + `isError`; validate `Origin` as well as `Host` |
| 4 | 3-strike lockout per ticket stops brute force | An agent can create unlimited tickets and get 3 guesses on each. CSRF doesn't help either, because the agent can fetch the page and its token itself | Add a **global** PIN guard shared by unlock and all approvals: after 5 consecutive failures, exponential cooldown (30 s doubling, capped at 1 h), reset on success. Keep the per-ticket 3-strike lockout too |
| 5 | The approval page is safe | The prototype puts agent-supplied `args` into the HTML without escaping, so an agent could inject script into the page where the user types their PIN. CSRF is also skipped when the token is simply omitted | HTML-escape everything, require CSRF, and send a strict CSP (`default-src 'none'`), `X-Frame-Options: DENY`, `no-store`, `no-referrer` |
| 6 | A 4-character PIN protects the vault | Offline, the vault's security depends only on how hard the PIN is to guess | Minimum 6 characters, any characters allowed, with a strength hint in the UI. **Open for the user:** whether to also bind the vault to the Windows account (DPAPI), which is stronger at rest but breaks moving the app to another PC |
| 7 | IPv6 private-range detection by string prefix | `host.startsWith('fc')` classifies `fcbarcelona.com` as LAN | Only check private ranges on addresses that actually parse as IP addresses (`std::net::IpAddr`) |
| 8 | The webview never receives the MCP bearer token | The user has to copy it into their MCP client | The token is sent to the webview only through an explicit `reveal_mcp_token(pin)` action; API keys are write-only from the UI |
| 9 | Gate policies can be changed freely | Downgrading `pin_required` → `auto` removes the human check | Downgrading requires the PIN; upgrading doesn't |
| 10 | Elevation via the encrypted job bridge | The elevated process has no way to get the vault key without the PIN (the open question above) | **Deferred.** Basic app: admin tools say they need admin and offer "Restart AegisWin as administrator" (`ShellExecuteExW` `runas` on its own exe, then exit). This is already allowed by Guiding Principle 3. The job bridge comes back as its own design decision |
| 11 | Async execution only when `asyncExecution: true` | Long tools (`sfc`) block the approval HTTP request | Approved tickets always run in the background (`running` → `approved`/`execution_failed`); agents poll `aegis__check_ticket` |
| 12 | Tool commands are strings like `ipconfig /release "<filter>"` | String-built commands invite injection | Absolute `System32` paths with argument vectors and `CREATE_NO_WINDOW`; validate input against `inputSchema` plus per-tool allow-lists. Decode `sfc` output as UTF-16 |
| 13 | Usage telemetry persisted to `./data/telemetry.json` | Foreground-app history is privacy-sensitive and would sit on disk in plaintext | Keep telemetry in memory only (capped ring buffer); record process names only, never window titles; `purge_telemetry_history` clears it |
| 14 | UI: React + Tailwind (CDN) | React is declared but unused; the CDN breaks offline use and is an injection risk | Plain TypeScript modules + hand-written CSS using the existing design tokens. Drop `react`/`react-dom`. Set a strict CSP in `tauri.conf.json` |
| 15 | Each plugin is fully separate | `usage-monitor`'s crash correlator needs the same event-log reader as `event-logs` | Shared OS primitives (event-log query, `run_system_binary`, `is_elevated`) live in `aegis-core::os`; plugins stay separate crates |
| 16 | One PR per port step, deleting JS as each lands | The JS modules all import `vault.mjs`, so they can't be deleted one by one | One feature branch with one atomic, signed commit per step (each passes CI and updates the ledger), opened as a single PR. The JS prototype and its tests are deleted in the final commit, once Rust tests cover the behavior. The elevation-bridge spec stays in git history for the deferred work |

### Revised implementation order (commits on `feat/rust-core`)

1. Cargo workspace + `aegis-core::vault` (Argon2id, AES-256-GCM, PIN guard, atomic saves) + `cargo test` in `npm run ci`.
2. `aegis-core::os` + plugin registry, gate engine, and input validation.
3. `aegis-core::llm`: LAN classification, Off-LAN trust gate, PII/host scrubbing, OpenAI-compatible client.
4. Plugins: `event-logs` (Win32 `EvtQuery`), `windows-health`, `usage-monitor`.
5. `aegis-core::mcp`: MCP server, tickets, approval portal, bind-aware firewall handling.
6. Tauri app: commands, `./data` paths, WebView2 data directory, CSP, restart-as-admin.
7. UI rebuild on `invoke`.
8. Remove the JS prototype and its tests, and bring the docs in line with the shipped design.

**Status (2026-10-24)**: steps 1–8 are done on `feat/rust-core`. Still open: DPAPI binding (#6), the elevation job bridge (#10), and a license.
