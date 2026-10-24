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
