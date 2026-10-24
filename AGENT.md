# AGENT.md — Autonomous Agent Engineering Contract (AegisWin)

> **Purpose**: Authoritative operational guide for any AI coding agent contributing to **AegisWin**, the portable Windows system utility, LLM diagnostic assistant, and human-gated MCP server.

## 1. Guiding Engineering Principles
1. **Skeptical Efficiency First**: Before writing any new function, dependency, or abstraction, ask: *"Does a native OS primitive, Win32 API, Rust standard library module, or existing core helper already solve this more efficiently?"* Never spawn heavy external shells when a direct API or batch query suffices.
2. **True Single-Binary Portability**: Everything compiles into a single portable `.exe` (`Tauri v2` + `Vite`) that stores runtime state strictly inside `./data/` next to the executable. Never write to the Windows Registry or `%APPDATA%`, and never drop secondary `.exe`/`.dll` payloads that trigger Windows Defender or Bitdefender heuristics.
3. **Standard User by Default (`asInvoker`)**: The application runs under standard user privileges by default. Users may optionally configure "Run as administrator" via Windows Properties, or approve per-tool UAC self-elevation (`aegis-win.exe --elevate-tool <plugin>:<tool>`) when an administrative repair tool (`sfc`, `netsh winsock reset`) is invoked.
4. **Zero-Knowledge PIN Isolation**: The user's startup PIN is used exclusively in local memory (via Argon2id/Scrypt KDF) to unlock `./data/vault.enc` and verify human approval on the local `/approve/<ticket-id>` web portal. **The PIN must NEVER be logged, returned over MCP, or included in any LLM prompt.**
5. **Per-Tool Human-in-the-Loop Gating**: Every plugin contains multiple discrete tools. Each tool defines a customizable gate policy (`auto` vs `pin_required`). When a gated tool is called via MCP, the server returns an approval URL (`http://<host>:<port>/approve/<ticket-id>`) where the user reviews the action, enters comments, accepts/declines, and inputs their PIN.
6. **Per-Plugin Off-LAN LLM Trust Boundary**: Local LLM endpoints (`127.0.0.1`, `localhost`, RFC1918 private LAN IPs) are trusted by default. The first time any plugin attempts to send diagnostic data to an Off-LAN OpenAI-compatible endpoint, execution halts until the user explicitly grants external LLM trust to that plugin.

## 2. Atomic Commit & CI Pipeline Mandate
- **Commit Prefix Convention**: Every git commit message MUST begin with a parenthesized type tag:
  - `(feat) ...` — New core capability or plugin feature
  - `(fix) ...` — Bug fix or edge-case mitigation
  - `(doc) ...` — Architectural or agent documentation update
  - `(chore) ...` — Build, CI, or tooling configuration
  - `(test) ...` — Test suite expansion
  - `(refactor) ...` — Efficiency improvement with zero behavior change
- **Mandatory Test Gate**: Every commit MUST add or update automated tests in `tests/` or `plugins/<id>/tests/` and pass `npm run ci` (`node scripts/ci-runner.mjs`) via the `.githooks/pre-commit` hook.
- **Mandatory Documentation Audit**: Every commit MUST audit and update `documentation/AUDIT_LEDGER.md` (and any impacted spec in `documentation/`) to keep agent knowledge 100% synchronized with the codebase.

## 3. Repository Map
- `AGENT.md` & `CLAUDE.md` — Agent operating instructions and workflow shortcuts.
- `documentation/` — Critical architectural specs, diagrams, security invariants, plugin contracts, and the live commit audit ledger.
- `src/core/` — Portable encrypted vault, zero-knowledge PIN verifier, Central LLM Service (with LAN/Off-LAN detector), Plugin Registry, and MCP HTTP Server + Approval Web Portal.
- `src/ui/` — High-contrast dark-mode UI (`WCAG AAA`), dynamic UI scaling engine (`80%`–`150%`), First-Run Component Wizard, Plugin Views, and Live MCP Approval Queue.
- `plugins/` — Self-contained modular plugins (`event-logs`, `windows-health`, `usage-monitor`), each with its own `manifest.json`, implementation, `tests/`, and `README.md`.
- `src-tauri/` — Tauri v2 Rust backend, `Cargo.toml`, `tauri.conf.json`, and Windows `app.manifest` (`asInvoker`).
