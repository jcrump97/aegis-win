# AGENTS.md — Autonomous Agent Engineering Contract (AegisWin)

> **Purpose**: Authoritative operational guide for any AI coding agent contributing to **AegisWin**, the portable Windows system utility, LLM diagnostic assistant, and human-gated MCP server.

## 1. Guiding Engineering Principles
1. **Skeptical Efficiency First**: Before writing any new function, dependency, or abstraction, ask: *"Does a native OS primitive, Win32 API, Rust standard library module, or existing core helper already solve this more efficiently?"* Never spawn heavy external shells when a direct API or batch query suffices.
2. **True Single-Binary Portability**: Everything compiles into a single portable `.exe` (`Tauri v2` + `Vite`) that stores runtime state strictly inside `./data/` next to the executable. Never write to the Windows Registry or `%APPDATA%`, and never drop secondary `.exe`/`.dll` payloads that trigger Windows Defender or Bitdefender heuristics.
3. **Standard User by Default (`asInvoker`)**: The application runs under standard user privileges by default. A tool that needs administrator rights (`sfc`, `netsh winsock reset`) reports `REQUIRES_ADMIN`, and the UI offers **Restart as administrator** (one UAC prompt, then the vault is unlocked again). There is no elevated helper process (`documentation/SECURITY_MODEL.md` §5, ADR 0001 Amendment 1).
4. **Zero-Knowledge PIN Isolation**: The user's startup PIN is used exclusively in local memory (via the Argon2id KDF) to unlock `./data/vault.enc.json` and to approve gated actions in the app. No web page ever takes the PIN: the opt-in device page (`/approve/<ticket-id>`) takes a one-time code the app shows (ADR 0004). **The PIN must NEVER be logged, returned over MCP, or included in any LLM prompt.**
5. **Per-Tool Human-in-the-Loop Gating**: Every plugin contains multiple discrete tools. Each tool defines a customizable gate policy (`auto` vs `pin_required`). When a gated tool is called via MCP, the server returns `pending_approval` with a `ticketId` and no link. The owner reviews the action on the app's Approvals tab, adds a comment, approves or declines, and enters the PIN; the agent polls `aegis__check_ticket`. Several repairs under one approval go through `aegis__propose_plan` (ADR 0003).
6. **Per-Plugin Off-LAN LLM Trust Boundary**: Local LLM endpoints (`127.0.0.1`, `localhost`, RFC1918 private LAN IPs) are trusted by default. The first time any plugin attempts to send diagnostic data to an Off-LAN OpenAI-compatible endpoint, execution halts until the user explicitly grants external LLM trust to that plugin.
7. **Code Finds, the AI Explains**: Diagnose findings and their next steps are written by code. An LLM may rank and explain them and pick only among the fixes code linked to a finding; code checks its reply, and the owner approves with the PIN (ADR 0005).

## 2. Atomic Commit & CI Pipeline Mandate
- **Commit Prefix Convention**: Every git commit message MUST begin with a parenthesized type tag:
  - `(feat) ...` — New core capability or plugin feature
  - `(fix) ...` — Bug fix or edge-case mitigation
  - `(doc) ...` — Architectural or agent documentation update
  - `(chore) ...` — Build, CI, or tooling configuration
  - `(test) ...` — Test suite expansion
  - `(refactor) ...` — Efficiency improvement with zero behavior change
  - `(security) ...` — Hardening or a fix to a security invariant
  - `(perf) ...` — Measured performance improvement
- **No AI Attribution**: Commit messages and PR descriptions MUST NOT carry AI-tool attribution: no `Co-Authored-By: Claude …` (or other AI) trailers and no "Generated with …" footers. Credit for AI assistance belongs in the README, not in every commit. `.githooks/commit-msg` rejects these trailers.
- **Signed Commits**: Commits are SSH-signed with the maintainer's key (`commit.gpgsign=true`). Never bypass signing or hooks (`--no-verify`, `--no-gpg-sign`).
- **Mandatory Test Gate**: Every commit MUST add or update automated tests (`tests/`, `plugins/<id>/tests/`, or a crate's Rust tests) and pass `npm run ci` (`node scripts/ci-runner.mjs`) via the `.githooks/pre-commit` hook. `npm run ci` also runs `cargo test --workspace`.
- **Mandatory Documentation Audit**: Every commit MUST audit and update `documentation/AUDIT_LEDGER.md` (and any impacted spec in `documentation/`) to keep agent knowledge 100% synchronized with the codebase.

## 3. Review & Findings
- **Fresh-Session Review**: Every pull request is reviewed before merge by a session (or person) that did not write it, for example `/review-pr <number>` (the repo's skill, `.claude/skills/review-pr/`) in a new Claude Code session. The session that wrote the code does not count as its reviewer.
- **File Every Finding**: Anything found and not fixed in the same commit (by a review, an agent, or while working on something else) is filed as a GitHub issue before the session ends, and the issue numbers are listed in the final message. An issue says whether it was verified (`**Status:**`), where it is (`**Where:**`, a permalink to the file and line), what goes wrong, and a `**Fix direction:**`. Labels: `bug`, `enhancement`, or `documentation` (`.github/ISSUE_TEMPLATE/finding.md`). Chat is not a record. The one exception is a security problem someone could exploit: it is not filed in public; tell the maintainer privately.
- **Caller Audit**: If a change adds a side effect to an existing function (it stores, records, sends, or clears something), list every caller and confirm each one wants it. Shared engine functions are reached from the app, MCP agents, and background tasks.
- **Two-Actor Test**: A feature that both the app and an MCP agent can reach gets at least one test where both act in sequence on the same engine.
- **Fixes Start with a Failing Test**: A `(fix)` commit adds a test that fails without the fix. A behaviour promised in `documentation/` has a test that would fail if the promise broke.
- **What Enforces This**: CI runs `scripts/check-commit-messages.mjs` over a pull request's commits and description (type tag, no AI attribution), because git hooks are off in a fresh clone. `.github/pull_request_template.md` carries the checklist. For Claude Code sessions, `.claude/settings.json` wires three hooks from `.claude/hooks/`: `guard-git.mjs` refuses git commands that skip hooks or signing, `session-issues.mjs` lists the maintainers' open issues at the start of a session, and `stop-ledger.mjs` sends a session back once when code changed without a ledger row.

## 4. Repository Map
- `AGENTS.md` — The rules for every AI coding tool, under the name those tools look for. `CLAUDE.md` loads it with an `@AGENTS.md` line and adds only what is specific to Claude Code, so no rule is written twice.
- `documentation/` — Critical architectural specs, diagrams, security invariants, plugin contracts, decision records (`adr/`), and the live commit audit ledger.
- `crates/aegis-core/` — Rust core ([ADR 0001](documentation/adr/0001-rust-core.md)): the engine (single enforcement point for install state, input validation, and the dry-run → admin → PIN gate), portable encrypted vault with the global PIN guard, approval tickets, Central LLM Service (with LAN/Off-LAN detector), plugin registry, OS layer, and MCP HTTP server + approval web portal.
- `src/ui/` — High-contrast dark-mode UI (`WCAG AAA`), dynamic UI scaling engine (`80%`–`150%`), First-Run Component Wizard, Plugin Views, and Live MCP Approval Queue. Talks to the core only through Tauri `invoke`.
- `plugins/` — Self-contained modular plugins (`event-logs`, `windows-health`, `usage-monitor`). Each is a Rust crate with its own `manifest.json`, `src/lib.rs`, `tests/`, and `README.md` (see `documentation/PLUGIN_SPEC.md`).
- `src-tauri/` — Tauri v2 app binary (thin command layer and wiring), `build.rs`, `tauri.conf.json`, and Windows `app.manifest` (`asInvoker`).
- `Start AegisWin.exe` & `launcher/` — One-click entry point for users: checks for WebView2, C++ Build Tools, Node.js 20+, and Rust, installs what's missing via winget after asking, runs `npm ci`, enables git hooks, rebuilds the app only when sources changed (via `scripts/package.mjs`), and starts `release/AegisWin/AegisWin.exe`. It sits outside the Cargo workspace (`exclude` in the root `Cargo.toml`) so it keeps its own lockfile and size-optimized profile. Standard-library-only Rust, run by absolute path with argv (no shell). The exe is committed so it works before any toolchain exists; after changing `launcher/`, run `npm run launcher:build` and commit the new exe.
