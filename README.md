# AegisWin

**A portable Windows diagnostic and repair utility with a human-gated MCP server.**

AegisWin is a single `.exe` you can run from a USB stick or a downloads folder. It lets you, or an AI agent you connect over [MCP](https://modelcontextprotocol.io), read event logs, watch resource usage, and run common Windows repairs. Every state-changing action an agent asks for waits until you approve it with your PIN.

> **Status: early development.** The core is written in Rust ([ADR 0001](documentation/adr/0001-rust-core.md)) and the plugins work against real Windows APIs: event logs, live usage sampling, and the repair commands. It has not had an outside security review or a tagged release yet, so try repairs with **Dry run** first.

## What it's designed to do

- **Portable, single executable.** Tauri v2 app; all state lives in `./data/` next to the exe. Nothing goes to the registry or `%APPDATA%`, and no helper binaries are dropped.
- **Standard user by default.** Runs `asInvoker`, so it never forces a UAC prompt at launch. Admin-only tools (`sfc /scannow`, Winsock reset) say so up front and offer to restart AegisWin as administrator.
- **PIN-gated approvals for AI agents.** Each tool is either `auto` (e.g. read-only log queries) or `pin_required`. A gated MCP call returns a local approval link where you review the exact action, add a comment, and accept or decline with your PIN. The PIN never reaches the agent, an LLM, or a log.
- **LAN-aware LLM use.** Local endpoints (Ollama, LM Studio, private LAN addresses) are trusted. Before a plugin sends diagnostics to an LLM outside your LAN, you have to trust that plugin, and usernames, hostnames, and local paths are scrubbed from the payload.
- **Self-contained plugins.** `event-logs`, `windows-health`, and `usage-monitor`, each with its own manifest, tests, and docs.

See [`documentation/ARCHITECTURE.md`](documentation/ARCHITECTURE.md) for diagrams and [`documentation/SECURITY_MODEL.md`](documentation/SECURITY_MODEL.md) for the threat model.

## Development setup (Windows)

### Prerequisites

| Tool | Notes |
| :--- | :--- |
| Windows 10/11 x64 | |
| [Node.js](https://nodejs.org) 20 or newer | CI uses 20 |
| Rust (stable, MSVC) | `winget install Rustlang.Rustup`, then open a new terminal |
| Visual Studio Build Tools | "Desktop development with C++" workload, including a Windows 10/11 SDK |
| WebView2 Runtime | Preinstalled on Windows 11 |

### Clone and install

```bash
git clone https://github.com/jcrump97/aegis-win.git
```
```bash
cd aegis-win
```
```bash
git config core.hooksPath .githooks
```
```bash
npm install
```

`core.hooksPath` turns on the repo's git hooks: commit-message checks and the full test suite before every commit. Git doesn't carry this setting over in a clone, so set it once per clone.

### Everyday commands

| Command | What it does |
| :--- | :--- |
| `npm run ci` | Full test suite: Node tests plus `cargo test --workspace` (also runs automatically before each commit) |
| `npm run dev` | UI only, in a browser at `http://127.0.0.1:1420` |
| `npm run tauri:dev` | Desktop app with hot reload. The first build takes a few minutes. |
| `npm run tauri:build` | Portable release exe at `target/release/aegis-win.exe` |
| `npm run package` | Release build copied to `release/AegisWin/AegisWin.exe` (git-ignored). Its vault lives in `release/AegisWin/data/` and survives repackaging. Add `-- --no-build` to copy the last build only. |

`npm run dev` and `npm run tauri:dev` both use port 1420, so run only one at a time.

## Contributing

- Read [`AGENT.md`](AGENT.md) for the engineering rules, and [`documentation/PLUGIN_SPEC.md`](documentation/PLUGIN_SPEC.md) before touching a plugin.
- Commit messages start with a type tag: `(feat)`, `(fix)`, `(doc)`, `(chore)`, `(test)`, `(refactor)`, `(security)`, or `(perf)`.
- Every commit updates tests and [`documentation/AUDIT_LEDGER.md`](documentation/AUDIT_LEDGER.md).
- Commits are signed. Changes land through pull requests into `main`.
- No AI-attribution trailers in commits or PRs; credit lives in this README.

## Acknowledgements

AegisWin is developed with help from **[Claude](https://claude.com)** by Anthropic, working through [Claude Code](https://claude.com/claude-code): architecture review, the Rust migration plan, build and repository setup, and code. Credit goes here instead of in individual commits.

## License

No license has been chosen yet, so all rights are reserved by the author for now.
