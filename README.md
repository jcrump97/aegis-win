# AegisWin

**A portable Windows diagnostic and repair utility with a human-gated MCP server.**

AegisWin is a single `.exe` you can run from a USB stick or a downloads folder. It lets you, or an AI agent you connect over [MCP](https://modelcontextprotocol.io), read event logs, watch resource usage, and run common Windows repairs. Every state-changing action an agent asks for waits until you approve it with your PIN.

> **Status: early development.** The core is written in Rust ([ADR 0001](documentation/adr/0001-rust-core.md)) and the plugins work against real Windows APIs: event logs, live usage sampling, and the repair commands. It has not had an outside security review or a tagged release yet, so try repairs with **Dry run** first.

## What it's designed to do

- **Portable, single executable.** Tauri v2 app; all state lives in `./data/` next to the exe. Nothing goes to the registry or `%APPDATA%`, and no helper binaries are dropped.
- **Standard user by default.** Runs `asInvoker`, so it never forces a UAC prompt at launch. Admin-only tools (`sfc /scannow`, Winsock reset) say so up front and offer to restart AegisWin as administrator.
- **PIN-gated approvals for AI agents.** Each tool is either `auto` (e.g. read-only log queries) or `pin_required`. A gated MCP call waits on the **Approvals** tab, where you review the exact action, add a comment, and accept or decline with your PIN. Agents get no approval link, and AegisWin never asks for the PIN on a web page. Optionally, **Approve from another device** lets you approve from a phone with a one-time code the app shows. The PIN never reaches the agent, an LLM, or a log.
- **Action plans.** An agent can propose up to five repairs to run in order under one approval. You see every step, its arguments, and the exact commands before you enter your PIN; the plan stops at the first failure, and you can stop it after any step. You can build the same kind of plan yourself with **Add to plan** on a repair's card. Every request, your decision, and each change AegisWin makes go into an encrypted approval record that only your PIN can open (Approvals tab). The record is tamper-evident: each event is chained to the one before and signed with a key kept in the vault, and the card says plainly if events were removed, cut short or changed. A change runs only once its start is on disk.
- **Diagnose this PC.** One button reads the event logs, memory and CPU, and lists what looks wrong, most serious first, with evidence and next steps. Suggested repairs go into a plan you approve with your PIN. With an LLM set up, **Explain with AI** ranks the findings, explains them, and suggests a plan, picking only among the repairs AegisWin linked to each finding. AI agents can run it over MCP, read-only, unless you turn that off.
- **LAN-aware LLM use.** Local endpoints (Ollama, LM Studio, private LAN addresses) are trusted. Before a plugin sends diagnostics to an LLM outside your LAN, you have to trust that plugin, and usernames, hostnames, and local paths are scrubbed from the payload.
- **A passphrase protects the folder.** The vault key is a passphrase: five random words AegisWin generates for you, or your own of at least 14 characters (a strength guide shows how guessable it is). Argon2id at 256 MiB makes each guess slow, so a copied `data` folder cannot be opened by guessing. If typing it is too much, **Keep a short PIN on this PC** lets a 6+ character PIN unlock on this Windows account only (Windows DPAPI); **Forget this PC** removes it. Vaults set up with a short PIN before this keep working and show a banner until you choose.
- **Locks itself.** The vault locks after 15 minutes without you (5 to 60 in Settings); what AI agents do never keeps it open. While a monitor runs, closing the window keeps AegisWin in the tray, and locking keeps the monitor going: it records only to an encrypted history that needs your PIN to read. Every start resumes running monitors, and an opt-in Startup shortcut (Settings, PIN to turn on) starts AegisWin in the tray when you sign in. Only one copy runs per folder.
- **Self-contained plugins.** `event-logs`, `windows-health`, and `usage-monitor`, each with its own manifest, tests, and docs.

See [`documentation/ARCHITECTURE.md`](documentation/ARCHITECTURE.md) for diagrams and [`documentation/SECURITY_MODEL.md`](documentation/SECURITY_MODEL.md) for the threat model.

## Quick start (Windows)

1. Get the code: clone the repository, or download the ZIP from GitHub and extract it.
2. Double-click **`Start AegisWin.exe`** in the project folder.

The launcher checks your PC for everything AegisWin needs: the WebView2 Runtime, the Visual Studio C++ Build Tools (with a Windows SDK), Node.js 20 or newer, and Rust. It lists anything missing and, after you say yes, installs it with winget. Then it installs the JavaScript packages, turns on the git hooks, builds the app if the source changed since the last build (the same as `npm run package`), and starts `release\AegisWin\AegisWin.exe`. Your vault is in `release\AegisWin\data\` next to it and is kept when the app is rebuilt.

- **The first run on a fresh PC is slow**, often 30 minutes or more: the C++ Build Tools are a multi-GB download and the first build compiles everything. Later runs start in seconds when nothing has changed.
- Some installers ask for administrator permission. The launcher itself runs as a standard user.
- The exe isn't code-signed, so if you downloaded the ZIP, Windows SmartScreen may say it doesn't recognize it. Choose **More info**, then **Run anyway**, or build the launcher yourself with `npm run launcher:build`.
- Options: `--check` reports what's installed and changes nothing, `--yes` installs without asking, `--rebuild` forces a build, and `--dev` starts the hot-reload dev app. `--help` lists them.

## Development setup (Windows)

`Start AegisWin.exe` does everything in this section for you. These are the same steps by hand.

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
| `npm run launcher:build` | Rebuilds `Start AegisWin.exe` from `launcher/`. Commit the new exe along with any launcher change. |

`npm run dev` and `npm run tauri:dev` both use port 1420, so run only one at a time.

### Connecting Claude Code in this folder

The repo's `.mcp.json` points Claude Code at AegisWin's MCP server. It holds no secrets; it reads two environment variables:

| Variable | Value |
| :--- | :--- |
| `AEGIS_MCP_TOKEN` | Required. The bearer token from the MCP tab (**Show token and setup commands**, needs your PIN). Update it after rotating the token. |
| `AEGIS_MCP_URL` | Optional, defaults to `http://127.0.0.1:47821/mcp`. Set it only if you changed the port. A LAN bind still listens on `127.0.0.1`, so clients on this PC never need the LAN address. |

On your network the server uses HTTPS with a certificate AegisWin makes and keeps in the vault. Agents on other devices trust the public certificate, `data\mcp-cert.pem` (or **Copy certificate** on the MCP tab): `NODE_EXTRA_CA_CERTS=<path>` for Claude Code and other Node clients, `curl --cacert <path>` for curl. Phones show a one-time browser warning. To avoid it, put your own `mcp-cert.pem` and `mcp-key.pem` (for example from `tailscale cert`) in the data folder; AegisWin moves the key into the vault.

Set them in your user environment, not in a file in the repo, so the token is never committed.

## Contributing

- Read [`AGENT.md`](AGENT.md) for the engineering rules, and [`documentation/PLUGIN_SPEC.md`](documentation/PLUGIN_SPEC.md) before touching a plugin.
- Commit messages start with a type tag: `(feat)`, `(fix)`, `(doc)`, `(chore)`, `(test)`, `(refactor)`, `(security)`, or `(perf)`.
- Every commit updates tests and [`documentation/AUDIT_LEDGER.md`](documentation/AUDIT_LEDGER.md).
- Commits are signed. Changes land through pull requests into `main`.
- No AI-attribution trailers in commits or PRs; credit lives in this README.

## Acknowledgements

AegisWin is developed with help from **[Claude](https://claude.com)** by Anthropic, working through [Claude Code](https://claude.com/claude-code): architecture review, the Rust migration plan, build and repository setup, and code. Credit goes here instead of in individual commits.

Generated passphrases use the [EFF large wordlist](https://www.eff.org/dice) by the Electronic Frontier Foundation, licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/). It is included unchanged as `src/ui/assets/eff_large_wordlist.txt`; AegisWin leaves out its 4 hyphenated words when picking.

## License

No license has been chosen yet, so all rights are reserved by the author for now.
