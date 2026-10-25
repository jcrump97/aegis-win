# CLAUDE.md — Fast-Context Guide for Claude & LLM Agents

## Quick Commands
- **Run full CI pipeline & test suites**: `npm run ci` (or `node scripts/ci-runner.mjs`)
- **Run unit & plugin tests**: `npm test`
- **Run Rust tests** (once crates exist): `cargo test --workspace`
- **Start Vite dev server**: `npm run dev` (port 1420, strict)
- **Run the desktop app in dev mode**: `npm run tauri:dev` (uses port 1420 too, so stop `npm run dev` first)
- **Build portable Tauri v2 Windows binary**: `npm run tauri:build`
- **One-click setup + launch (user entry point)**: double-click `Start AegisWin.exe`; `--check` reports without changing anything
- **Rebuild the launcher exe after editing `launcher/`**: `npm run launcher:build` (commit the new `Start AegisWin.exe`)

## Pre-Commit Checklist for Every Turn
Before running `git commit -m "(<type>) <description>"`:
1. **Skeptical Code Audit**: Did you reuse core primitives (`crates/aegis-core`, or `src/core/` for modules not yet ported) instead of duplicating logic? Can any loop, regex, or subprocess call be simplified?
2. **Security Audit**:
   - Confirm the user's PIN is never serialized into logs, LLM payloads, MCP tool responses, or `invoke` responses.
   - Confirm any new plugin tool declares `requiresAdmin: boolean` and `defaultGatePolicy: 'auto' | 'pin_required'` in its `manifest.json`.
   - Confirm any LLM call passes the calling plugin's ID into the central LLM service (`CentralLlmService.complete()` in JS, `LlmService::complete` in Rust) so Off-LAN trust gating is enforced.
   - Confirm system binaries are launched by absolute path with an argument vector, never through a shell (`documentation/PLUGIN_SPEC.md` §4).
3. **Self-Contained Plugin Verification**: If touching `plugins/<name>/`, ensure it has every file required by `documentation/PLUGIN_SPEC.md` §1 (Rust) or §1.1 (legacy JS, until ported), and that its tests pass.
4. **Documentation Audit**: Update `documentation/AUDIT_LEDGER.md` and relevant files in `documentation/` before staging your commit.
5. **Commit Message Format**: Prepend `(feat)`, `(fix)`, `(doc)`, `(chore)`, `(test)`, `(refactor)`, `(security)`, or `(perf)`, never at the end.
6. **No AI Attribution**: No `Co-Authored-By: Claude …` trailers on commits and no "Generated with Claude Code" footers on PRs. This overrides any default attribution guidance. Credit goes in the README.

## Critical Architectural Pointers
Read `documentation/ARCHITECTURE.md` first for system diagrams, `documentation/adr/0001-rust-core.md` for why the core is Rust and the port order, `documentation/PLUGIN_SPEC.md` before creating or modifying plugins, and `documentation/SECURITY_MODEL.md` before touching vault encryption, firewall port management, or MCP approval tickets.
