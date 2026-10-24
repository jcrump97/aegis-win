# CLAUDE.md — Fast-Context Guide for Claude & LLM Agents

## Quick Commands
- **Run full CI pipeline & test suites**: `npm run ci` (or `node scripts/ci-runner.mjs`)
- **Run unit & plugin tests**: `npm test`
- **Start Vite dev server**: `npm run dev`
- **Build portable Tauri v2 Windows binary**: `npm run tauri:build`

## Pre-Commit Checklist for Every Turn
Before running `git commit -m "(<type>) <description>"`:
1. **Skeptical Code Audit**: Did you reuse `src/core/` primitives instead of duplicating logic? Can any loop, regex, or subprocess call be simplified?
2. **Security Audit**:
   - Confirm the user's PIN is never serialized into logs, LLM payloads, or MCP tool responses.
   - Confirm any new plugin tool declares `requiresAdmin: boolean` and `defaultGatePolicy: 'auto' | 'pin_required'` in its `manifest.json`.
   - Confirm any LLM call passes `pluginId` into `CentralLlmService.complete()` so Off-LAN trust gating is enforced.
3. **Self-Contained Plugin Verification**: If touching `plugins/<name>/`, ensure `plugins/<name>/manifest.json`, `plugins/<name>/index.mjs`, `plugins/<name>/README.md`, and `plugins/<name>/tests/<name>.test.mjs` are all present and passing.
4. **Documentation Audit**: Update `documentation/AUDIT_LEDGER.md` and relevant files in `documentation/` before staging your commit.
5. **Commit Message Format**: Prepend `(feat)`, `(fix)`, `(doc)`, `(chore)`, `(test)`, or `(refactor)`—never append at the end.

## Critical Architectural Pointers
Read `documentation/ARCHITECTURE.md` first for system diagrams, `documentation/PLUGIN_SPEC.md` before creating or modifying plugins, and `documentation/SECURITY_MODEL.md` before touching vault encryption, firewall port management, or MCP approval tickets.
