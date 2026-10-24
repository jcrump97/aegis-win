# Documentation & Architectural Audit Ledger

> **Rule for Future Agents**: This ledger must be updated with every atomic commit to verify that `documentation/` reflects the current state of the codebase.

| Commit Order | Type | Summary | Audited Docs | Test Suite Verified |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `(chore)` | Initialize portable Windows utility repository and CI pipeline | N/A (Bootstrap) | `tests/01-ci-foundation.test.mjs` |
| 2 | `(doc)` | Establish guiding principles, agent standards, and system architecture plan | `AGENT.md`, `CLAUDE.md`, `GUIDING_PRINCIPLES.md`, `ARCHITECTURE.md`, `PLUGIN_SPEC.md`, `SECURITY_MODEL.md` | `tests/02-documentation-audit.test.mjs` |
| 3 | `(feat)` | Implement portable zero-knowledge PIN vault and AES-256-GCM secret store | `SECURITY_MODEL.md`, `AUDIT_LEDGER.md` | `tests/03-vault.test.mjs` |
| 4 | `(feat)` | Add central LLM service with LAN detection and per-plugin external trust gate | `ARCHITECTURE.md`, `AUDIT_LEDGER.md` | `tests/04-llm-service.test.mjs` |
| 5 | `(feat)` | Implement compile-time plugin registry, first-run wizard state, and per-tool gate policy engine | `PLUGIN_SPEC.md`, `AUDIT_LEDGER.md` | `tests/05-plugin-registry.test.mjs` |
| 6 | `(feat)` | Build local MCP HTTP server with auto firewall port management and PIN-gated approval web portal | `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `AUDIT_LEDGER.md` | `tests/06-mcp-server.test.mjs` |
