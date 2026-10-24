# AegisWin System Architecture & Design Plan

## 1. High-Level System Overview

**AegisWin** is a portable Windows utility built on **Tauri v2 (Rust)** and **Vite (React/TypeScript/ES Modules)** with a compile-time modular plugin architecture, a central OpenAI-compatible LLM diagnostic service, and an authenticated HTTP MCP server with PIN-gated human approval.

```
+-----------------------------------------------------------------------------------+
|                        AEGISWIN PORTABLE SINGLE EXECUTABLE                        |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                 HIGH-CONTRAST DYNAMIC-SCALE DARK UI (Vite)                  |  |
|  |  [Startup PIN Gate]  [First-Run Plugin Wizard]  [Dynamic Zoom: 85% - 150%]  |  |
|  |  [Plugin Workspace]  [Off-LAN LLM Trust Modal]  [Live MCP Approval Queue]   |  |
|  +--------------------------------------+--------------------------------------+  |
|                                         | IPC / Internal Bridge                   |
|  +--------------------------------------v--------------------------------------+  |
|  |                      COMPILE-TIME PLUGIN REGISTRY & ENGINE                  |  |
|  |                                                                             |  |
|  |  +---------------------+  +----------------------+  +--------------------+  |  |
|  |  | plugins/event-logs  |  | plugins/win-health   |  | plugins/usage-mon  |  |  |
|  |  | - query_logs (auto) |  | - flush_dns (pin)    |  | - cpu_ram_spikes   |  |  |
|  |  | - filter_id  (auto) |  | - ip_renew  (pin)    |  | - crash_correlator |  |  |
|  |  | - analyze_ai (auto) |  | - sfc_scan  (pin+adm)|  | - active_window    |  |  |
|  |  |                     |  | - winsock   (pin+adm)|  |                    |  |  |
|  |  +---------------------+  +----------------------+  +--------------------+  |  |
|  +----------+---------------------------+---------------------------+----------+  |
|             |                           |                           |             |
|  +----------v-----------+   +-----------v------------+   +----------v----------+  |
|  |  PORTABLE VAULT      |   |  CENTRAL LLM SERVICE   |   |  LOCAL MCP SERVER   |  |
|  |  (./data/vault.enc)  |   |  - Ollama / LM Studio  |   |  - Bearer Key Auth  |  |
|  |  - Scrypt/Argon2 KDF |   |  - OpenAI Compatible   |   |  - Auto Firewall    |  |
|  |  - AES-256-GCM Keys  |   |  - RFC1918 LAN Check   |   |  - /mcp JSON-RPC    |  |
|  |  - Zero-Knowledge PIN|   |  - Per-Plugin Trust    |   |  - /approve/:ticket |  |
|  +----------------------+   +------------------------+   +---------------------+  |
+-----------------------------------------------------------------------------------+
```

## 2. Core Data Flows & Sequence Diagrams

### 2.1 MCP Tool Call & PIN-Gated Web Approval Flow
When an AI agent connects to the local MCP HTTP server (`POST /mcp`), every tool call passes through the **Per-Tool Gate Policy Engine**:

```mermaid
sequenceDiagram
    participant Agent as External AI Agent (MCP Client)
    participant MCP as AegisWin MCP Server (:47821)
    participant Gate as Tool Gate Policy Engine
    participant Portal as Local Approval Web Page (/approve/:id)
    participant User as Human Operator

    Agent->>MCP: POST /mcp (Bearer Token) -> tools/call "windows-health:winsock_reset"
    MCP->>Gate: Check tool gate policy for "windows-health:winsock_reset"
    alt Tool Policy == "auto"
        Gate->>MCP: Execute tool immediately
        MCP-->>Agent: 200 OK { status: "completed", result: {...} }
    else Tool Policy == "pin_required"
        Gate->>MCP: Create Pending Ticket #T-9042
        MCP-->>Agent: 200 OK { status: "pending_approval", ticketId: "T-9042", approvalUrl: "http://127.0.0.1:47821/approve/T-9042" }
        User->>Portal: Opens http://127.0.0.1:47821/approve/T-9042 in browser
        Portal-->>User: Renders high-contrast action details, Accept/Decline, Comments, PIN input
        User->>Portal: POST /approve/T-9042 { decision: "accept", comment: "Proceed before reboot", pin: "****" }
        Portal->>Gate: Verify PIN hash in memory (Zero-Knowledge: PIN never stored in ticket)
        Gate->>Gate: Execute "windows-health:winsock_reset" (if accepted)
        Agent->>MCP: POST /mcp -> tools/call "mcp:check_ticket" { ticketId: "T-9042" }
        MCP-->>Agent: 200 OK { status: "approved", userComment: "Proceed before reboot", result: {...} }
    end
```

### 2.2 Central LLM Service & Per-Plugin Off-LAN Trust Flow

```mermaid
flowchart TD
    A[Plugin requests LLM analysis] --> B{Inspect Endpoint Host}
    B -->|127.0.0.1 / localhost / RFC1918 LAN| C[Classified: ON-LAN Trusted]
    B -->|Public IP or External Domain| D[Classified: OFF-LAN External]
    C --> E[Sign request with decrypted API key & execute]
    D --> F{Is Plugin in trustedExternalPlugins?}
    F -->|Yes| E
    F -->|No| G[Halt & Return OFF_LAN_TRUST_REQUIRED Warning]
    G --> H[User acknowledges warning & trusts Plugin in UI]
    H --> I[Persist pluginId in Portable Vault trusted list]
    I --> E
```

## 3. Directory Structure
```
aegis-win/
├── AGENT.md
├── CLAUDE.md
├── package.json
├── vite.config.ts
├── scripts/
│   └── ci-runner.mjs
├── documentation/
│   ├── ARCHITECTURE.md
│   ├── AUDIT_LEDGER.md
│   ├── GUIDING_PRINCIPLES.md
│   ├── PLUGIN_SPEC.md
│   └── SECURITY_MODEL.md
├── src/
│   ├── core/
│   │   ├── vault.mjs           # Portable Argon2/Scrypt + AES-256-GCM encrypted store
│   │   ├── llm-service.mjs     # Central LLM client + LAN/Off-LAN detector + plugin trust gate
│   │   ├── plugin-registry.mjs # Compile-time plugin loader, first-run wizard state, tool gating
│   │   └── mcp-server.mjs      # HTTP MCP server, auto-firewall port manager, /approve/:id portal
│   └── ui/
│       └── app-shell.mjs       # High-contrast dark UI state & dynamic scale controller
├── plugins/
│   ├── event-logs/             # Windows Event Log Explorer & AI log analyzer
│   ├── windows-health/         # SFC scan, DNS flush, IP release/renew, Winsock reset
│   └── usage-monitor/          # Modular resource spikes, crash correlator, active window tracker
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── app.manifest            # Windows UAC asInvoker manifest
│   └── src/
│       └── main.rs             # Rust native bridge, firewall rule helper, UAC self-elevation
└── tests/
    └── *.test.mjs              # Core & architectural verification test suites
```
