# AegisWin Guiding Principles

This document records the foundational engineering philosophy for **AegisWin**. Future agents must evaluate every design decision against these five pillars.

## 1. Skeptical Minimalism & Native Efficiency
- **Question Every Abstraction**: Always ask whether a standard OS command, Win32 API, or existing core module already solves the problem.
- **Avoid Antivirus False Positives**: Multi-binary droppers and obfuscated child scripts trigger Windows Defender SmartScreen and Bitdefender Advanced Threat Defense. AegisWin compiles plugins into a single portable executable and uses transparent, structured command invocation.

## 2. True Zero-Footprint Portability
- **Self-Contained `./data/` Directory**: All configuration, encrypted secrets (`vault.enc`), rolling telemetry (`telemetry.json`), and audit logs live relative to the portable executable directory.
- **Standard User First (`asInvoker`)**: Launching the app never forces a UAC prompt. Users can browse logs, monitor resources, and run the MCP server as a standard user, elevating only specific administrative repair tools when needed—or optionally set "Run as Administrator" in Windows shortcut properties.

## 3. Zero-Knowledge Human Authority
- **The AI Never Sees the PIN**: The user's PIN is prompted on startup and verified locally via cryptographic KDF (Scrypt/Argon2id + timing-safe comparison). Neither the MCP client agent nor any LLM provider can ever read, query, or infer the PIN.
- **Out-of-Band Web Approval Portal**: When an MCP agent calls a gated tool, the server issues a ticket and returns a local approval URL (`http://<host>:<port>/approve/<ticket-id>`). The human operator reviews the exact tool parameters, enters optional feedback comments, selects Accept or Decline, and authenticates with their PIN.

## 4. Network-Aware Data Sovereignty
- **LAN vs. Off-LAN LLM Classification**: Localhost (`127.0.0.1`, `::1`) and private RFC1918 LAN subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are recognized as local home/lab networks. Any external endpoint triggers a per-plugin trust prompt warning the user that diagnostic data may leave the LAN.

## 5. High-Contrast, Dynamically Scalable Ergonomics
- **Dark-First WCAG AAA Contrast**: Pure obsidian/slate surfaces (`#090D16` / `#111827`) paired with high-luminance text (`#F9FAFB`) and semantic status indicators.
- **Dynamic UI Scaling**: Every typography, spacing, and control token scales fluidly via a root scale factor (`--ui-scale: 0.85` to `1.50`), ensuring crisp legibility from compact 1080p laptops to 4K monitors.
