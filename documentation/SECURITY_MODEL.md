# AegisWin Security & Threat Model

## 1. Threat Boundaries
1. **Untrusted / Semi-Trusted MCP Agents**: External or local AI agents connected via MCP HTTP must never execute destructive or state-changing tools without human authorization, and must never access the user's PIN or raw API keys.
2. **Off-LAN LLM Providers**: Cloud LLM endpoints receive diagnostic snippets only after the user explicitly marks the calling plugin as trusted for Off-LAN transmission.
3. **Antivirus & EDR Compatibility**: Single-binary compilation (`asInvoker`) avoids process-injection patterns and unsigned multi-binary drops.

## 2. Cryptographic & Storage Standards
- **PIN Hashing & Key Derivation**: Startup PIN is processed through memory-hard `scrypt` / `Argon2id` with a 16-byte CSPRNG salt and verified with `crypto.timingSafeEqual`.
- **Vault Encryption**: LLM API keys and MCP Bearer tokens are encrypted at rest inside `./data/vault.enc` using `AES-256-GCM` with authenticated 12-byte IVs and 16-byte auth tags.
- **PIN Non-Exposure Invariant**: No API, MCP response, or log file ever contains the plaintext PIN or its derived key.

## 3. Automatic Firewall & Port Lifecycle
When the user enables the MCP HTTP server on port `P`:
- AegisWin binds to the configured interface and invokes `netsh advfirewall firewall add rule name="AegisWin_MCP_<P>" dir=in action=allow protocol=TCP localport=<P> profile=private` (or queues UAC elevation if required).
- When the MCP server stops or the portable app exits cleanly, the temporary firewall rule is removed so no stale open ports remain on the host.

## 4. Approval Portal Hardening (DNS Rebinding, CSRF, and 3-Strike Lockout)
- **Host Header Validation**: Rejects any request to `/mcp` or `/approve/:ticketId` whose `Host` header does not match `127.0.0.1`, `localhost`, or the configured LAN bind IP.
- **Per-Ticket CSRF Nonce**: Each approval page embeds a 128-bit cryptographic `csrfToken` validated on `POST`.
- **3-Strike PIN Brute-Force Lockout**: Three failed PIN submissions permanently transition the ticket to `locked_out` (`HTTP 423 Locked`), requiring the agent to request a fresh ticket.

### 3.1 Bind-Aware Firewall Resolution (`asInvoker` Compatibility)
- **Loopback Default (`127.0.0.1`)**: Bypasses `netsh advfirewall` so standard users never see an `Access is denied` error on startup.
- **LAN Mode (`0.0.0.0` / RFC1918 IP)**: Checks token elevation and issues `aegis-win.exe --elevate-firewall-port <P>` via UAC if running as a standard user.
