# AegisWin Security & Threat Model

## 1. Threat Boundaries
1. **Untrusted / Semi-Trusted MCP Agents**: External or local AI agents connected via MCP HTTP must never execute destructive or state-changing tools without human authorization, and must never access the user's PIN or raw API keys.
2. **Off-LAN LLM Providers**: Cloud LLM endpoints receive diagnostic snippets only after the user explicitly marks the calling plugin as trusted for Off-LAN transmission.
3. **Antivirus & EDR Compatibility**: Single-binary compilation (`asInvoker`) avoids process-injection patterns and unsigned multi-binary drops.

## 2. Cryptographic & Storage Standards
- **Key derivation**: the PIN (6-128 characters) goes through Argon2id (64 MiB, 3 passes) with a 16-byte random salt. No PIN hash or verifier is stored; a wrong PIN shows up as an AES-GCM authentication failure. The KDF parameters and salt are bound to the ciphertext as associated data.
- **Vault encryption**: all settings, including LLM API keys and the MCP bearer token, are encrypted in `./data/vault.enc.json` with AES-256-GCM and a fresh 12-byte nonce on every save. Saves are atomic (write a temp file, flush, rename).
- **PIN Non-Exposure Invariant**: no API, MCP response, approval page or log line ever contains the PIN or the derived key.
- **One rate limit for every PIN check**: unlock, in-app approvals, gate changes, token reveal and the browser portal share a guard: 5 free attempts, then a 30-second cooldown that doubles per further failure (capped at 1 hour). PIN checks are serialized so parallel guesses cannot slip past it.

### 2.1 Rust Core Requirements ([ADR 0001](adr/0001-rust-core.md))
- **Algorithms**: Argon2id (`argon2` crate) for new vaults, AES-256-GCM (`aes-gcm`), `OsRng` for every salt, nonce, ticket ID, and CSRF token. No hand-rolled cryptography.
- **Secret memory**: the PIN, derived key, and decrypted secrets are held in `zeroize`-on-drop types inside the Rust process and wiped when the vault locks. Comparisons of verifiers and tokens use constant-time equality (`subtle`).
- **Webview boundary**: the webview is untrusted for secrets. It sends the startup PIN to exactly one Tauri command (`unlock_vault`), keeps no copy, and never receives API keys or derived keys back. The MCP bearer token is the one exception: the user needs it to configure an MCP client, so it is returned only by an explicit, PIN-confirmed `reveal_mcp_token` action. API keys are write-only from the UI. Secret-bearing types do not implement `Serialize` or `Debug`, so they cannot leak into an `invoke` response or a log line by accident.
- **No demo credentials**: no build may ship a default or hardcoded PIN. A vault that doesn't exist yet means first-run PIN setup.
- **Process execution**: system binaries are launched by absolute path with argument vectors only. No shell, no `PATH` lookup, no string-built command lines (see [PLUGIN_SPEC §4](PLUGIN_SPEC.md)).

## 3. MCP Server Binding and Firewall (`aegis-core::mcp`)
- **Bind address**: `127.0.0.1` (default) or one of this PC's private IPv4 addresses (10/8, 172.16/12, 192.168/16). `0.0.0.0` and public addresses are refused, so the server is never reachable from outside the local network by configuration mistake.
- **Lifetime**: the server runs only while the vault is unlocked. Locking stops it and forgets every ticket.
- **Firewall rule**: only for a LAN bind, only when "open firewall" is on, and only when AegisWin already runs elevated: `netsh advfirewall firewall add rule name=AegisWin-MCP-<port> dir=in action=allow protocol=TCP localport=<port> localip=<bind ip> remoteip=localsubnet profile=private`. It is deleted when the server stops. A standard user gets a note instead of a UAC prompt; loopback never touches the firewall.
- **Authentication**: `POST /mcp` needs `Authorization: Bearer <token>` (24 random bytes, compared in constant time). The token can be rotated at any time, which disconnects existing clients.

## 4. Approval Tickets and the Browser Portal
- **When**: a `pin_required` tool called over MCP never runs directly. It returns `pending_approval` with a 128-bit `ticketId` and an `approvalUrl`. Tools that need administrator rights fail with `REQUIRES_ADMIN` before a ticket is opened, so the owner is never asked to approve something that cannot run. `dryRun: true` calls skip the gate because they only describe the commands.
- **Who**: the owner approves or declines in the AegisWin app or at `GET /approve/{ticketId}`. Both decisions need the PIN, so an agent cannot probe PINs or spam declines. Approval re-checks that the plugin and component are still enabled, then runs the tool in the background; the agent polls `aegis__check_ticket`.
- **Host and Origin validation (DNS rebinding)**: every request to `/mcp` and `/approve/*` must name the bound address in `Host` (`127.0.0.1:<port>` or `localhost:<port>` for loopback, `<lan ip>:<port>` for LAN). A present `Origin` must be the same address.
- **CSRF**: each ticket has its own 128-bit CSRF token, embedded in the approval form, compared in constant time, and never returned to agents.
- **No script, strict headers**: the portal is server-rendered HTML with every value escaped and no JavaScript. Headers: `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`.
- **Lockouts**: three wrong PINs lock the ticket (`locked_out`, HTTP 423) and the agent must ask again. Wrong PINs also count toward the global guard (HTTP 429 while it cools down). Pending tickets expire after 30 minutes.

## 5. Elevation
AegisWin always starts `asInvoker`. Tools that need administrator rights report `REQUIRES_ADMIN`, and the UI offers **Restart as administrator** (a UAC prompt via `ShellExecuteExW` with `runas`), after which the vault must be unlocked again. There is no cross-integrity job bridge: the prototype's encrypted job files were dropped (ADR 0001, Amendment 1) because one elevated process is simpler to reason about than a privileged helper that accepts requests.

## 6. Off-LAN LLM Gate and PII Sanitizer (`aegis-core::llm`)
- **LAN classification** parses the endpoint URL first. IP literals are LAN when loopback, RFC 1918, link-local, IPv6 ULA (`fc00::/7`) or IPv6 link-local; host names only when they are `localhost` or end in `.localhost`, `.local`, `.lan`, `.home`, `.internal` or `.home.arpa` (whole labels, so `fcbarcelona.com` is not LAN). Everything else is Off-LAN.
- **Trust is bound by the engine, not the plugin.** Each call gets an `LlmHandle` carrying the calling plugin's id and whether the user trusted it; a plugin cannot claim another identity. An untrusted Off-LAN call fails with `OFF_LAN_TRUST_REQUIRED` before any byte is sent.
- **Granting trust needs the PIN; revoking does not.** Trust is for a destination: changing the endpoint to a different host clears every grant.
- **Off-LAN endpoints must use `https://`.** Plain-HTTP Off-LAN URLs are refused.
- **No redirects.** The HTTP client never follows redirects, so a LAN endpoint cannot bounce a payload to an Off-LAN host.
- **Scrubbing** runs on every string in the payload before an Off-LAN call: profile paths (`C:\Users\<Name>`, also with `/`), SMB UNC server names (`\\Server\Share`), and the Windows user and computer names as whole words (case-insensitive). The PIN is never part of any payload because it is never stored.
