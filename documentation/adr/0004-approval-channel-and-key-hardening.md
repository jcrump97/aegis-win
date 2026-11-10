# ADR 0004: Approval channel and key hardening

- **Status**: Accepted (2026-11-10). The owner accepted every recommended decision in §7. Implementation follows the phases in §6, one branch per phase.
- **Date**: 2026-11-08
- **Related**: [ADR 0002](0002-ai-monitor-creator.md) §5 (encrypted history), [ADR 0003](0003-action-plans.md) §3 and §7 (plan binding, approval record), [SECURITY_MODEL](../SECURITY_MODEL.md) §3, §4, §10
- **Supersedes, once implemented**: ADR 0003 §3's rule that the browser page "always requires the PIN". Under this ADR the browser page never asks for the vault PIN.

## Context

Two independent reviews of the 16-branch stack (through `feat/approvals-history`, `1c5d188`) agreed on one top finding, plus a set of smaller ones.

**The top finding: the approval channel.**
- The agent supplies the link where the owner types the PIN (`approvalUrl`).
- In LAN mode that page is plain HTTP.
- The PIN typed there is also the vault key: Argon2id over the PIN decrypts `vault.enc.json`.

So an agent can phish the PIN with a look-alike page, and anyone on the network can sniff it. Either gives the attacker the vault, the history keys and every future approval.

**The other findings:**
1. **Offline guessing.** A 6-character minimum PIN (`MIN_PIN_LEN = 6`) through Argon2id at 64 MiB, t=3, p=1 protects a portable vault. A copied data folder (USB stick, backup, cloud sync) can be attacked offline with no lockout. Most people choose 6 digits.
   - That is about 10^6 candidates.
   - One multi-core machine tries on the order of 50-200 per second at these settings.
   - So the expected time to break it is hours.
2. **The approval record can't prove it's complete or genuine.**
   - **Forgery.** Segments use HPKE base mode, so anyone with a stream's public key can write frames that read back as genuine. The public key is in the runtime file for plugin streams, and in process memory for every stream.
   - **Deletion and truncation go unnoticed.** Removing files, or cutting frames off the end of a file, leaves nothing a reader can detect.
   - **Flooding.** Pending tickets are never evicted and have no cap; only plans are capped, at 5. Retention then deletes the oldest files once the 64 MB size limit is reached, even inside the 90-day limit, so a burst of requests can push real history out.
   - **Writes fail open.** `record_approval` is `let _ = history_append(..)`, so a change can run with no record of it.
   - **A lost end.** A ticket that is running when AegisWin locks never gets its `finished` record: `record_finished` looks the ticket up in the store, and lock has already cleared it.
3. **Repairs aren't bound to what was shown.**
   - `windows-health` has no `review_call`.
   - A call with `dryRun: true` skips the gate (`Gate::Run`) and trusts the plugin to honour the flag.
   - A plan shows the commands from a dry run made at creation, but those commands aren't covered by the plan hash and aren't checked again when the plan runs.
4. **Robustness.**
   - `usage-monitor` has about 35 `lock().unwrap()` calls in `lib.rs` and no supervisor for its sampler, so one panic poisons a lock and stops monitoring for the rest of the session.
   - `os.rs` `reads_real_events_from_the_application_log` asserts the events come back in time order, but Windows returns them in record order, so the test is flaky.
   - A ticket that is withdrawn while queued is reported as `Stop::Locked` ("AegisWin locked…").
5. **Low-severity findings.**
   - Single-instance mutex and event names are predictable: `Local\AegisWin-<FNV hash of the path>-…`.
   - The Startup shortcut and **Restart as administrator** both launch an exe from a folder the user can write to, which allows DLL planting. The elevated restart is the case that matters.
   - The project pins `esbuild ^0.21.5`, which is affected by the dev-server CORS advisory GHSA-67mh-4wv8-2f99. This affects development only.
   - The docs oversell two things. The 8-hex plan fingerprint is a 32-bit label, and an agent controls both plans, so it can find two with the same fingerprint in about 2^16 tries. The keyword filters (unsafe questions, reasoning consistency) are heuristics.

**The owner's decision:** "option B sounds reasonable. i wish you could make https easy".

## Decision

- **Option B.** By default, the only way to approve is in the AegisWin window. Approving from a browser or phone is an opt-in setting, and it never uses the vault PIN. Each approval needs a one-time code that only the app shows (§1).
- **HTTPS for LAN mode.** It uses a self-signed certificate that AegisWin generates (§2).
- **Vault key.** It needs a strong passphrase; a short PIN is allowed only when the key is also wrapped to this PC with DPAPI (§3).
- **Approval record.** It becomes tamper-evident (§4).
- **Everything else** is fixed in the phases of §6.

## 1. Option B: approval channel

### 1.1 Default: approve in the app only

- **No `approvalUrl` for agents.** MCP responses, `aegis__check_ticket`, and the `tools/list` descriptions no longer contain an approval link. The pending response says: "Waiting for the owner to approve in the AegisWin app. Call aegis__check_ticket to see the outcome."
- **The portal is off by default.** `GET` and `POST /approve/*` return 404 unless the owner turns on **Approve from another device** (§1.2). The MCP endpoint itself doesn't change.
- **The vault PIN is never sent to a web page.** No form served by AegisWin has a PIN field, even with the setting on. The app states the rule next to the PIN fields: "AegisWin only asks for your PIN in this window. A web page asking for it is not AegisWin."
- **AegisWin notifies the owner itself.** It doesn't rely on the agent passing on a link.
  - **Inside the app:** the existing toast and **Approvals** badge.
  - **When the window is hidden or minimised:** a tray balloon (`Shell_NotifyIconW` with `NIIF_INFO`) and a taskbar flash (`FlashWindowEx`).
  - **Not Windows toast notifications:** toasts from an unpackaged app need an AppUserModelID registered on a Start-menu shortcut, which breaks the portable rule.
  - **Every agent request notifies, at most once per 30 seconds,** with the count rolled up ("3 requests waiting").

### 1.2 Opt-in: approve from another device with a one-time code

How the setting is controlled:
- **Turning it on** is in **MCP server** > **Approve from another device** and needs the vault PIN, in the app.
- **Turning it off** needs no PIN, because it makes things stricter.
- **It never turns on by itself.** A new install, or a vault restored from a backup, starts with it off.

The flow:
1. The agent's ticket appears in the app as usual.
2. On the ticket card, the owner clicks **Approve on another device**. Only now does AegisWin create a code.
3. The app shows the code and a QR code for the device page, which is a fixed URL: `https://<LAN IP>:47821/approve` in LAN mode (§2), or `http://127.0.0.1:47821/approve` on this PC.
4. The page lists the pending tickets, rendered by code exactly as they are today. On the ticket, the owner types the code and taps **Approve**.

Rules for the code:

| Property | Rule |
|---|---|
| **Alphabet and length** | 8 characters from Crockford base32 (`0-9 A-Z` without `I L O U`), shown as `K7QM-4XRT`. Input ignores case and dashes, and reads `I`/`L` as `1` and `O` as `0`. |
| **Entropy** | 40 bits from the OS random generator (`getrandom`). |
| **Storage** | Only SHA-256(code) is kept in the ticket. It is compared in constant time. The code itself exists in the app's display and nowhere else. |
| **Binding** | The code is created for one ticket ID. For a plan it is also bound to the full plan hash, and the POST must carry both. A code works only for the ticket it was shown on. |
| **Approve only** | The code authorises **approve**. **Decline** on the device page needs no code. So someone in the middle of the connection can't turn a decline into an approve: when the owner declines, no code is ever sent. |
| **Single use** | It is consumed by the first correct submission. It is also destroyed when the ticket leaves `pending_approval`, when AegisWin locks, when the ticket expires, or when the owner clicks **Approve on another device** again (which makes a new code). |
| **Lifetime** | 5 minutes from when it is shown, and never longer than the ticket's own TTL. |
| **Never leaves the app** | It never appears in MCP responses, ticket views sent over MCP, the approval record, logs, or the device page. The approval record logs `via: "device code"`. |
| **Attempts per ticket** | 3 wrong codes lock that ticket (`locked_out`), as `STRIKES_PER_TICKET` does today. |
| **Global attempt limit** | 10 wrong codes within an hour, across all tickets, turn **Approve from another device** off. The app shows a red notice, and turning the setting back on needs the PIN. With 40-bit codes and 10 guesses per hour, the chance of success is about 10/2^40 for each time the owner re-enables the setting. |
| **Kept apart from the vault lockout** | Wrong codes never count towards `PinGuard`. A code isn't the vault key, so guessing it reveals nothing that could be attacked offline, and an agent spamming wrong codes can't lock the owner out of the vault. (Today, agent PIN guesses do count towards the owner's lockout; that is known issue 2 in the test plan.) |
| **CSRF** | The per-ticket CSRF token stays, as a second check against cross-site posts. |

**What this protects against.**
- **A passive eavesdropper** sees a code that has already been used, which is worthless.
- **An attacker in the middle of the connection** can hide requests (denial of service) or show the owner a false description on the device. But the code only approves the ticket the owner was looking at in the app, which shows the true description. What gets approved is decided in the app, not on the device.
- **A phishing page that collects codes** gets codes that approve only what the owner meant to approve anyway.

**The limitation (decision D1).** The code is shown only in the app, so the owner must be at the PC to read it. In that situation, approving in the app is just as easy. The device path is mostly worthwhile when the PC's screen is in reach but its keyboard isn't (a TV, an HTPC, a second room with the monitor visible). A "paired phone" that can approve with no PC screen at all needs a trusted certificate to be safe (§2.4), so it is deferred.

### 1.3 Limits on how many requests agents can make

Today there is one MCP bearer token per install. The limits apply per token, so they still work if more tokens are added later.

| Limit | Value | Notes |
|---|---|---|
| Pending requests | 10 per token | Plans keep their own limit of 5, which counts within the 10. When full, a new request is refused with `Conflict` ("10 requests are already waiting for the owner"). |
| New requests | 30 per hour per token | Counted over a sliding window. Every request counts, including refused ones, so a flood is cheap to stop. |
| Total tickets in memory | `MAX_TICKETS` 200, as today | Finished tickets are still dropped oldest first; pending ones can no longer pile up past the caps above. |

## 2. HTTPS for LAN mode

Loopback (`127.0.0.1`) stays on plain HTTP. It never leaves the PC, and browsers treat it as a secure context.

### 2.1 Options evaluated

| Option | How it works | Warning on the phone | Protects against an attacker in the middle? | Fits portable / no registry / no certificate store? | Verdict |
|---|---|---|---|---|---|
| **A. Auto-generated self-signed certificate** | AegisWin generates a certificate and key at first LAN start (with `rcgen`, ECDSA P-256) and serves it with `rustls`. The app shows the SHA-256 fingerprint and a QR code. | **Yes, every new phone and every certificate change.** Chrome on Android shows *Your connection is not private*, then *Advanced* > *Proceed to … (unsafe)*, and remembers that for about a week. iOS Safari shows *This Connection Is Not Private*, then *Show Details* > *visit this website*. | Not for phones: browsers can't pin a certificate, and an attacker's certificate produces the same warning. **Yes for agent clients** that trust the exported certificate (§2.3). | Yes. The key lives inside the vault. | **Recommended** for LAN mode, together with §1.2. |
| **B. Pinned certificate via QR** | The QR code carries the URL plus the fingerprint. | Same as A. | No. A browser opening a URL from a QR code doesn't check a fingerprint. Only a dedicated app could, and AegisWin has none. | Yes | Use the QR code for **convenience only**, and say plainly that the browser doesn't check the fingerprint. |
| **C. Private CA installed on the phone** | AegisWin makes its own certificate authority. The owner installs it on the phone (an iOS profile with *Full Trust* turned on; an Android user CA). | None after setup. | Yes. | Not on the phone, and it is risky: if the CA key leaked from a portable folder, it could intercept **all** of the phone's HTTPS traffic unless name constraints are honoured, and support for them differs between platforms. | **Rejected.** |
| **D. Bring your own certificate** | The owner puts `mcp-cert.pem` and `mcp-key.pem` in the data folder, for example from `tailscale cert` (`*.ts.net`) or ACME DNS-01 for a domain they own. | None. | Yes. | Yes. The key file is read once and imported into the vault. | **Supported as an advanced option**; the only route to warning-free HTTPS. |
| **E. A hosted relay or a `*.plex.direct`-style certificate service** | A vendor service issues certificates for each install. | None. | Yes. | Needs an operated service and an account. | **Rejected** (out of scope; no servers). |
| **F. Plain HTTP with the one-time code** | Today's transport, with §1.2 added. | None. | Approvals stay safe thanks to the code binding, but the bearer token and request contents can be read. | Yes. | **Fallback only,** behind a *Compatibility: plain HTTP* toggle with a red warning. |

### 2.2 Recommendation

**LAN mode uses Option A by default, Option D when the owner provides a certificate, and Option F only as a labelled compatibility fallback.**

The reasons:
- **The bearer token is the main thing HTTPS protects.** It is long-lived and gives full agent access, and in LAN mode it crosses the network on every call. With A, agents that trust the exported certificate are **actually pinned** (§2.3), which closes that leak. The one-time code alone does nothing for the token.
- **For the phone, A protects against passive sniffing only.** An attacker in the middle produces the same warning as AegisWin's own certificate. The ADR doesn't claim more than that. Approval integrity against that attacker comes from §1.2, not from TLS.
- **Is plain HTTP acceptable as a fallback, with the code?** For approvals, yes: a sniffed code is already used, and it is bound to one ticket. For the token and request contents, no. So F stays off unless the owner picks it, with the warning "Anyone on this network can read your AI agent's token and requests."

### 2.3 Details for Option A

- **Generation.**
  - ECDSA P-256.
  - SubjectAltName lists every private IPv4 address AegisWin binds to, plus `localhost`.
  - Extended key usage is `serverAuth`, and the certificate is `CA:FALSE`.
  - It is valid for 397 days. iOS rejects TLS certificates valid for more than 825 days, even ones the user trusts; 397 days stays well inside every limit.
  - It is regenerated automatically 30 days before expiry, and when the LAN address changes (a new DHCP lease). Either way, the app warns: "Your AegisWin certificate changed. Phones will warn once more, and agents need the new certificate file."
- **Key storage.** The private key lives in the vault. The MCP server only runs while unlocked, so the key never needs to be on disk outside the vault. Only the public certificate is written, to `data\mcp-cert.pem`.
- **What the app shows** (on **MCP server**):
  - the URL
  - the SHA-256 fingerprint, in groups of 4 hex characters
  - a QR code of `https://<IP>:47821/approve`
  - **Save certificate for agents** (writes the PEM to a path the owner chooses)
  - a short explanation of the one-time browser warning, with a screenshot-style description of each step on Android and iOS
- **Agent clients.**
  - **Node-based clients** (Claude Code and others): set `NODE_EXTRA_CA_CERTS=<path to mcp-cert.pem>`. Node then trusts exactly this certificate, which pins it.
  - **Other clients:** use their own trust option, or `curl --cacert`.
  - The setup commands on **MCP server** include these lines.
  - **Phase 5 must check** that Claude Code and `curl` accept a self-signed `CA:FALSE` certificate as their only trusted certificate. If one refuses it, AegisWin generates a single-purpose CA instead: name-constrained to the bound IPs, kept in the vault, signing only the server certificate.
- **Crypto provider.** `rustls` with the `ring` provider. `aws-lc-rs` needs CMake and NASM to build on Windows.
- **The Host check.** Today's `Host` header check stays as it is.

### 2.4 Deferred: a paired phone

A phone paired once (with a QR code in the app and a long device secret kept in an `HttpOnly; Secure` cookie) could approve with a short approval PIN of its own and no PC screen. That would remove the limitation in §1.2.

It is safe only if an attacker can't steal the cookie, so it needs a certificate the phone actually trusts (Option D). With Option A, one warning clicked through on an attacker's connection would hand them the device secret and the approval PIN together. **So it is deferred, and allowed only with Option D** (decision D1).

## 3. Vault key strength

### 3.1 The same-user boundary

This statement goes into SECURITY_MODEL §1 in Phase 0:

> AegisWin's approval gate protects against AI agents that reach it **only through MCP**. It does not protect against code running as your Windows user. Such code can do all of the following:
> - read the data folder
> - read AegisWin's memory while it is unlocked
> - call DPAPI as you
> - replace or plant files next to the exe
> - send keystrokes to the window
>
> Run agents that can execute commands under a separate Windows account or in a sandbox if they must not be able to do these things.

Everything below protects against **someone who copies the data folder** (offline guessing) and **agents limited to MCP**. It doesn't protect against same-user code.

### 3.2 Passphrase rules for a portable vault

- **What a vault key must be:** a **passphrase** with an estimated strength of **at least 60 bits**. Two ways to meet it:
  - **Generated** (recommended, and the default choice on the setup screen): 5 words from the EFF large wordlist (7,776 words, about 64.6 bits), for example `cradle-unpaid-vivid-otter-sprout`. The words are generated on the device and shown once, with **Show again** and **I've written it down**.
  - **Owner-chosen:** at least 14 characters, with a `zxcvbn` strength score of 4. The score is a guide only; the length minimum is enforced.
- **Argon2id parameters.**
  - Raised to **m = 256 MiB, t = 3, p = 1**, tuned at creation to about 1 second, with a floor of 128 MiB.
  - The parameters are stored in the vault header, as today, so old vaults still open.
  - At a guess rate of 100 per second, a 60-bit passphrase takes about 3.6 × 10^8 years on one machine.
- **Existing vaults.**
  - At the first unlock after the upgrade, a vault whose key fails the new rule gets a banner: "Your PIN can be guessed in hours if someone copies your AegisWin folder." It offers **Set a passphrase** and **Keep a short PIN on this PC only** (§3.3).
  - Monitoring and approvals keep working until the owner chooses (decision D2).
  - Re-keying uses the existing `PinVerifier` / new-key path, so the vault is rewritten atomically.

### 3.3 Optional DPAPI wrapping: "Keep a short PIN on this PC"

**The problem.** With auto-lock at 15 minutes, the owner would type the passphrase many times a day.

**The fix.**
- The vault gets a random 256-bit **data key** (`K`). The vault contents are encrypted with `K`.
- `K` is stored wrapped in one or two ways:
  1. **Always:** `wrap_pass = AES-256-GCM(Argon2id(passphrase), K)`, in the vault header. This is the portable path, and it works on any PC.
  2. **Opt-in, this PC only:** `wrap_pin = DPAPI_CurrentUser(AES-256-GCM(Argon2id(short PIN), K))`, in `data\vault.thispc.bin`.
     - DPAPI ties the blob to this Windows account. Its master keys are files in the user profile, not the registry, so this fits the no-registry rule. The blob is useless on another PC or another account.
     - The short PIN must be at least 6 characters.
     - `PinGuard` limits guesses inside AegisWin.
- **Unlocking.**
  - On this PC, the short PIN or the passphrase both work.
  - Anywhere else, only the passphrase works.
  - **Forget this PC** deletes `vault.thispc.bin`, with no PIN needed.
- **What it doesn't protect against.**
  - Same-user code can call DPAPI and then guess the short PIN offline in hours (§3.1).
  - A thief who also has the user's Windows password can unwrap the blob.
  - The setting's description says both.
- **A stronger option, deferred.** Wrapping with a TPM-backed key (the Microsoft Platform Crypto Provider through NCrypt) gives a PIN that hardware limits against guessing, which would also slow same-user code. It keeps state in the user's key storage profile and needs a TPM. It is noted for later, not in this plan.
- **The agent rule doesn't change.** The vault PIN and the passphrase never reach logs, LLM payloads, MCP responses, or `invoke` responses (CLAUDE.md). The device code (§1.2) is not a vault credential.

## 4. A tamper-evident approval record

This applies to the `approvals` stream first. Plugin streams (`usage-monitor`) get the same format later; it is optional for them (decision D4).

### 4.1 Frames are chained

- Every record gets three new fields, filled in by the engine:
  - `seq`: per stream, rising by one for each record, continuing across files.
  - `prev`: the SHA-256 of the previous record's canonical plaintext.
  - `mac`: see §4.2.
- Every segment starts with an `open` frame: segment name, starting `seq`, and the `prev` link from the previous segment's last frame.
- A cleanly closed segment ends with a `close` frame: record count, last `seq`, last hash. Rotation, lock and Quit all close cleanly.
- A segment with no `close` frame is reported as "ended without closing (AegisWin stopped unexpectedly, or the file was cut short)".

### 4.2 Forward-secure MAC: stops forgery with the public key

- **Each writer session** (from unlock to lock, or from lock to unlock) starts with a random 32-byte key `M0`.
- **Each frame** is authenticated with `mac = HMAC-SHA256(Mi, frame)`. Then the key is replaced with `Mi+1 = SHA-256("aegis-ratchet" || Mi)`, and `Mi` is wiped.
- **Where `M0` is kept:** sealed in the vault, while the vault key is still in memory.
  - A session that starts at **unlock** stores its `M0` then.
  - A session for a **locked period** starts just before lock zeroes the vault key, so its `M0` is stored at that moment.
- **Verifying.** The reader takes `M0` from the vault and recomputes every key in turn.
- **What an attacker can do.**
  - Someone with the public key but not the vault can't produce a valid `mac`.
  - Someone who later reads process memory gets only the current key, so they can't forge earlier frames (forward security).
  - They can still forge frames *after* the point they read, which is within the same-user boundary of §3.1.

### 4.3 Checkpoints in the vault: detect deletion and truncation

- At every unlock, every lock, and Quit while unlocked, the engine stores `{stream, last seq, last hash, last segment name}` in the vault, with the session keys from §4.2.
- **The limit, stated plainly:** records written after the last checkpoint can be cut off. Doing so also removes the segment's `close` frame, so the segment is reported as "ended without closing". It is flagged, but can't be told apart from a crash.
- When reading, AegisWin compares the files on disk against the last checkpoint and against its own `seq` and `prev` links.
- **Retention and purges are recorded.** Before retention deletes a file, it writes a `pruned` record giving the `seq` range and last hash of what it deleted. A purge (**Delete the record (PIN)**) starts a new chain whose first record is `purged`, with the count it removed. A gap covered by one of these records is an authorised gap, not tampering.

### 4.4 Reporting

The **Approval record** card shows one integrity line above the table:
- "Verified: 1,284 events, no gaps."
- "Events 1,203 to 1,288 are missing (a file was deleted outside AegisWin)."
- "The record ends at event 1,301, but AegisWin last saw 1,342 (it was cut short)."
- "File seg-20261108-002.bin failed its check (changed or forged); its 40 events are shown in red."
- "seg-20261109-001.bin ended without closing."

The same results are written into the record as `integrity` events the next time it is read, so a later reader also sees that tampering was found.

### 4.5 No eviction by size inside the day limit

- The `approvals` stream is retained **by age only**: 90 days, as today. The size limit no longer deletes files from it.
- **Ceiling:** the stream stops accepting new records at **256 MB**. Agent requests are then refused, with "The approval record is full. Open AegisWin." The app shows a banner offering **Delete the record (PIN)** or a shorter retention period. Plugin streams keep size eviction (decision D3).
- **Expected size:** the limits in §1.3 cap creation at 30 requests per hour, and arguments are already capped at 4 KB. That is at most about 7 MB a day, under 256 MB within the first 36 days of a sustained flood, and normal use is far below that.

### 4.6 Failing closed for changes

| Record | If writing it fails |
|---|---|
| `created` | The request is refused ("AegisWin couldn't write its approval record"). |
| `decided` (approve) | The approval isn't applied, and the ticket stays pending, with an error shown. |
| `decided` (decline) | The decline still happens (it is the safe direction), and the failure is noted in memory and shown as a banner. |
| `change_started` | **The change doesn't run.** The record is synced to disk (`sync_data`) before the plugin is called, instead of waiting for the 30-second `SYNC_EVERY` flush. |
| `change_finished` | The change already happened. The record is held in memory and written again before the next record; a banner appears until it is written. |
| `finished` / `cancelled` | Same as `change_finished`. |

### 4.7 A ticket running at lock

- The run task keeps its own copy of the ticket's final view.
- It writes `finished` from that copy, instead of looking the ticket up in the store (which lock clears).
- While locked, the write uses the cached public key and the locked-period MAC session (§4.2).

## 5. Repair tools: bind what runs to what was shown

- **Commands are described by a pure function.**
  - Plugins get a new optional trait method, `describe(tool, args) -> Option<Vec<CommandLine>>`, where each entry is an absolute exe path plus an argument vector.
  - `windows-health` implements it with its existing `plan(tool, args)` and also adds `review_call`, so the code-written description appears in the app.
- **The engine answers dry runs itself.**
  - For a tool that implements `describe`, a `dryRun: true` call returns `describe()` and **never calls `Plugin::call`**. So the dry run is safe by construction, not by convention.
  - For a tool without `describe`, `dryRun: true` no longer skips the gate. The registry stops returning `Gate::Run` for those tools.
- **The commands are covered by the hash, and checked again at run time.**
  - A plan's hash input gets each step's `commands` from `describe()`, so the commands shown are part of what is approved.
  - Single tickets store the same list.
  - Before each step runs, the engine calls `describe()` again and refuses the step if the result differs: "The commands changed since you approved them."
- **Deferred.** The core executing the commands itself (the plugin returning commands, and `os` running them) is noted for later. With the check above, it isn't needed now.

## 6. Phased fix plan

Each phase is its own branch, stacked on this one, with a review and isolated CI before every commit. Nothing is pushed without the owner's OK.

| Phase | Scope | Findings closed |
|---|---|---|
| **0. Docs (this branch)** | This ADR; an audit ledger row; SECURITY_MODEL notes on the same-user boundary (§3.1), LAN cleartext as it is today, the fingerprint being a label rather than proof, and the keyword filters being heuristics. | The docs overselling things; LAN cleartext undocumented |
| **1. Approval channel** | §1 in full: no `approvalUrl`; portal off by default; no PIN field on any web page; one-time device codes; a separate code limit, outside `PinGuard`; tray balloon and taskbar flash; the limits in §1.3. Also the tray-icon description fix (known issue 1) and `Stop::Cancelled` for withdrawn tickets. Amends ADR 0003 §3 and its doc test. | Phishing the agent-supplied URL; agent guesses locking out the owner; unlimited pending requests; withdrawn tickets reported as locked |
| **2. Vault key** | §3: passphrase rules, the EFF wordlist, Argon2id tuning, the data key with two wraps, "Keep a short PIN on this PC" with DPAPI, the upgrade banner for existing vaults. | Offline guessing |
| **3. Approval record integrity** | §4: `seq`/`prev`/`mac`, `open`/`close` frames, the forward-secure MAC sessions, vault checkpoints, `pruned`/`purged` records, the integrity line, age-only retention with the ceiling, fail-closed writes, the lock-time `finished` fix. Migration: a new chain starts at upgrade; older files are shown as "recorded before integrity checks". | Forgery, truncation, file deletion, flooding plus eviction, failing open, the lost `finished` record |
| **4. Repair binding** | §5: `describe`, `windows-health` `review_call`, engine-answered dry runs, commands in the hash, the run-time check. | No `review_call`; dry runs unsafe by convention; displayed commands not bound |
| **5. HTTPS for LAN** | §2: generated certificate in the vault, `rustls` with the `ring` provider, the fingerprint and QR code, **Save certificate for agents**, bring-your-own certificate, the *Compatibility: plain HTTP* toggle. | Cleartext token and approvals on the LAN |
| **6. Robustness and low-severity items** | Replace `lock().unwrap()` in `usage-monitor` with the core's poison-tolerant `lock()` helper; supervise the sampler (restart it with backoff, write a `sampler_restarted` record and a gap); fix the event-log test to check record order; give the single-instance objects a random per-install suffix plus a DACL limited to the current user's SID; build with `/DEPENDENTLOADFLAG:0x800` and call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` first thing in `main`; upgrade `esbuild` to ≥0.25 (checking Vite compatibility). The small items can come forward into an earlier phase. | The unwraps and missing supervisor; the flaky test; predictable mutex names; DLL planting; esbuild |

Phases 1 and 2 come first: together they mean the vault key never goes to a web page and survives a copied folder. Phase 3 is independent of them, so it can go in parallel if the owner wants.

## 7. Decisions (accepted by the owner, 2026-11-10)

- **D1. Device approval: (a).** Approval is in the app only by default. The opt-in device code of §1.2 is built as specified. The paired phone of §2.4 is deferred until a bring-your-own certificate exists.
- **D2. Existing short PINs: (a).** At the first unlock after Phase 2, the owner must choose: set a passphrase, or keep the short PIN on this PC only (§3.3). The vault stays usable until they choose, but the choice can't be dismissed.
- **D3. A full approval record: (a).** At 256 MB, new agent requests are refused until the owner acts (§4.5).
- **D4. Integrity checks: (a).** The approval record first, in Phase 3. `usage-monitor` history follows later.
- **D5. The EFF large wordlist: (a).** It is embedded, with the CC BY 3.0 credit in the README.
- **D6. HTTPS for LAN mode: (a).** Self-signed (Option A) by default. Plain HTTP only through the compatibility toggle.

## Consequences

- **What gets easier and safer.** Agents can no longer phish or sniff the vault key, and approvals in LAN mode stay sound even over HTTP. The approval record can show that it is complete and that its events are genuine. A repair can only run the commands the owner saw.
- **What gets harder.**
  - Approving from a phone needs the PC's screen (D1).
  - Phones show one certificate warning per certificate.
  - Owners with a short PIN must set a passphrase, or limit the vault to this PC.
  - The approval record can fill up and block agents (D3).
- **What stays the same.** Agents limited to MCP remain the boundary. Code running as the same Windows user is outside it, and the docs now say so.
