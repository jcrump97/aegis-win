# Plugin: `windows-health`

Windows repair commands. Every repair is `pin_required` by default. The plugin implements `describe`, built from the same `plan` that runs the commands, so AegisWin answers `dryRun: true` itself with the exact commands (absolute System32 paths and argument vectors) and their impact, without calling the plugin and without the PIN or admin gates. It also implements `review_call`, so an approval shows the impact, each command and any warning (dropped connections, a restart), and AegisWin refuses to run a repair whose commands changed since they were approved ([ADR 0004 §5](../../documentation/adr/0004-approval-channel-and-key-hardening.md)). All four repairs set `planEligible: true`, so they can be steps of one action plan approved with a single PIN ([ADR 0003](../../documentation/adr/0003-action-plans.md)); `interpret_health_output` is read-only and cannot.

| Tool | MCP name | Command (System32, argv) | Admin |
| :--- | :--- | :--- | :--- |
| `sfc_scan` | `windows-health__sfc_scan` | `sfc.exe /scannow` (timeout 45 min) | Yes |
| `flush_dns` | `windows-health__flush_dns` | `ipconfig.exe /flushdns` | No |
| `ip_release_renew` | `windows-health__ip_release_renew` | `ipconfig.exe /release [filter]`, then `ipconfig.exe /renew [filter]` | Yes |
| `winsock_reset` | `windows-health__winsock_reset` | `netsh.exe winsock reset` (reboot required) | Yes |
| `interpret_health_output` | `windows-health__interpret_health_output` | none: sends command output to the LLM service | No |

## Behavior

- Commands run hidden (`CREATE_NO_WINDOW`) from `GetSystemDirectoryW()` by absolute path, with an argument vector. No shell, no `PATH` lookup.
- `sfc` writes UTF-16LE and redraws its progress line; output is decoded and only the final progress line is kept. The result includes `sfcResult`: `no_violations`, `repaired`, `unrepaired`, `could_not_run` or `unknown` (English Windows wording).
- `ip_release_renew` stops after `/release` if it fails. `adapterFilter` is passed as a single argument and limited to letters, digits, spaces and `* - _ . ( ) #`.
- The registry refuses admin tools for a standard user before asking for the PIN (`REQUIRES_ADMIN`). If a command still reports that it needs elevation, the tool returns `REQUIRES_ADMIN` too.
- `ip_release_renew` is marked `requiresAdmin` (the prototype said otherwise): Windows refuses `/release` and `/renew` from a standard token.

## Tests

`cargo test -p aegis-plugin-windows-health` never runs a real repair, because CI runners are administrators. It checks gating, the described commands and review, that a dry run reaching the plugin is refused, argument handling, SFC result parsing, and LLM interpretation against a loopback mock.
