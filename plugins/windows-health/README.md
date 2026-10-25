# Plugin: `windows-health`

Windows repair commands. Every repair is `pin_required` by default and supports `dryRun: true`, which returns the exact commands and their impact without running anything (dry runs skip the PIN and admin gates).

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

`cargo test -p aegis-plugin-windows-health` never runs a real repair, because CI runners are administrators. It checks gating, dry-run output, argument handling, SFC result parsing, and LLM interpretation against a loopback mock.
