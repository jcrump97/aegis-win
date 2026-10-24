# Plugin: Windows Health & Network Stack Optimizer (`windows-health`)

## Purpose
Implements native Windows health and network repair operations (`sfc /scannow`, `ipconfig /flushdns`, `ipconfig /release && ipconfig /renew`, `netsh winsock reset`) with explicit per-tool PIN gating, dry-run impact advisories, and standard-user UAC self-elevation.

## Privilege Model (`asInvoker` Compatibility)
- `flush_dns` and `ip_release_renew` execute directly under standard user privileges.
- `sfc_scan` and `winsock_reset` require Administrator elevation. When AegisWin is running as a standard user (`isElevatedAdmin: false`), invoking these tools returns a single-binary self-elevation command (`aegis-win.exe --elevate-tool windows-health:<tool>`) that triggers a Windows UAC prompt only for that approved task.
