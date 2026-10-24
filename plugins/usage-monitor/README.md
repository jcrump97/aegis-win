# Plugin: Diagnostic Usage & Time-Window Monitor (`usage-monitor`)

## Purpose
Captures targeted diagnostic clues during user-specified timeframes or application slowdowns without running an intrusive 24/7 background agent.

## Modular Installable Sub-Components
During the First-Run Setup Wizard (or in Plugin Settings), the user can individually toggle:
1. `usage-monitor:resource-spikes` — Per-process CPU %, RAM working set, and Disk I/O spike detection.
2. `usage-monitor:crash-correlator` — Automatic temporal correlation between resource spikes and Windows Event ID `1000` / `1002` faults.
3. `usage-monitor:active-window` — Foreground window responsiveness (`GetForegroundWindow` + `SendMessageTimeoutW` hang detection).
