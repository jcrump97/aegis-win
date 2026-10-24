import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createAegisWinApp } from '../src/ui/app-shell.mjs';

test('Full System Integration: Tauri v2 asInvoker manifest, dynamic UI scaling, and all 3 plugins registered', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-e2e-'));
  try {
    // Verify Windows manifest uses asInvoker (Standard User by default)
    const manifestXml = fs.readFileSync('src-tauri/app.manifest', 'utf8');
    assert.match(manifestXml, /requestedExecutionLevel level="asInvoker" uiAccess="false"/);

    const app = createAegisWinApp({ dataDir: tmpDir });
    app.vault.unlockWithPin('246810');

    // Verify dynamic UI scaling clamping and persistence
    assert.equal(app.setUiScale(1.25), 1.25);
    assert.equal(app.setUiScale(2.5), 1.5);
    assert.equal(app.setUiScale(0.5), 0.85);
    assert.equal(app.getThemeSpec().backgroundPrimary, '#090D16');

    // Verify all 3 core plugins and their tools are available
    const plugins = app.registry.listAvailablePlugins();
    assert.equal(plugins.length, 3);
    const mcpTools = app.registry.listMcpTools();
    assert.ok(mcpTools.some((t) => t.name === 'event-logs:query_logs'));
    assert.ok(mcpTools.some((t) => t.name === 'windows-health:sfc_scan'));
    assert.ok(mcpTools.some((t) => t.name === 'usage-monitor:capture_diagnostic_snapshot'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Tauri Build Scaffold: build.rs embeds the asInvoker manifest, Windows icon exists, and lockfiles are committed', () => {
  // Without build.rs + icon.ico, `tauri dev` / `tauri build` cannot compile on Windows.
  const buildRs = fs.readFileSync('src-tauri/build.rs', 'utf8');
  assert.match(buildRs, /app_manifest\(include_str!\("app\.manifest"\)\)/);
  assert.ok(fs.statSync('src-tauri/icons/icon.ico').size > 0, 'Missing src-tauri/icons/icon.ico');

  // A custom manifest replaces Tauri's default, so it must keep the Common Controls v6 dependency.
  const manifestXml = fs.readFileSync('src-tauri/app.manifest', 'utf8');
  assert.match(manifestXml, /Microsoft\.Windows\.Common-Controls/);

  // Reproducible builds: pin both the npm and Cargo dependency trees.
  assert.ok(fs.existsSync('package-lock.json'), 'Missing package-lock.json');
  assert.ok(fs.existsSync('src-tauri/Cargo.lock'), 'Missing src-tauri/Cargo.lock');
});
