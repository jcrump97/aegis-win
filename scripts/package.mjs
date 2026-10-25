#!/usr/bin/env node
/**
 * Builds the portable release exe and copies it to release/AegisWin/AegisWin.exe.
 *
 * The app keeps its vault in a `data` folder next to the exe, so this only
 * ever replaces the exe and never deletes anything else in release/AegisWin/.
 *
 *   npm run package              build, then copy
 *   npm run package -- --no-build  copy the existing target/release build
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const BUILT_EXE = path.join(rootDir, 'target', 'release', 'aegis-win.exe');
export const RELEASE_DIR = path.join(rootDir, 'release', 'AegisWin');

/** Copies `exePath` to `<outDir>/AegisWin.exe`, leaving everything else in `outDir` alone. */
export function stage(exePath, outDir) {
  if (!fs.existsSync(exePath)) {
    throw new Error(`No build at ${exePath}. Run npm run package without --no-build.`);
  }
  fs.mkdirSync(outDir, { recursive: true });
  const target = path.join(outDir, 'AegisWin.exe');
  try {
    fs.copyFileSync(exePath, target);
  } catch (err) {
    if (err.code === 'EBUSY' || err.code === 'EPERM') {
      throw new Error(`${target} is in use. Close AegisWin and run this again.`);
    }
    throw err;
  }
  return target;
}

function build() {
  // Same fallback as ci-runner: PATH may not include ~/.cargo/bin yet.
  const home = process.env.USERPROFILE || process.env.HOME || '';
  const env = { ...process.env, PATH: [process.env.PATH, path.join(home, '.cargo', 'bin')].join(path.delimiter) };
  const cli = path.join(rootDir, 'node_modules', '@tauri-apps', 'cli', 'tauri.js');
  execFileSync(process.execPath, [cli, 'build'], { cwd: rootDir, env, stdio: 'inherit' });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (!process.argv.includes('--no-build')) build();
    const target = stage(BUILT_EXE, RELEASE_DIR);
    console.log(`[AegisWin] Packaged ${path.relative(rootDir, target)}`);
  } catch (err) {
    console.error(`[AegisWin] Package failed: ${err.message}`);
    process.exit(1);
  }
}
