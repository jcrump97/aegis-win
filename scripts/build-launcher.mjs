#!/usr/bin/env node
/**
 * Rebuilds the one-click launcher and copies it to the repository root as `Start AegisWin.exe`.
 * The exe is committed so a fresh clone can run it before Rust or Node.js are installed,
 * so run this (and commit the result) whenever launcher/ changes.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = path.join(rootDir, 'launcher', 'Cargo.toml');
const built = path.join(rootDir, 'launcher', 'target', 'release', 'aegis-launcher.exe');
const dest = path.join(rootDir, 'Start AegisWin.exe');

execFileSync('cargo', ['build', '--release', '--locked', '--manifest-path', manifest], { stdio: 'inherit' });
fs.copyFileSync(built, dest);
console.log(`[build-launcher] ${path.relative(rootDir, dest)} (${Math.round(fs.statSync(dest).size / 1024)} KB)`);
