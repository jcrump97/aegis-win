import { defineConfig } from 'vite';

// Vite configuration tailored for Tauri v2 Portable Windows App
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
     host: '127.0.0.1',
  },
  envPrefix: ['VITE_', 'TAURI_ENV_*'],
  build: {
    target: 'chrome105',
    minify: 'esbuild',
    sourcemap: false,
    outDir: 'dist',
  },
});
