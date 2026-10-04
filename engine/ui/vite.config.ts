import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Everything is bundled. No CDN, no external font, no analytics, no telemetry:
// this has to run on a forensic workstation with the ethernet unplugged, which
// is the state such a machine should be in and the state the venue may impose
// regardless.
//
// `assetsInlineLimit: 0` keeps assets as separate files so the
// no-external-origin test can grep each emitted file individually rather than
// having to decode data URIs. `base: './'` makes every reference relative, so
// the bundle works from a file:// URL as well as from the API's static mount.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    outDir: 'dist',
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    host: '127.0.0.1',
    proxy: {
      '/devices': 'http://127.0.0.1:8787',
      '/jobs': 'http://127.0.0.1:8787',
      '/ledger': 'http://127.0.0.1:8787',
      '/reports': 'http://127.0.0.1:8787',
      '/health': 'http://127.0.0.1:8787',
    },
  },
})
