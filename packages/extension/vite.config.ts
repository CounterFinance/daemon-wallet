import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// MV3 build.
//
// The popup (index.html + React) is bundled by Vite. The three extension
// scripts - background.js, content.js, inpage.js - and manifest.json live in
// public/ and are copied verbatim to dist/, so they stay plain classic scripts
// that load in a service worker / content-script context without bundling.
//
// base: './' keeps the popup's asset URLs relative so they resolve under
// chrome-extension://<id>/ when loaded unpacked.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: 'index.html',
      },
    },
  },
  publicDir: 'public',
})
