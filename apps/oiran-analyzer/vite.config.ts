import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig({
  plugins: [react()],
  // The Analyzer is served behind the preview reverse proxy at
  // `/analyzer/` (see apps/portal/src/config/apps.ts and the capture
  // library deep-links). `base` makes Vite emit asset URLs relative to
  // that path so the bundle works untouched when served from the
  // preview.
  base: '/analyzer/',
  resolve: {
    alias: {
      '@shared': path.resolve(__dirname, '../../packages/ui/src'),
      '@oiran-polaris/ui': path.resolve(__dirname, '../../packages/ui/src'),
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 4320,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:7080',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    emptyOutDir: true,
    chunkSizeWarningLimit: 1500,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
