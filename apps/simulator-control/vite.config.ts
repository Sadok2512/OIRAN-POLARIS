import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { demoApiPlugin } from './scripts/demoApiPlugin';

const demoMode = process.env.POLARIS_DEMO_MODE === '1';

export default defineConfig({
  // CI/audit runs can keep dependency metadata off a constrained system disk.
  cacheDir: process.env.POLARIS_SIM_VITE_CACHE_DIR,
  plugins: [react(), ...(demoMode ? [demoApiPlugin()] : [])],
  // The Simulator Control app is served behind the preview reverse proxy
  // at `/simulator/` (apps/portal links to that path).
  base: '/simulator/',
  resolve: {
    alias: {
      '@shared': path.resolve(__dirname, '../../packages/ui/src'),
      '@oiran-polaris/ui': path.resolve(__dirname, '../../packages/ui/src'),
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    host: '127.0.0.1',
    port: demoMode ? 4331 : 4330,
    strictPort: true,
    proxy: demoMode ? undefined : {
      // POLARIS Control owns `/polaris-api/v1`. Dev proxy forwards to the
      // local POLARIS backend.
      '/polaris-api': {
        target: 'http://127.0.0.1:7090',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/polaris-api\/v1/, '/api/v1'),
      },
    },
  },
  preview: {
    host: '127.0.0.1',
    port: 4331,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    emptyOutDir: true,
    chunkSizeWarningLimit: 1200,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
