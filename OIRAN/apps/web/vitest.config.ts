import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: true,
    // 2.5.0 — Playwright anti-overlap matrix lives under e2e-2.4.0/ and is
    // driven by playwright-2.4.0.config.ts; vitest must not try to execute
    // those specs (they import @playwright/test).
    exclude: ['node_modules', 'dist', 'e2e-2.4.0/**'],
  },
});
