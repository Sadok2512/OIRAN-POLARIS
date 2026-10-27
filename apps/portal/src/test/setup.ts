import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

// matchMedia polyfill for jsdom (must run at module import time, before any
// component code calls useTheme).
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  configurable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

if (!('performance' in globalThis)) {
  (globalThis as unknown as { performance: Performance }).performance = {
    now: () => Date.now(),
  } as Performance;
}
