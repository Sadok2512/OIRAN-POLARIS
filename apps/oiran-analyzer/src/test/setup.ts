import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

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

// ResizeObserver polyfill for React Flow in jsdom
class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}
(globalThis as unknown as { ResizeObserver: typeof ResizeObserverMock }).ResizeObserver =
  ResizeObserverMock;

// DOMRect polyfill
if (!(globalThis as any).DOMRect) {
  (globalThis as any).DOMRect = class {
    x = 0;
    y = 0;
    width = 0;
    height = 0;
    top = 0;
    left = 0;
    right = 0;
    bottom = 0;
    toJSON() {
      return {};
    }
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});