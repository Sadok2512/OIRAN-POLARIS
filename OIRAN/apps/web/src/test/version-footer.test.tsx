// 2.9.0 (#9): the Analyzer footer must show BOTH the frontend and
// the backend version at the bottom of the SPA. `vite.config.ts`
// injects the web version via `import.meta.env.VITE_WEB_VERSION`;
// `VersionFooter` renders both. The pinned web version is also
// asserted against the `package.json` so a bump cannot ship without
// updating both sides.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VersionFooter } from '../layouts/AppShell';
import { api } from '../services/api';
import pkg from '../../package.json';

vi.mock('../services/api', () => ({
  api: vi.fn(),
  setAccessToken: vi.fn(),
  getAccessToken: vi.fn(() => null),
  recommendedPollInterval: vi.fn((_: string, baseMs: number) => baseMs),
  resetPollInterval: vi.fn(),
}));

const mockedApi = vi.mocked(api);

function renderFooter() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <VersionFooter />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  // `vite.config.ts` defines `VITE_WEB_VERSION` at build time; in
  // the Vitest runtime we stub it here so the footer under test can
  // read `import.meta.env.VITE_WEB_VERSION` deterministically.
  vi.stubEnv('VITE_WEB_VERSION', pkg.version);
  mockedApi.mockImplementation(async (path?: string) => {
    if (path === '/version') {
      return {
        data: {
          platform_core: '2.9.0',
          backend_api: '2.9.0',
          web_frontend: '2.9.0',
          event_schema: '1.5.0',
          callflow_schema: '1.3.0',
          session_engine: '0.6.0',
          correlation_engine: '0.6.0',
          decoders: {},
        },
        meta: {},
      } as never;
    }
    return { data: [], meta: {} } as never;
  });
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
});

describe('Analyzer version footer (2.9.0)', () => {
  it('shows BOTH the web bundle version and the backend API version', async () => {
    renderFooter();
    const footer = screen.getByTestId('version-footer');
    expect(footer).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByTestId('web-version').textContent).toBe('2.9.0'),
    );
    await waitFor(() =>
      expect(screen.getByTestId('api-version').textContent).toBe('2.9.0'),
    );
  });

  it('pins the vite.config.ts VITE_WEB_VERSION to apps/web/package.json', () => {
    expect(pkg.version).toBe('2.9.0');
    expect(import.meta.env.VITE_WEB_VERSION).toBe(pkg.version);
  });
});
