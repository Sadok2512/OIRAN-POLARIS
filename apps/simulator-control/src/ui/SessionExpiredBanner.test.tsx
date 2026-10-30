// 0.10.1 — Session expiry banner tests.
//
// Covers the regression called out at 0.10.0 release: the reconnect
// target was `/polaris-api/v1/auth/login` (a POST-only API path, 405 on
// GET). The banner must now point at the SPA Settings route, which is
// where `operator-login-form` is rendered.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

// Mock the auth hook so we drive the banner deterministically without
// having to simulate react-query refetch intervals.
const authState: {
  data: { authenticated: boolean } | null;
  error: Error | null;
} = { data: null, error: null };

vi.mock('@/data/queries', () => ({
  useAuth: () => ({ data: authState.data, error: authState.error }),
}));

import { SessionExpiredBanner } from './SessionExpiredBanner';

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="*"
          element={
            <>
              <SessionExpiredBanner />
              <div data-testid="here">at {path}</div>
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  authState.data = null;
  authState.error = null;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('SessionExpiredBanner (0.10.1)', () => {
  it('stays hidden while the session is live', () => {
    authState.data = { authenticated: true };
    renderAt('/ues');
    expect(screen.queryByTestId('session-expired-banner')).toBeNull();
  });

  it('stays hidden on the very first unauth check (never signed in)', () => {
    authState.data = { authenticated: false };
    renderAt('/ues');
    expect(screen.queryByTestId('session-expired-banner')).toBeNull();
  });

  it('renders the reconnect button as a react-router Link to /settings once auth flips', () => {
    authState.data = { authenticated: true };
    const { rerender } = renderAt('/ues');
    // Flip auth to false and rerender the SAME component tree so the
    // internal `wasAuthenticated` ref carries over and the effect
    // promotes the banner to visible.
    authState.data = { authenticated: false };
    rerender(
      <MemoryRouter initialEntries={['/ues']}>
        <Routes>
          <Route
            path="*"
            element={
              <>
                <SessionExpiredBanner />
                <div data-testid="here">at /ues</div>
              </>
            }
          />
        </Routes>
      </MemoryRouter>,
    );
    const link = screen.getByTestId('session-expired-reconnect');
    expect(link.tagName).toBe('A');
    expect(link.getAttribute('href')).toBe('/settings');
    expect(link.getAttribute('href')).not.toMatch(/polaris-api/);
  });

  it('hides the reconnect link when already on /settings', () => {
    authState.data = { authenticated: true };
    const { rerender } = renderAt('/settings');
    authState.data = { authenticated: false };
    rerender(
      <MemoryRouter initialEntries={['/settings']}>
        <Routes>
          <Route
            path="*"
            element={
              <>
                <SessionExpiredBanner />
                <div data-testid="here">at /settings</div>
              </>
            }
          />
        </Routes>
      </MemoryRouter>,
    );
    expect(screen.getByTestId('session-expired-banner')).toBeInTheDocument();
    expect(screen.queryByTestId('session-expired-reconnect')).toBeNull();
  });
});
