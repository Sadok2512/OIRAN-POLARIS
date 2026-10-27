import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '@/test/testUtils';
import { OverviewPage } from './Overview';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('Overview', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows empty states when every backend returns zero items', async () => {
    globalThis.fetch = vi.fn(async () =>
      respond(200, { data: [], meta: {} }),
    ) as unknown as typeof fetch;
    render(renderWithProviders(<OverviewPage />));
    expect(await screen.findByTestId('page-header')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getAllByTestId('empty-state').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('reports an unavailable storage state when filesystem data is missing', async () => {
    globalThis.fetch = vi.fn(async (input) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/storage/safety')) {
        return respond(200, {
          data: {
            filesystem: null,
            decision: {
              state: 'UNKNOWN',
              new_capture_allowed: false,
              active_capture_must_finalize: false,
              read_only_analysis_allowed: true,
              reason: 'no measurement',
            },
            budget: {
              allowed: false,
              requested_bytes: 0,
              maximum_allowed_bytes: 0,
              headroom_to_stop_bytes: 0,
              reserved_bytes: 0,
              reason: 'no measurement',
            },
            rotation: {
              max_file_bytes: 0,
              max_files: 0,
              maximum_job_bytes: 0,
              max_job_seconds: 0,
            },
            policy: {
              information_percent: 0,
              warning_percent: 0,
              stop_percent: 0,
              hard_limit_percent: 0,
              polling_interval_ms: 0,
            },
            capture_job: { state: 'UNKNOWN', active: false, writes_enabled: false },
            monitoring: {
              poll_interval_ms: 0,
              event_driven_limit: 'none',
              failure_mode: 'none',
            },
          },
          meta: {},
        });
      }
      return respond(200, { data: [], meta: {} });
    }) as unknown as typeof fetch;

    render(renderWithProviders(<OverviewPage />));
    await waitFor(() =>
      expect(screen.getByTestId('unavailable-state')).toBeInTheDocument(),
    );
  });
});
