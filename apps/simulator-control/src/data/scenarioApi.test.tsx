import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactNode } from 'react';
import { useScenarioSteps, useScenarioDefinitions } from './scenarioApi';
import { _resetFlags, setFlag } from './featureFlags';

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const calls: string[] = [];

function stubFetch() {
  calls.length = 0;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push(url);
    if (url.endsWith('/scenario-definitions')) {
      return respond(200, {
        data: [
          {
            id: 'scn-be-1',
            name: 'from-backend',
            version: 1,
            steps: [
              {
                type: 'udp_traffic',
                loop_count: 1,
                parameters: { duration_ms: { random: { min: 10, max: 20 } } },
              },
            ],
          },
        ],
        meta: {},
      });
    }
    if (url.includes('/scenarios/') && url.endsWith('/steps')) {
      return respond(200, {
        data: [
          {
            index: 0,
            type: 'udp_traffic',
            loop: 1,
            state: 'RUNNING',
            started_at: '2026-10-28T10:00:00Z',
            ended_at: null,
            error: null,
            resolved_parameters: { duration_ms: 15 },
          },
        ],
        meta: {},
      });
    }
    return respond(404, { error: 'not stubbed' });
  }) as unknown as typeof fetch;
}

function withClient(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  if (typeof localStorage !== 'undefined') localStorage.clear();
  _resetFlags();
  stubFetch();
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

describe('scenarioApi — flag gating', () => {
  it('does NOT call /scenario-definitions when scenarioBackend flag is off', async () => {
    const { result } = renderHook(() => useScenarioDefinitions(), {
      wrapper: ({ children }) => withClient(children),
    });
    // Give the query a tick; it should remain disabled.
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(result.current.fetchStatus).toBe('idle');
    expect(calls.find((url) => url.includes('/scenario-definitions'))).toBeUndefined();
  });

  it('calls /scenario-definitions when the flag is on and parses the body', async () => {
    setFlag('scenarioBackend', true);
    const { result } = renderHook(() => useScenarioDefinitions(), {
      wrapper: ({ children }) => withClient(children),
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.[0].name).toBe('from-backend');
    expect(calls.some((url) => url.includes('/scenario-definitions'))).toBe(true);
  });

  it('fetches /scenarios/:job_id/steps and exposes resolved_parameters', async () => {
    setFlag('scenarioBackend', true);
    const { result } = renderHook(() => useScenarioSteps('job-42'), {
      wrapper: ({ children }) => withClient(children),
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.[0]).toMatchObject({
      index: 0,
      type: 'udp_traffic',
      state: 'RUNNING',
      resolved_parameters: { duration_ms: 15 },
    });
  });

  it('does NOT fetch /steps when jobId is null (even with flag on)', async () => {
    setFlag('scenarioBackend', true);
    const { result } = renderHook(() => useScenarioSteps(null), {
      wrapper: ({ children }) => withClient(children),
    });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(result.current.fetchStatus).toBe('idle');
    expect(calls.find((url) => url.includes('/steps'))).toBeUndefined();
  });
});
