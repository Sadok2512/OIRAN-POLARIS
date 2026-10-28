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
      // Raw body of GET /api/v1/scenario-definitions (polaris-control-api 0.10.0, lib.rs
      // list_scenario_definitions): { items, total, schema_version } — no {data, meta}.
      return respond(200, {
        items: [
          {
            created_at_epoch_s: 1793186621,
            id: 'scenario-contract',
            loop_count: 2,
            name: 'Contract scenario',
            steps: [{ loop_count: 2, parameters: { duration_ms: { fixed: 5 } }, type: 'wait' }],
            updated_at_epoch_s: 1793186621,
            version: 1,
          },
        ],
        total: 1,
        schema_version: 1,
      });
    }
    if (url.includes('/scenarios/') && url.endsWith('/steps')) {
      // Copied from scenario-definitions.contract.md (measured /steps response, first element).
      return respond(200, {
        job_id: 'scenario-contract-1a98345aaa93',
        scenario_definition_id: 'scenario-contract',
        steps: [
          {
            ended_at: 1793186621,
            error: null,
            index: 0,
            resolved_parameters: { duration_ms: 5 },
            scenario_loop: { count: 2, iteration: 1 },
            started_at: 1793186621,
            state: 'COMPLETED',
            step_loop: { count: 2, iteration: 1 },
            type: 'wait',
          },
        ],
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
    expect(result.current.data?.items[0].name).toBe('Contract scenario');
    expect(result.current.data?.total).toBe(1);
    expect(calls.some((url) => url.includes('/scenario-definitions'))).toBe(true);
  });

  it('fetches /scenarios/:job_id/steps and exposes resolved_parameters', async () => {
    setFlag('scenarioBackend', true);
    const { result } = renderHook(() => useScenarioSteps('job-42'), {
      wrapper: ({ children }) => withClient(children),
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.job_id).toBe('scenario-contract-1a98345aaa93');
    expect(result.current.data?.steps[0]).toMatchObject({
      index: 0,
      type: 'wait',
      state: 'COMPLETED',
      scenario_loop: { count: 2, iteration: 1 },
      step_loop: { count: 2, iteration: 1 },
      resolved_parameters: { duration_ms: 5 },
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
