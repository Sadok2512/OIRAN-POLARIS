import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactNode } from 'react';
import { _resetFlags, setFlag } from '@/data/featureFlags';
import { cloneTargetId, useScenarioLibrary } from './library';
import { emptyScenario, newStepId, type Scenario } from './model';

interface Call {
  method: string;
  url: string;
  body: unknown;
}
const calls: Call[] = [];

// Bodies below follow polaris-control-api 0.10.0 (lib.rs handlers): raw JSON, no envelope.
const existing = {
  created_at_epoch_s: 1793186621,
  id: 'scenario-contract',
  loop_count: 2,
  name: 'Contract scenario',
  steps: [{ loop_count: 1, parameters: { duration_s: { fixed: 5 } }, type: 'wait' }],
  updated_at_epoch_s: 1793186621,
  version: 1,
};

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

beforeEach(() => {
  localStorage.clear();
  _resetFlags();
  calls.length = 0;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ method, url, body });
    if (method === 'GET' && url.endsWith('/scenario-definitions')) {
      return respond(200, { items: [existing], total: 1, schema_version: 1 });
    }
    if (method === 'POST' && url.endsWith('/scenario-definitions')) {
      return respond(201, { ...body, version: 1, created_at_epoch_s: 1, updated_at_epoch_s: 1 });
    }
    if (method === 'PUT') {
      return respond(200, { ...body, version: 2, created_at_epoch_s: 1, updated_at_epoch_s: 2 });
    }
    if (method === 'POST' && url.endsWith('/clone')) {
      return respond(201, { ...existing, id: body.target_id, version: 1 });
    }
    if (method === 'DELETE') return respond(200, { deleted: 'scenario-contract' });
    return respond(404, { error: 'NOT_STUBBED' });
  }) as unknown as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetFlags();
});

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

function oneStep(id: string, loop: Scenario['loop']): Scenario {
  const scenario = emptyScenario('New one');
  scenario.id = id;
  scenario.loop = loop;
  scenario.steps = [{ id: newStepId(), kind: 'WAIT', params: { duration_s: { mode: 'fixed', value: 3 } } }];
  return scenario;
}

describe('useScenarioLibrary — backend mode', () => {
  it('lists decoded backend definitions', async () => {
    setFlag('scenarioBackend', true);
    const { result } = renderHook(() => useScenarioLibrary(), { wrapper });
    await waitFor(() => expect(result.current.scenarios).toHaveLength(1));
    expect(result.current.backend).toBe(true);
    expect(result.current.scenarios[0].loop).toEqual({ kind: 'FIXED', cycles: 2 });
  });

  it('creates with POST and the exact mutation body', async () => {
    setFlag('scenarioBackend', true);
    const { result } = renderHook(() => useScenarioLibrary(), { wrapper });
    await waitFor(() => expect(result.current.scenarios).toHaveLength(1));
    await act(async () => {
      await result.current.save(oneStep('scn-new-1', { kind: 'FIXED', cycles: 50 }));
    });
    const post = calls.find((call) => call.method === 'POST' && call.url.endsWith('/scenario-definitions'));
    expect(post?.body).toEqual({
      id: 'scn-new-1',
      name: 'New one',
      loop_count: 50,
      steps: [{ type: 'wait', loop_count: 1, parameters: { duration_s: { fixed: 3 } } }],
    });
  });

  it('updates an existing id with PUT', async () => {
    setFlag('scenarioBackend', true);
    const { result } = renderHook(() => useScenarioLibrary(), { wrapper });
    await waitFor(() => expect(result.current.scenarios).toHaveLength(1));
    await act(async () => {
      await result.current.save(oneStep('scenario-contract', { kind: 'ONCE' }));
    });
    expect(calls.some((call) => call.method === 'PUT' && call.url.endsWith('/scenario-definitions/scenario-contract'))).toBe(true);
  });

  it('clones with a valid target_id', async () => {
    setFlag('scenarioBackend', true);
    const { result } = renderHook(() => useScenarioLibrary(), { wrapper });
    await waitFor(() => expect(result.current.scenarios).toHaveLength(1));
    await act(async () => {
      await result.current.duplicate('scenario-contract');
    });
    const clone = calls.find((call) => call.url.endsWith('/clone'));
    expect(clone?.body).toMatchObject({ target_id: expect.stringMatching(/^[A-Za-z0-9_-]{1,64}$/) });
  });

  it('does not issue any request when the flag is off', async () => {
    // 0.5.1 — scenarioBackend defaults to ON. Explicitly flip it off here to
    // verify the offline-draft branch stays wired.
    setFlag('scenarioBackend', false);
    const { result } = renderHook(() => useScenarioLibrary(), { wrapper });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(result.current.backend).toBe(false);
    expect(calls.filter((call) => call.url.includes('/scenario-definitions'))).toHaveLength(0);
  });
});

describe('cloneTargetId', () => {
  it('stays within the backend id rule even for a 64-char source', () => {
    const id = cloneTargetId('a'.repeat(64), 123);
    expect(id.length).toBeLessThanOrEqual(64);
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});
