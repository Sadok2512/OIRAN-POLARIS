import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderHook, waitFor } from '@testing-library/react';
import { createElement } from 'react';
import { useSessionCorrelations, usePackets } from './queries';

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const calls: string[] = [];

function stub(responder: (url: string) => Response) {
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push(url);
    return responder(url);
  }) as unknown as typeof fetch;
}

function wrap() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) =>
    createElement(QueryClientProvider, { client, children });
}

beforeEach(() => {
  calls.length = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('useSessionCorrelations — handles the real backend envelope', () => {
  it('extracts { status, edges } when the backend returns the envelope object', async () => {
    stub(() =>
      respond({
        data: {
          status: { N2_N4: 'STRONG', E2E: 'EXACT' },
          edges: [
            {
              edge_id: 'e-1',
              source_event_id: 's',
              target_event_id: 't',
              source_interface: 'N4',
              target_interface: 'N3',
              matching_identifiers: ['TEID'],
              rule_id: 'r',
              rule_version: '1',
              evidence_description: '',
              packet_references: [],
              confidence: 'EXACT',
            },
          ],
        },
        meta: {},
      }),
    );
    const { result } = renderHook(() => useSessionCorrelations('s-1'), {
      wrapper: wrap(),
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.edges).toHaveLength(1);
    expect(result.current.data?.status.E2E).toBe('EXACT');
  });

  it('accepts the legacy bare-array shape without crashing', async () => {
    stub(() =>
      respond({
        data: [
          {
            edge_id: 'e-legacy',
            source_event_id: 's',
            target_event_id: 't',
            source_interface: 'N4',
            target_interface: 'N3',
            matching_identifiers: [],
            rule_id: 'r',
            rule_version: '1',
            evidence_description: '',
            packet_references: [],
            confidence: 'STRONG',
          },
        ],
        meta: {},
      }),
    );
    const { result } = renderHook(() => useSessionCorrelations('s-2'), {
      wrapper: wrap(),
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.edges).toHaveLength(1);
    expect(result.current.data?.status).toEqual({});
  });
});

describe('usePackets — only forwards backend-supported query params', () => {
  it('includes capture_id, event_id, interface and protocol but NOT session_id', async () => {
    stub(() =>
      respond({ data: [], meta: { total: 0, total_pages: 1 } }),
    );
    const { result } = renderHook(
      () =>
        usePackets({
          page: 1,
          pageSize: 25,
          captureId: 'cap-1',
          eventId: 'ev-1',
          interface: 'N3',
          protocol: 'GTP-U',
        }),
      { wrapper: wrap() },
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const url = calls[0];
    expect(url).toContain('capture_id=cap-1');
    expect(url).toContain('event_id=ev-1');
    expect(url).toContain('interface=N3');
    expect(url).toContain('protocol=GTP-U');
    expect(url).not.toContain('session_id');
  });
});
