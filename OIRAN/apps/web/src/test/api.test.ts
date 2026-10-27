import { describe, expect, it, vi } from 'vitest';
import { api } from '../services/api';

describe('typed API client', () => {
  it('uses public read-only access and returns an envelope', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: { source_events: 54 } }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const response = await api<{ source_events: number }>('/health');
    expect(response.data.source_events).toBe(54);
    expect((fetchMock.mock.calls[0][1] as RequestInit).headers).toBeInstanceOf(Headers);
    expect(((fetchMock.mock.calls[0][1] as RequestInit).headers as Headers).has('Authorization')).toBe(false);
  });

  it('surfaces a controlled backend error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'SESSION_NOT_FOUND', message: 'unknown session id' } }), { status: 404, headers: { 'Content-Type': 'application/json' } })));
    await expect(api('/sessions/not-real')).rejects.toMatchObject({ status: 404, code: 'SESSION_NOT_FOUND' });
  });
});
