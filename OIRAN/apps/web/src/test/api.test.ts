import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, recommendedPollInterval, resetPollInterval } from '../services/api';

afterEach(() => {
  resetPollInterval('/datasets');
  resetPollInterval('/health');
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

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

  it('2.9.0: caches ETag, sends If-None-Match on re-request, returns cached body on 304', async () => {
    const etag = 'W/"abcd1234"';
    const first = new Response(JSON.stringify({ data: { count: 3 }, meta: {} }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ETag: etag },
    });
    const second = new Response(null, { status: 304, headers: { ETag: etag } });
    const fetchMock = vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(second);
    vi.stubGlobal('fetch', fetchMock);

    const firstResponse = await api<{ count: number }>('/datasets');
    expect(firstResponse.data.count).toBe(3);
    const firstHeaders = (fetchMock.mock.calls[0][1] as RequestInit).headers as Headers;
    expect(firstHeaders.has('If-None-Match')).toBe(false);

    const secondResponse = await api<{ count: number }>('/datasets');
    const secondHeaders = (fetchMock.mock.calls[1][1] as RequestInit).headers as Headers;
    expect(secondHeaders.get('If-None-Match')).toBe(etag);
    expect(secondResponse.data.count).toBe(3);
    // The second call returns the SAME cached envelope — the ETag
    // short-circuit avoids re-parsing the response body.
    expect(secondResponse).toBe(firstResponse);
  });

  it('2.9.0: recommendedPollInterval grows after a streak of 304s and resets on 200', async () => {
    const etag = 'W/"streak"';
    const change = new Response(JSON.stringify({ data: 1, meta: {} }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ETag: etag },
    });
    const notModified = () => new Response(null, { status: 304, headers: { ETag: etag } });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(change)
      .mockResolvedValueOnce(notModified())
      .mockResolvedValueOnce(notModified())
      .mockResolvedValueOnce(notModified())
      .mockResolvedValueOnce(notModified())
      .mockResolvedValueOnce(change);
    vi.stubGlobal('fetch', fetchMock);

    await api('/datasets'); // 200 → streak 0
    expect(recommendedPollInterval('GET /datasets', 3000)).toBe(3000);
    await api('/datasets'); // 304 → streak 1
    await api('/datasets'); // 304 → streak 2
    await api('/datasets'); // 304 → streak 3 → factor 2
    expect(recommendedPollInterval('GET /datasets', 3000)).toBe(6000);
    await api('/datasets'); // 304 → streak 4 → factor 2 still
    expect(recommendedPollInterval('GET /datasets', 3000)).toBe(6000);
    await api('/datasets'); // 200 → streak reset
    expect(recommendedPollInterval('GET /datasets', 3000)).toBe(3000);
  });
});
