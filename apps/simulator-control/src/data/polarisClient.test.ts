import { afterEach, describe, expect, it, vi } from 'vitest';
import { isApiError } from '@shared/api';
import { polarisApi, unwrapPolarisBody } from './polarisClient';

function respond(status: number, body: unknown) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  );
}

afterEach(() => vi.restoreAllMocks());

describe('polarisClient — real POLARIS wire shapes', () => {
  it('returns the RAW body POLARIS actually sends (no {data, meta} envelope)', async () => {
    // Captured from polaris-control-api 0.11.0: GET /api/v1/gnbs
    const raw = { items: [{ gnb_id: 'GNB-01', link_ip: '10.77.0.20' }], source: 'LAB_DEFAULT', total: 1 };
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => respond(200, raw));
    const body = await polarisApi<typeof raw>('/gnbs');
    expect(body).toEqual(raw);
    expect(body.items[0].gnb_id).toBe('GNB-01');
  });

  it('still unwraps an OIRAN-style {data, meta} envelope', () => {
    expect(unwrapPolarisBody({ data: { a: 1 }, meta: {} })).toEqual({ a: 1 });
  });

  it('does not unwrap a raw body that merely contains a data field among others', () => {
    const raw = { data: 1, meta: 2, total: 3 };
    expect(unwrapPolarisBody(raw)).toEqual(raw);
  });

  it('keeps the POLARIS error code from {"error":"CODE"}', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      respond(422, { error: 'UNKNOWN_SERVING_GNB' }),
    );
    const failure: unknown = await polarisApi('/ue-profiles', { method: 'POST', body: '{}' }).catch((e: unknown) => e);
    if (!isApiError(failure)) throw new Error('expected ApiError');
    expect(failure.status).toBe(422);
    expect(failure.code).toBe('UNKNOWN_SERVING_GNB');
  });
});
