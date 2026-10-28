import { afterEach, describe, expect, it, vi } from 'vitest';
import { assignUeProfileScenario } from './profileApi';

describe('UE scenario assignment contract', () => {
  afterEach(() => vi.restoreAllMocks());

  it('sends only scenario metadata through PATCH', async () => {
    let request: { url: string; init?: RequestInit } | undefined;
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      request = { url: String(input), init };
      return new Response(
        JSON.stringify({ ue_id: 'UE-201', scenario_id: 'wait-only', subscription_status: 'VERIFIED' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;

    await assignUeProfileScenario('UE-201', {
      scenario_id: 'wait-only',
      auto_run_scenario: false,
    });

    expect(request?.url).toContain('/polaris-api/v1/ue-profiles/UE-201/scenario');
    expect(request?.init?.method).toBe('PATCH');
    expect(JSON.parse(String(request?.init?.body))).toEqual({
      scenario_id: 'wait-only',
      auto_run_scenario: false,
    });
    expect(String(request?.init?.body)).not.toMatch(/imsi|supi|authentication|opc|dnn/i);
  });
});
