import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('operational backend contracts', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.resetModules();
  });

  it('enables every deployed backend contract in a fresh browser', async () => {
    const { getFlags } = await import('./featureFlags');

    expect(getFlags()).toEqual({
      scenarioBackend: true,
      profileBackend: true,
      scenarioTemplates: true,
      polarisProvisioning: true,
    });
  });

  it('forces legacy v1 OFF values ON during migration', async () => {
    localStorage.setItem(
      'polaris.featureFlags.v1',
      JSON.stringify({
        scenarioBackend: false,
        profileBackend: false,
        scenarioTemplates: false,
        polarisProvisioning: false,
      }),
    );

    const { getFlags } = await import('./featureFlags');
    const expected = {
      scenarioBackend: true,
      profileBackend: true,
      scenarioTemplates: true,
      polarisProvisioning: true,
    };
    expect(getFlags()).toEqual(expected);
    expect(JSON.parse(localStorage.getItem('polaris.featureFlags.v3') ?? '{}')).toEqual(expected);
  });

  it('allows the test harness to cover unreachable legacy branches', async () => {
    localStorage.setItem(
      'polaris.featureFlags.v3',
      JSON.stringify({
        scenarioBackend: false,
        profileBackend: false,
        scenarioTemplates: false,
        polarisProvisioning: false,
      }),
    );

    const { getFlags, setFlag } = await import('./featureFlags');
    setFlag('profileBackend', false);
    setFlag('scenarioBackend', false);

    expect(getFlags().profileBackend).toBe(false);
    expect(getFlags().scenarioBackend).toBe(false);
  });
});
