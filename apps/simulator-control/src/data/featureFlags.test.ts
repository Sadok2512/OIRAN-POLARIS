import { beforeEach, describe, expect, it, vi } from 'vitest';

describe('feature flag schema v2', () => {
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

  it('forces legacy v1 OFF values ON exactly once during migration', async () => {
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
    expect(JSON.parse(localStorage.getItem('polaris.featureFlags.v2') ?? '{}')).toEqual(expected);
  });
});
