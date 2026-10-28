import { beforeEach, describe, expect, it } from 'vitest';
import { _reloadFlags, _resetFlags, getFlags } from './featureFlags';

describe('feature flag schema migration', () => {
  beforeEach(() => {
    localStorage.clear();
    _resetFlags();
  });

  it('migrates v1 flags to schema v2 and keeps the persistent profile backend authoritative', () => {
    localStorage.setItem(
      'polaris.featureFlags.v1',
      JSON.stringify({ profileBackend: false, polarisProvisioning: true, scenarioBackend: true }),
    );
    _reloadFlags();

    expect(getFlags().profileBackend).toBe(true);
    const stored = JSON.parse(localStorage.getItem('polaris.featureFlags.v2') ?? '{}');
    expect(stored.schemaVersion).toBe(2);
    expect(stored.flags.profileBackend).toBe(true);
  });
});
