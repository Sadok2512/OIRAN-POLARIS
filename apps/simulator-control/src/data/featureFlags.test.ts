// 0.9.2 — regression tests for the `polarisProvisioning` default flip and
// the one-shot localStorage migration.

import { afterEach, describe, expect, it } from 'vitest';
import { migrateStoredFlags, _resetFlags } from './featureFlags';

const FLAGS_KEY = 'polaris.featureFlags.v1';

describe('featureFlags migration (0.9.2 schema v2)', () => {
  afterEach(() => {
    localStorage.removeItem(FLAGS_KEY);
    _resetFlags();
  });

  it('flips polarisProvisioning OFF → ON when the stored payload is pre-0.9.2 (no _v)', () => {
    const legacy = {
      scenarioBackend: true,
      profileBackend: false,
      scenarioTemplates: true,
      polarisProvisioning: false,
    };
    const migrated = migrateStoredFlags(legacy);
    expect(migrated.polarisProvisioning).toBe(true);
    // Other flags stay as-is.
    expect(migrated.scenarioBackend).toBe(true);
    expect(migrated.scenarioTemplates).toBe(true);
    expect(migrated.profileBackend).toBe(false);
  });

  it('preserves polarisProvisioning OFF when the operator explicitly disabled it (_v>=2)', () => {
    const explicitlyOff = {
      _v: 2,
      scenarioBackend: true,
      profileBackend: false,
      scenarioTemplates: true,
      polarisProvisioning: false,
    };
    const migrated = migrateStoredFlags(explicitlyOff);
    expect(migrated.polarisProvisioning).toBe(false);
  });

  it('preserves polarisProvisioning ON when it was already ON before 0.9.2', () => {
    const legacyOn = {
      scenarioBackend: true,
      profileBackend: false,
      scenarioTemplates: true,
      polarisProvisioning: true,
    };
    const migrated = migrateStoredFlags(legacyOn);
    expect(migrated.polarisProvisioning).toBe(true);
  });

  it('defaults polarisProvisioning to ON when the stored payload omits it', () => {
    const partial = { _v: 2, scenarioBackend: true };
    const migrated = migrateStoredFlags(partial);
    expect(migrated.polarisProvisioning).toBe(true);
  });

  it('ignores an unknown _v and still forces the pre-0.9.2 OFF → ON migration', () => {
    const unknownVersion = { _v: 1, polarisProvisioning: false };
    const migrated = migrateStoredFlags(unknownVersion);
    expect(migrated.polarisProvisioning).toBe(true);
  });
});
