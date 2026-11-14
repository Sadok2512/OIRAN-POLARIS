import { describe, expect, it } from 'vitest';
import { diskMeasurementView } from './Console';
import type { SystemHealth } from '@/data/polarisTypes';

const base: SystemHealth = {
  cpu: { usage_percent: 10, logical_cpus: 4 },
  memory: { total_bytes: 100, available_bytes: 50, used_bytes: 50 },
  disk: null,
  decision: { state: 'MEASUREMENT_FAILED', writes_allowed: false, reason: 'filesystem measurement failed; writes fail closed', maximum_budget_bytes: 0 },
  load_average: '0 0 0',
  uptime_seconds: 1,
};

describe('diskMeasurementView', () => {
  it('shows the measured cause as an explicit error instead of Measuring', () => {
    expect(diskMeasurementView({ ...base, disk_measurement_error: 'permission denied' }, null)).toEqual({
      error: 'permission denied',
      usage: null,
    });
  });

  it('renders a real disk measurement when the probe succeeds', () => {
    const health = { ...base, disk: { total_bytes: 100, used_bytes: 73, available_bytes: 27, usage_percent: 73 } };
    expect(diskMeasurementView(health, null)).toEqual({ error: null, usage: '73.00 % utilisés' });
  });
});
