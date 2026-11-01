import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LteControlPanel } from './LteControlPanel';

const startMutate = vi.fn();
const prepareMutate = vi.fn();
const activateMutate = vi.fn();
const emergencyMutate = vi.fn();
const stopMutate = vi.fn();

vi.mock('@/data/queries', () => ({
  useAuth: () => ({ data: { can_start: true } }),
  useLteAction: () => ({ mutate: stopMutate, isPending: false, error: null }),
  useLteLogs: () => ({ data: { lines: [] } }),
  useLteProfile: () => ({ data: {
    enabled: false,
    permanent_enabled: false,
    temporary_activation_active: false,
    temporary_activation_state: 'INACTIVE',
    temporary_activation_grant_id: null,
    temporary_activation_expires_at_epoch_ms: null,
    temporary_activation_remaining_seconds: null,
    grant_required: true,
    revision: 1,
    configuration_sha256: 'a'.repeat(64),
    compose_model_sha256: 'c'.repeat(64),
    scenario_id: 'lte-e2e-certification-v1',
    scenario_revision: 1,
    scenario_sha256: 'b'.repeat(64),
  } }),
  useLteStatus: () => ({ data: {
    operation_mode: 'CERTIFICATION_RUN',
    certification_state: 'CERTIFICATION_PENDING',
    certification_run_enabled: true,
    certified: false,
    live_enabled: true,
    safety_ready: true,
    grant_active: false,
    ownership_verified: true,
    ue_id: 'LTE-SRSUE-TEST-01',
    attach_state: 'UNKNOWN',
    s1_state: 'UNKNOWN',
    apn: 'UNKNOWN',
    ue_ip: null,
    session_state: 'UNKNOWN',
    active_sessions: 0,
    epc: { process_state: 'running', controller_owned: false },
    enb: { process_state: 'stopped', controller_owned: true },
    ue: { process_state: 'stopped', controller_owned: true },
  } }),
}));

vi.mock('@/data/liveGrantApi', () => ({
  formatCountdown: () => '00:00',
  usePrepareLteCertificationGrant: () => ({ mutate: prepareMutate, isPending: false, error: null, data: undefined }),
  useActivateLteCertification: () => ({ mutate: activateMutate, isPending: false, error: null, data: undefined }),
  useStartLteCertifiedRun: () => ({ mutate: startMutate, isPending: false, error: null, data: undefined }),
  useLteRun: () => ({ data: undefined }),
  useEmergencyStopLteRun: () => ({ mutate: emergencyMutate, isPending: false, error: null }),
}));

describe('LTE certification gate control', () => {
  beforeEach(() => vi.clearAllMocks());

  it('requires a prepared Grant V2 before Operator temporary activation', () => {
    render(<LteControlPanel compact />);
    expect(screen.getByTestId('lte-certification-state')).toHaveTextContent('CERTIFICATION PENDING');
    const prepare = screen.getByTestId('lte-prepare-grant');
    const authorize = screen.getByTestId('lte-authorize-certification');
    const start = screen.getByTestId('lte-enb-start');
    expect(prepare).toBeEnabled();
    expect(authorize).toBeDisabled();
    expect(start).toBeDisabled();
    fireEvent.click(prepare);
    expect(prepareMutate).toHaveBeenCalledWith(expect.objectContaining({
      purpose: 'CERTIFICATION_RUN',
      revision: 1,
      scenario_id: 'lte-e2e-certification-v1',
    }));
    expect(screen.getByText(/never promote themselves/)).toBeInTheDocument();
  });
});
