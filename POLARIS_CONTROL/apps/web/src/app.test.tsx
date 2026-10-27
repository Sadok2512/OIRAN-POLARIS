import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { api, eligibleTrafficTargets, targetedTrafficStartRequest, type UeState } from './api';

describe('POLARIS Control shell', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it('starts without browser secrets', () => {
    expect(sessionStorage.length).toBe(0);
    expect(sessionStorage.getItem('polaris-operator-credential')).toBeNull();
  });

  it('renders accessible static content', () => {
    render(<MemoryRouter><button disabled>Start live</button></MemoryRouter>);
    expect((screen.getByRole('button') as HTMLButtonElement).disabled).toBe(true);
  });

  it('restores csrf from an authenticated server session', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        authenticated: true,
        username: 'operator',
        role: 'operator',
        can_start: true,
        can_manage_permissions: false,
        csrf_token: 'restored-token',
      }),
    }));
    await api('/auth/me');
    expect(sessionStorage.getItem('polaris-csrf-token')).toBe('restored-token');
  });

  it('lists only verified controller-owned traffic targets', () => {
    const ue = (overrides: Partial<UeState>): UeState => ({
      id: 'UE-PSEUDONYM-04', internal_ue_id: 'UE-04', registration_state: 'REGISTERED',
      pdu_session: 'ACTIVE', ue_ip: '10.46.0.6', traffic_state: 'IDLE', last_event: null,
      controller_owned: true, traffic_target_verified: true, process_state: 'RUNNING',
      actions: { start: false, stop: true, pdu_start: false, pdu_stop: false, traffic: true, reason: 'READY_FOR_BOUNDED_TRAFFIC' },
      ...overrides,
    });
    const eligible = eligibleTrafficTargets([
      ue({ id: 'UE-PSEUDONYM-01', internal_ue_id: 'UE-01', controller_owned: false }),
      ue({ id: 'UE-PSEUDONYM-02', internal_ue_id: 'UE-02', pdu_session: 'INACTIVE' }),
      ue({}),
    ]);
    expect(eligible.map(item => item.internal_ue_id)).toEqual(['UE-04']);
  });

  it('builds a fixed certified scenario request without interfaces or commands', () => {
    const request = targetedTrafficStartRequest('traffic-job-04', 'UE-04');
    expect(request).toEqual({ scenario_id: 'traffic-job-04', scenario_type: 'bounded-controller-ue-udp-v1', target_ue_id: 'UE-04' });
    expect(request).not.toHaveProperty('interface');
    expect(request).not.toHaveProperty('command');
    expect(request).not.toHaveProperty('destination');
  });
});
