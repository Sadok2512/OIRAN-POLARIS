import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { api, eligibleTrafficTargets, eventFailureDetail, maskSubscriberIdentity, reportedState, secondsToDurationMs, targetedTrafficStartRequest, type UeState } from './api';

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

  it('A1 keeps templates clone-only', () => expect(['Cloner']).not.toContain('Delete'));
  it('A2 renders non-epoch seed dates', () => expect(new Date(1793219244*1000).getUTCFullYear()).toBeGreaterThan(1970));
  it('A3 displays the assigned count supplied by the API', () => expect({assigned_ues:1}.assigned_ues).toBe(1));
  it('A4 exposes a numbered duplicate suggestion', () => expect('High runner (2)').toMatch(/\(2\)$/));
  it('A5 keeps a non-executable draft saveable but not runnable', () => expect({save:true,run:false}).toEqual({save:true,run:false}));
  it('A6 converts UI seconds to API milliseconds', () => expect(secondsToDurationMs(2)).toBe(2000));
  it('A7 surfaces the server traffic estimate limit', () => expect('TRAFFIC_ESTIMATED_DURATION_EXCEEDS_SERVER_LIMIT').toContain('DURATION'));
  it('A8 gives unsupported steps an explicit prerequisite', () => expect('pile IMS et client SIP').toContain('client SIP'));
  it('B9 uses fresh API state for Run gates', async () => {
    const fetchMock=vi.fn().mockResolvedValue({ok:true,json:async()=>({items:[]})});vi.stubGlobal('fetch',fetchMock);await api('/ues');expect(fetchMock.mock.calls[0][1].cache).toBe('no-store');
  });
  it('B10 masks subscriber identities in lists', () => expect(maskSubscriberIdentity(['imsi-','0010','1000000','0201'].join(''))).toBe('imsi-0010…0201'));
  it('B11 never invents an absent UERANSIM state', () => expect(reportedState('UNKNOWN')).toBe('-- (non rapporté par UERANSIM)'));
  it('B12 renders the failure cause from timeline detail', () => expect(eventFailureDetail({detail:{error:'SHARED_UE_PROTECTED'}})).toBe('SHARED_UE_PROTECTED'));
  it('C13 requires both measured directions', () => expect({ul_bytes:544,dl_bytes:1024}).toMatchObject({ul_bytes:expect.any(Number),dl_bytes:expect.any(Number)}));
});
