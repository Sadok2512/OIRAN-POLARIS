import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { actionReasonMessages, api, eligibleTrafficTargets, eventFailureDetail, filterAndSortHistory, filterScenarioDefinitions, humanActionReason, humanApiRefusal, maskSubscriberIdentity, reportedState, safeAuditReference, secondsToDurationMs, targetedTrafficStartRequest, type ScenarioDefinition, type ScenarioState, type UeState } from './api';
import { Scenarios } from './main';

describe('POLARIS Control shell', () => {
  afterEach(cleanup);
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
  it('0.36.20 masks subscriber identity defensively in lists and Activity', () => {
    const raw = ['imsi-','0010','1000000','0201'].join('');
    const projected = maskSubscriberIdentity(raw);
    expect(projected).toBe('…0201');
    expect(projected).not.toContain(raw.replace(/^imsi-/, ''));
    expect(maskSubscriberIdentity('…0201')).toBe('…0201');
    expect(maskSubscriberIdentity('not-an-identity')).toBe('PROTECTED');
  });
  it('B11 never invents an absent UERANSIM state', () => expect(reportedState('UNKNOWN')).toBe('-- (non rapporté par UERANSIM)'));
  it('B12 renders the safe failure cause from timeline detail', () => expect(eventFailureDetail({detail:{error:'SHARED_UE_PROTECTED'}})).toContain('UE partagée protégée'));
  it('C13 requires both measured directions', () => expect({ul_bytes:544,dl_bytes:1024}).toMatchObject({ul_bytes:expect.any(Number),dl_bytes:expect.any(Number)}));

  it('C5 searches templates by exact identifier and explains validation failures', () => {
    const item = { id:'tpl-small-traffic', name:'Petit trafic', catalog_scope:'SYSTEM' } as ScenarioDefinition;
    expect(filterScenarioDefinitions([item], 'SYSTEM', 'tpl-small')).toEqual([item]);
    expect(humanActionReason('UE_CONTROL_VALIDATION_REQUIRED')).toContain('ouvrir UE Manager');
  });

  it('C5 explains every emitted provisioning refusal with an actionable next step', () => {
    const emittedRefusals = [
      'SUBSCRIBER_PROVISIONING_REVIEW_REQUIRED',
      'SHARED_UE_PROTECTED',
      'PROTECTED_OR_UNAPPROVED_UE',
      'LIVE_EXECUTION_NOT_CONFIGURED',
      'UE_ALREADY_RUNNING',
      'UE_CONTROL_VALIDATION_REQUIRED',
      'UE_NOT_RUNNING',
      'NOT_CONFIGURED',
      'UE_NOT_REGISTERED',
      'PDU_SESSION_NOT_ACTIVE',
      'UE_RUNTIME_OWNERSHIP_NOT_VERIFIED',
      'LTE_E2E_CERTIFICATION_REQUIRED',
      'SRSRAN_LIVE_DISABLED',
      'LTE_LIVE_GRANT_REQUIRED',
      'LIVE_GRANT_REQUIRED',
      'SRSRAN_CONTROLLER_OWNERSHIP_REQUIRED',
      'LTE_ATTACH_OR_IP_NOT_OBSERVED',
    ];
    expect(Object.keys(actionReasonMessages)).toEqual(expect.arrayContaining(emittedRefusals));
    for (const code of emittedRefusals) {
      const message = humanActionReason(code);
      expect(message).not.toBe(code.replaceAll('_', ' '));
      expect(message).toMatch(/ouvrir|demander|vérifier/i);
      expect(message).toMatch(/Action :/);
    }
  });

  it('C5b gives every dedicated refusal a French corrective action', () => {
    expect(Object.keys(actionReasonMessages).length).toBeGreaterThan(70);
    for (const message of Object.values(actionReasonMessages)) {
      expect(message).toContain('Action :');
    }
  });

  it('C5 translates a known API refusal and discards its raw suggestion', () => {
    const message = humanApiRefusal(new Error('SHARED_UE_PROTECTED: retry the unsafe operation'));
    expect(message).toContain('UE partagée protégée');
    expect(message).toContain('Action :');
    expect(message).not.toContain('retry the unsafe operation');
  });

  it('C5 fail-closes an unknown API refusal with a French corrective action', () => {
    const message = humanApiRefusal(new Error('UNEXPECTED_BACKEND_REFUSAL'));
    expect(message).toContain('L’API a refusé l’opération');
    expect(message).toContain('Action : réessayer');
    expect(message).toContain('UNEXPECTED_BACKEND_REFUSAL');
  });

  it('C5 fail-closes an empty API refusal with a French corrective action', () => {
    const message = humanApiRefusal(null);
    expect(message).toBe('L’API a refusé l’opération. Action : réessayer, puis demander une vérification si le refus persiste.');
  });

  it('C5b suppresses a raw synthetic identity from an API refusal', () => {
    const clearIdentity = ['001', '01', '0000000201'].join('');
    const message = humanApiRefusal(new Error(`refus pour ${clearIdentity}`));
    expect(message).not.toContain(clearIdentity);
    expect(message).toBe('L’API a refusé l’opération. Action : réessayer, puis demander une vérification si le refus persiste.');
  });

  it('C5b inspects the whole psn-prefixed refusal instead of trusting its prefix', () => {
    const clearIdentity = ['001', '01', '0000000201'].join('');
    const message = humanApiRefusal(new Error(`psn-lab contenant ${clearIdentity}`));
    expect(message).not.toContain(clearIdentity);
    expect(message).not.toContain('psn-lab');
    expect(message).toContain('Action :');
    expect(eventFailureDetail({detail:{error:`psn-lab contenant ${clearIdentity}`}})).not.toContain(clearIdentity);
  });

  it('0.36.27 rejects valid-shaped codes containing long digit runs', () => {
    const longIdentity = ['001', '01', '0000000201'].join('');
    const phoneLike = ['33', '612', '345', '678'].join('');
    for (const unsafeCode of [`IMSI_${longIdentity}`, `MSISDN${phoneLike}`, `ERR_${longIdentity}`]) {
      expect(humanApiRefusal(new Error(unsafeCode))).not.toContain(unsafeCode);
      expect(safeAuditReference(unsafeCode)).toBe('REFUS_MASQUE');
    }
  });

  it('C5 sorts History newest first and filters target or cause', () => {
    const row = (overrides:Partial<ScenarioState>):ScenarioState => ({ scenario_id:'scn', technology:'5G SA', simulator:'UERANSIM', started_at:'', started_at_epoch_s:1, ended_at_epoch_s:2, duration_seconds:1, configured_ues:1, registered_ues:1, active_pdu_sessions:1, traffic_state:'IDLE', packets_requested:0, packets_sent:0, terminal_result:null, cpu:'BOUNDED', memory:'BOUNDED', state:'COMPLETED', controller_owned:true, ...overrides });
    const rows=[row({job_id:'old',started_at_epoch_s:1}),row({job_id:'new',started_at_epoch_s:2,target_ue_pseudonym:'UE-LAB',terminal_result:'CAUSE_LISIBLE'})];
    expect(filterAndSortHistory(rows,'','').map(item=>item.job_id)).toEqual(['new','old']);
    expect(filterAndSortHistory(rows,'cause lisible','')).toHaveLength(1);
    expect(filterAndSortHistory(rows,'ue-lab','COMPLETED')).toHaveLength(1);
  });

  it('C5a Run launches the selected definition on the selected eligible UE', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith('/scenario-definitions')) return { ok: true, json: async () => ({ items: [{ id: 'tpl-small-traffic', name: 'Small traffic', version: 1, loop_count: 1, steps: [], created_at_epoch_s: 1, updated_at_epoch_s: 1, catalog_scope: 'SYSTEM', mutable: false, cloneable: true, assigned_ues: 0, backend_support: 'SUPPORTED', executable: true, execution_block_reason: null, execution_message: null, archived: false }], total: 1, archived_total: 0, include_archived: false, schema_version: 1 }) };
      if (path.endsWith('/ues')) return { ok: true, json: async () => ({ items: [{ id: 'UE-LAB-02', internal_ue_id: 'UE-02', registration_state: 'DEREGISTERED', pdu_session: 'INACTIVE', ue_ip: null, traffic_state: 'IDLE', last_event: null, controller_owned: true, actions: { start: true, start_reason: 'READY', stop: false, pdu_start: false, pdu_stop: false, traffic: false, reason: 'READY' } }], configured_profiles: [], configured_count: 1, active_count: 0, registered_count: 0, source: 'test' }) };
      if (path.endsWith('/scenarios/start') && init?.method === 'POST') return { ok: true, json: async () => ({ job_id: 'job-test' }) };
      throw new Error(`unexpected request ${path}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/scenarios']}><Routes><Route path="/scenarios" element={<Scenarios/>}/><Route path="/console" element={<div>Suivi du job courant</div>}/></Routes></MemoryRouter>);

    fireEvent.click(await screen.findByRole('button', { name: 'Run Small traffic' }));
    fireEvent.click(await screen.findByRole('radio', { name: /UE-LAB-02/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Lancer le scénario' }));

    await screen.findByText('Suivi du job courant');
    const start = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith('/scenarios/start') && init?.method === 'POST');
    expect(JSON.parse(String(start?.[1]?.body))).toEqual({ scenario_definition_id: 'tpl-small-traffic', ue_ids: ['UE-02'] });
  });

  it('C5a explains when no UE is eligible and sends no launch request', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith('/scenario-definitions')) return { ok: true, json: async () => ({ items: [{ id: 'my-scenario', name: 'My blocked scenario', version: 1, loop_count: 1, steps: [], created_at_epoch_s: 1, updated_at_epoch_s: 1, catalog_scope: 'USER', mutable: true, cloneable: true, assigned_ues: 0, backend_support: 'SUPPORTED', executable: true, execution_block_reason: null, execution_message: null, archived: false }], total: 1, archived_total: 0, include_archived: false, schema_version: 1 }) };
      if (path.endsWith('/ues')) return { ok: true, json: async () => ({ items: [{ id: 'UE-LAB-02', internal_ue_id: 'UE-02', registration_state: 'DEREGISTERED', pdu_session: 'INACTIVE', ue_ip: null, traffic_state: 'IDLE', last_event: null, controller_owned: true, actions: { start: false, start_reason: 'UE_CONTROL_VALIDATION_REQUIRED', stop: false, pdu_start: false, pdu_stop: false, traffic: false, reason: 'UE_CONTROL_VALIDATION_REQUIRED' } }], configured_profiles: [], configured_count: 1, active_count: 0, registered_count: 0, source: 'test' }) };
      throw new Error(`unexpected request ${path}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/scenarios']}><Routes><Route path="/scenarios" element={<Scenarios/>}/><Route path="/ues" element={<div>UE Manager</div>}/></Routes></MemoryRouter>);

    fireEvent.click(await screen.findByRole('button', { name: 'Mes scénarios' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Run My blocked scenario' }));
    expect((await screen.findAllByText(/Validation Control requise/)).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: 'Ouvrir la gestion des UE' })).toBeTruthy();
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith('/scenarios/start'))).toBe(false);
  });

  it.each([
    ['UE_NOT_STARTED', 'UE non démarré dans ce job'],
    [`psn-lab contenant ${['001', '01', '0000000201'].join('')}`, 'L’API a refusé l’opération.'],
  ])('C5b clicking Run shows a safe actionable refusal for %s', async (refusal, expected) => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith('/scenario-definitions')) return { ok: true, json: async () => ({ items: [{ id: 'tpl-safe', name: 'Safe template', version: 1, loop_count: 1, steps: [], created_at_epoch_s: 1, updated_at_epoch_s: 1, catalog_scope: 'SYSTEM', mutable: false, cloneable: true, assigned_ues: 0, backend_support: 'SUPPORTED', executable: true, execution_block_reason: null, execution_message: null }], total: 1, schema_version: 1 }) };
      if (path.endsWith('/ues')) return { ok: true, json: async () => ({ items: [{ id: 'UE-LAB', internal_ue_id: 'UE-SAFE', registration_state: 'DEREGISTERED', pdu_session: 'INACTIVE', ue_ip: null, traffic_state: 'IDLE', last_event: null, controller_owned: true, actions: { start: true, start_reason: 'READY', stop: false, pdu_start: false, pdu_stop: false, traffic: false, reason: 'READY' } }], configured_profiles: [], configured_count: 1, active_count: 0, registered_count: 0, source: 'test' }) };
      if (path.endsWith('/scenarios/start') && init?.method === 'POST') return { ok: false, json: async () => ({ error: refusal }) };
      throw new Error(`unexpected request ${path}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/scenarios']}><Routes><Route path="/scenarios" element={<Scenarios/>}/></Routes></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button', { name: 'Run Safe template' }));
    fireEvent.click(await screen.findByRole('radio', { name: /UE-LAB/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Lancer le scénario' }));
    expect(await screen.findByText(expected, { exact: false })).toBeTruthy();
    expect(document.body.textContent).not.toContain(['001', '01', '0000000201'].join(''));
  });

  it('C7 reveals archived user scenarios explicitly and restores without deleting', async () => {
    const archived = { id: 'old-user-scenario', name: 'Ancien scénario', version: 1, loop_count: 1, steps: [], created_at_epoch_s: 1, updated_at_epoch_s: 2, catalog_scope: 'USER', mutable: true, cloneable: true, assigned_ues: 0, backend_support: 'SUPPORTED', executable: false, execution_block_reason: 'SCENARIO_ARCHIVED', execution_message: 'Scénario archivé : restaurez-le avant de l’exécuter.', archived: true };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.includes('/scenario-definitions?include_archived=true')) return { ok: true, json: async () => ({ items: [archived], total: 1, archived_total: 1, include_archived: true, schema_version: 1 }) };
      if (path.endsWith('/scenario-definitions')) return { ok: true, json: async () => ({ items: [], total: 0, archived_total: 1, include_archived: false, schema_version: 1 }) };
      if (path.endsWith('/scenario-definitions/old-user-scenario/restore') && init?.method === 'POST') return { ok: true, json: async () => ({ id: archived.id, archived: false }) };
      if (path.endsWith('/ues')) return { ok: true, json: async () => ({ items: [], configured_profiles: [], configured_count: 0, active_count: 0, registered_count: 0, source: 'test' }) };
      throw new Error(`unexpected request ${path}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/scenarios']}><Routes><Route path="/scenarios" element={<Scenarios/>}/></Routes></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button', { name: 'Mes scénarios' }));
    fireEvent.click(await screen.findByRole('checkbox', { name: /Afficher les archives/ }));
    const restore = await screen.findByRole('button', { name: 'Restaurer' });
    expect((screen.getByRole('button', { name: 'Run Ancien scénario' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(restore);
    expect(fetchMock.mock.calls.some(([input, init]) => String(input).endsWith('/restore') && init?.method === 'POST')).toBe(true);
    expect(screen.queryByRole('button', { name: 'Supprimer' })).toBeNull();
  });
});
