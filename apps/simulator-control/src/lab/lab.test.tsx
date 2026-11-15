// 0.36.0 — simplified lab pages: pure helpers + the run flow (grant → start → « En cours »).
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { LabUesPage, rowState } from './LabUes';
import { DEFAULT_FORM, buildSteps, callScenarios, isListed, slugify } from './LabScenarios';
import { LabUeMonitorPage, lastRun, lastVoiceCall, nextSamples, rrcView, toneFor } from './LabUeMonitor';
import { needsTwoUes, stepsSummary } from './labShared';
import type { WireScenarioDefinition } from '@/scenarios/wireCodec';

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const DATA: WireScenarioDefinition = {
  id: 'simple-data-ul-dl', name: 'Données UL/DL', loop_count: 1, version: 1, rat: '5G_SA',
  backend_support: 'SUPPORTED', catalog_scope: 'USER',
  steps: [
    { type: 'ue_start', loop_count: 1, parameters: {} },
    { type: 'pdu_establish', loop_count: 1, parameters: { dnn: { fixed: 'internet' } } },
    { type: 'traffic_ul', loop_count: 1, parameters: { bytes: { fixed: 1048576 } } },
    { type: 'detach', loop_count: 1, parameters: {} },
  ],
};
const CALL: WireScenarioDefinition = { ...DATA, id: 'simple-voice-call', name: 'Appel', steps: [{ type: 'voice_call', loop_count: 1, parameters: {} }] };

describe('lab helpers', () => {
  it('builds the exact wire steps of simple-data-ul-dl', () => {
    expect(buildSteps(DEFAULT_FORM)).toEqual([
      { type: 'ue_start', loop_count: 1, parameters: {} },
      { type: 'pdu_establish', loop_count: 1, parameters: { dnn: { fixed: 'internet' } } },
      { type: 'traffic_ul', loop_count: 1, parameters: { bytes: { fixed: 1048576 } } },
      { type: 'traffic_dl', loop_count: 1, parameters: { bytes: { fixed: 1048576 } } },
      { type: 'detach', loop_count: 1, parameters: {} },
    ]);
    expect(buildSteps({ ...DEFAULT_FORM, pdu: false }).map((s) => s.type)).toEqual(['ue_start', 'detach']);
  });
  it('slugs names and filters the list', () => {
    expect(slugify('Data 5 Mo à fond')).toBe('lab-data-5-mo-a-fond');
    expect(isListed(DATA)).toBe(true);
    expect(isListed({ ...DATA, id: 'anr2-x' })).toBe(false);
    expect(isListed({ ...DATA, rat: 'LTE' })).toBe(false);
    expect(isListed({ ...DATA, backend_support: 'BACKEND_REQUIRED' })).toBe(false);
  });
  it('labels steps and detects 2-UE scenarios', () => {
    expect(stepsSummary(DATA)).toBe('Démarrer l’UE → PDU internet → Trafic UL 1.0 Mo → Détacher');
    expect(needsTwoUes(CALL)).toBe(true);
    expect(needsTwoUes(DATA)).toBe(false);
  });
  it('maps states and samples', () => {
    expect(toneFor('RRC_CONNECTED')).toBe('ok');
    expect(toneFor('DEREGISTERED')).toBe('idle');
    expect(toneFor('FAILED')).toBe('bad');
    expect(nextSamples([], { ue_id: 'x', running: true, counters: { rx_bytes: 0, rx_packets: 0, tx_bytes: 0, tx_packets: 0, rx_bps: 8000, tx_bps: 2000 } })).toEqual([{ dl: 8000, ul: 2000 }]);
    expect(nextSamples([], { ue_id: 'x', running: false })).toEqual([]);
    const row = { id: 'UE-201', registration_state: 'DEREGISTERED', pdu_session: 'NONE', ue_ip: null, traffic_state: 'IDLE', last_event: null, controller_owned: true };
    expect(rowState(row, { jobId: 'j', scenarioName: 'Données', state: 'RUNNING' }).label).toBe('En cours · Données');
    expect(rowState(row, undefined).label).toBe('Arrêté');
  });
});

describe('LabUesPage run flow', () => {
  afterEach(() => vi.restoreAllMocks());

  it('Lancer creates a live grant, starts the run and shows « En cours »', async () => {
    const calls: Array<{ url: string; body?: string }> = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      calls.push({ url, body: init?.body as string | undefined });
      if (url.endsWith('/ues')) {
        return json(200, {
          items: [{ id: 'UE-201', subscriber_identity: '208930000000201', subscription_status: 'VERIFIED', registration_state: 'DEREGISTERED', pdu_session: 'NONE', ue_ip: null, traffic_state: 'IDLE', last_event: null, controller_owned: true, technology: '5G SA', scenario_id: null }],
          configured_profiles: [], configured_count: 1, active_count: 0, registered_count: 0,
        });
      }
      if (url.endsWith('/scenario-definitions')) return json(200, { items: [DATA, CALL], total: 2, schema_version: 2 });
      if (url.endsWith('/live/grant')) return json(200, { grant_id: 'g1', ue_ids: ['UE-201'] });
      if (url.endsWith('/scenarios/start')) return json(200, { job_id: 'job-1', state: 'RUNNING' });
      return json(200, {});
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/lab/ues']}>
          <Routes><Route path="/lab/ues" element={<LabUesPage />} /></Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText('208930000000201')).toBeTruthy();
    const select = await screen.findByLabelText('Scénario pour UE-201');
    // The 2-UE call is not offered on a single-UE row.
    expect(screen.queryByRole('option', { name: 'Appel' })).toBeNull();
    fireEvent.change(select, { target: { value: 'simple-data-ul-dl' } });
    fireEvent.click(screen.getByTestId('lab-run-UE-201'));
    expect(await screen.findByText('En cours · Données UL/DL')).toBeTruthy();
    const grant = calls.find((c) => c.url.endsWith('/live/grant'));
    const start = calls.find((c) => c.url.endsWith('/scenarios/start'));
    expect(JSON.parse(grant!.body!)).toEqual({ ue_ids: ['UE-201'], duration_minutes: 15 });
    expect(JSON.parse(start!.body!)).toEqual({ scenario_definition_id: 'simple-data-ul-dl', ue_ids: ['UE-201'] });
    expect(screen.getByRole('link', { name: 'UE-201' }).getAttribute('href')).toBe('/lab/ues/UE-201');
    await waitFor(() => expect(calls.findIndex((c) => c.url.endsWith('/live/grant'))).toBeLessThan(calls.findIndex((c) => c.url.endsWith('/scenarios/start'))));
  });
});

describe('LabUeMonitorPage — 0.36.1 (ANR2 FAIL 0.36.0)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const EVENTS = [
    { detail: {}, epoch_s: 1794672069, kind: 'live_start', outcome: 'OK' },
    { detail: { already_running: false }, epoch_s: 1794672069, kind: 'registration', outcome: 'OK' },
    { detail: { dnn: 'internet' }, epoch_s: 1794672070, kind: 'pdu_establish', outcome: 'OK' },
    { detail: { direction: 'UL', rate: '5M', receiver_bytes: 1310720, retransmissions: 0, sender_bytes: 1310720, warning: null }, epoch_s: 1794672074, kind: 'iperf3', outcome: 'OK' },
    { detail: { direction: 'DL', rate: '5M', receiver_bytes: 1310720, retransmissions: 0, sender_bytes: 1310720, warning: null }, epoch_s: 1794672078, kind: 'iperf3', outcome: 'OK' },
    { detail: { pdu_state: 'INACTIVE', process_state: 'STOPPED' }, epoch_s: 1794672080, kind: 'detach', outcome: 'OK' },
  ];

  it('lastRun rebuilds the run from the prod events', () => {
    const run = lastRun([{ detail: {}, epoch_s: 1, kind: 'live_start', outcome: 'OK' }, ...EVENTS]);
    expect(run.map((r) => r.label)).toEqual(['Démarrage UE', 'RRC + enregistrement 5G', 'Session PDU', 'Trafic UL', 'Trafic DL', 'Détachement']);
    expect(run[3].detail).toContain('1.3 Mo reçus');
  });

  it('keeps polling while SSE is open and shows the last run', async () => {
    class FakeES {
      static OPEN = 1;
      readyState = 1;
      onopen: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage: ((e: MessageEvent) => void) | null = null;
      close() {}
    }
    vi.stubGlobal('EventSource', FakeES);
    let n = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).endsWith('/ues')) {
        return json(200, { items: [{ id: 'UE-201', subscriber_identity: '001010000000201' }], configured_profiles: [], configured_count: 1, active_count: 0, registered_count: 0 });
      }
      n += 1;
      return json(200, n === 1
        ? { ue_id: 'UE-201', running: false, reason: 'UE_NOT_RUNNING', events: [] }
        : { ue_id: 'UE-201', running: true, states: { rrc_state: 'RRC_CONNECTED', rm_state: 'RM-REGISTERED' }, pdus: [{ dnn: 'internet', state: 'ACTIVE', address: '10.45.0.9' }], counters: { rx_bytes: 10, rx_packets: 1, tx_bytes: 5, tx_packets: 1, rx_bps: 4_000_000, tx_bps: 1_000_000 }, events: EVENTS });
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/lab/ues/UE-201']}>
          <Routes><Route path="/lab/ues/:ueId" element={<LabUeMonitorPage />} /></Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    // First snapshot is empty; the 2 s poll must bring live values despite SSE OPEN.
    expect(await screen.findByText('RRC_CONNECTED', {}, { timeout: 4000 })).toBeTruthy();
    expect(screen.getByText('ACTIVE')).toBeTruthy();
    expect(screen.getByText(/DL 4\.0 Mbit\/s/)).toBeTruthy();
    expect(screen.getByTestId('monitor-last-run').textContent).toContain('Trafic DL');
    expect(await screen.findByText(/IMSI 001010000000201/)).toBeTruthy();
    vi.unstubAllGlobals();
  }, 10000);
});

describe('rrcView — 0.36.2 (ANR2 FAIL 0.36.1 : rrc_state=null)', () => {
  it('derives RRC from CM state when nr-cli gives none', () => {
    expect(rrcView({ rrc_state: null, cm_state: 'CM-CONNECTED' })).toEqual({ value: 'RRC-CONNECTED', source: 'déduit de CM-CONNECTED' });
    expect(rrcView({ rrc_state: null, cm_state: 'CM-IDLE' }).value).toBe('RRC-IDLE');
    expect(rrcView({ rrc_state: 'RRC-CONNECTED', cm_state: 'CM-IDLE' })).toEqual({ value: 'RRC-CONNECTED', source: 'nr-cli' });
    expect(rrcView({}).value).toBeNull();
  });
});

describe('lastRun — 0.36.3 5QI', () => {
  it('shows the N2 5QI and the call verdict', () => {
    const run = lastRun([
      { detail: {}, epoch_s: 1, kind: 'live_start', outcome: 'OK' },
      { detail: { dnn: 'ims', five_qi: [1] }, epoch_s: 2, kind: 'n2_qos', outcome: 'OK' },
      { detail: { duration_ms: 7489, rtp: { rx_packets: 148 }, qos: { five_qi: 1, status: 'FIVE_QI_1_OBSERVED' } }, epoch_s: 3, kind: 'voice_call', outcome: 'OK' },
    ]);
    expect(run[1]).toMatchObject({ label: 'QoS N2 (ims)', detail: '5QI 1' });
    expect(run[2].detail).toContain('5QI 1');
  });
});

describe('callScenarios — 0.36.4 (ANR2 FAIL 0.36.3 : tpl-voice-long choisi)', () => {
  it('puts simple-voice-call first even when listed after tpl-voice-long', () => {
    const long = { ...CALL, id: 'tpl-voice-long', name: 'Voice long ×100', catalog_scope: 'SYSTEM' as const };
    const calls = callScenarios([long, DATA, CALL]);
    expect(calls.map((d) => d.id)).toEqual(['simple-voice-call', 'tpl-voice-long']);
  });
});

describe('quietMode — 0.36.5 (ANR2 #10 6882271073 : charge UI → throttling)', () => {
  it('suspends background polling while quiet', async () => {
    const { enterQuiet, leaveQuiet, isQuiet, politeInterval } = await import('@/data/quietMode');
    leaveQuiet();
    expect(politeInterval(10_000)()).toBe(10_000);
    enterQuiet(60_000);
    expect(isQuiet()).toBe(true);
    expect(politeInterval(10_000)()).toBe(false);
    expect(isQuiet(Date.now() + 61_000)).toBe(false);
    leaveQuiet();
  });
});

describe('lastVoiceCall — 0.36.6 (RTP au lieu du débit pour la voix)', () => {
  it('reads this UE\'s own RTP counters, role and 5QI', () => {
    const v = lastVoiceCall([
      { epoch_s: 10, kind: 'voice_call', outcome: 'OK', detail: { role: 'callee', duration_ms: 7489, rtp: { tx_packets: 301, tx_bytes: 15652, rx_packets: 300, rx_bytes: 15600 }, qos: { five_qi: 1, status: 'FIVE_QI_1_OBSERVED' }, capture: { kernel_drops: 0 } } },
      { epoch_s: 5, kind: 'voice_call', outcome: 'OK', detail: { rtp: { tx_packets: 1 } } },
    ]);
    expect(v).toMatchObject({ role: 'appelé', txPackets: 301, rxPackets: 300, fiveQi: 1, kernelDrops: 0 });
    expect(lastVoiceCall([])).toBeNull();
  });
});

describe('0.36.10 conflictMessageFr', () => {
  it('names the scenario and UEs that occupy the lab', async () => {
    const { conflictMessageFr } = await import('./labShared');
    const text = conflictMessageFr({
      error: 'SCENARIO_CONFLICT',
      active_scenario_id: 'simple-voice-call',
      active_ue_ids: ['UE-05', 'UE-201'],
    });
    expect(text).toContain('« simple-voice-call » sur UE-05, UE-201');
    expect(text).toContain('Un seul scénario à la fois');
  });
  it('returns null for other errors', async () => {
    const { conflictMessageFr } = await import('./labShared');
    expect(conflictMessageFr({ error: 'UE_NOT_RUNNING' })).toBeNull();
    expect(conflictMessageFr(undefined)).toBeNull();
  });
});
