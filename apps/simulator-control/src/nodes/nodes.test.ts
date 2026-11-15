// 0.36.7 — ANR2 Node Manager audit (#10): real /lab payload shape.
import { describe, expect, it } from 'vitest';
import { IMS_COMPONENTS, normalizeLabEnvelope, type WireLabEnvelope } from '@/data/queries';
import { nfPillState } from '@/pages/Topology';
import { countAttached } from '@/pages/Gnbs';

const nf = (name: string, health = 'healthy') => ({ container: `oiran-lab-${name.toLowerCase()}-1`, health, nf: name, observed: true, observed_at: 1, process_state: 'running' });
const RAW = {
  configuration_changed: false,
  source: 'READ_ONLY_HOST_AUDIT',
  observed: {
    nfs: [...['AMF', 'SMF', 'UPF', 'NRF', 'AUSF', 'UDM', 'UDR', 'PCF', 'NSSF', 'BSF'].map((n) => nf(n)), nf('Kamailio', 'not_available'), nf('RTPengine', 'not_available')],
    open5gs: { health: 'healthy', observed: true, process_state: 'running' },
  },
} as unknown as WireLabEnvelope;

describe('Node Manager 0.36.7', () => {
  it('turns the nfs array into a map keyed by NF name', () => {
    const lab = normalizeLabEnvelope(RAW);
    expect(Object.keys(lab.observed!.nfs!)).toHaveLength(12);
    expect(lab.observed!.nfs!['SMF']?.health).toBe('healthy');
    expect(lab.observed!.nfs!['KAMAILIO']?.health).toBe('not_available');
  });
  it('Topology no longer marks SMF « not exposed »', () => {
    const lab = normalizeLabEnvelope(RAW);
    expect(nfPillState('SMF', lab.observed).title).not.toMatch(/not exposed/);
  });
  it('excludes IMS from the Open5GS count (10 healthy, not 10/12)', () => {
    const lab = normalizeLabEnvelope(RAW);
    const core = Object.entries(lab.observed!.nfs!).filter(([k]) => !IMS_COMPONENTS.has(k));
    expect(core).toHaveLength(10);
  });
  it('separates assigned profiles from registered UEs', () => {
    const items = [
      { id: 'UE-201', serving_node: 'GNB-01', registration_state: 'REGISTERED' },
      { id: 'UE-05', serving_node: 'GNB-01', registration_state: 'DEREGISTERED' },
    ] as never;
    expect(countAttached(items, 'GNB-01')).toEqual({ assigned: ['UE-201', 'UE-05'], registered: ['UE-201'] });
  });
});
