import { describe, expect, it } from 'vitest';
import { CORE_5GC_NFS, aggregate, splitCoreAndIms, toHealth } from './LabTopbarState';

describe('toHealth', () => {
  it('maps running/healthy to healthy', () => {
    expect(toHealth('running')).toBe('healthy');
    expect(toHealth('Running')).toBe('healthy');
    expect(toHealth('healthy')).toBe('healthy');
  });
  it('maps degraded/starting to degraded', () => {
    expect(toHealth('degraded')).toBe('degraded');
    expect(toHealth('starting')).toBe('degraded');
  });
  it('maps exited/stopped/crashed to offline', () => {
    expect(toHealth('exited')).toBe('offline');
    expect(toHealth('stopped')).toBe('offline');
    expect(toHealth('crashed')).toBe('offline');
  });
  it('defaults to unknown', () => {
    expect(toHealth(undefined)).toBe('unknown');
    expect(toHealth('')).toBe('unknown');
    expect(toHealth('whatever')).toBe('unknown');
  });
});

describe('aggregate', () => {
  it('unknown on empty input', () => {
    expect(aggregate([])).toBe('unknown');
  });
  it('healthy iff every member is healthy', () => {
    expect(aggregate(['healthy', 'healthy'])).toBe('healthy');
  });
  it('offline if any member is offline', () => {
    expect(aggregate(['healthy', 'offline', 'degraded'])).toBe('offline');
  });
  it('degraded otherwise', () => {
    expect(aggregate(['healthy', 'degraded'])).toBe('degraded');
    expect(aggregate(['healthy', 'unknown'])).toBe('degraded');
  });
});

describe('CORE_5GC_NFS', () => {
  it('contains exactly the 10 canonical 5GC NFs', () => {
    const expected = ['AMF', 'SMF', 'UPF', 'NRF', 'AUSF', 'UDM', 'UDR', 'PCF', 'NSSF', 'BSF'];
    expect(CORE_5GC_NFS.size).toBe(10);
    for (const name of expected) {
      expect(CORE_5GC_NFS.has(name)).toBe(true);
    }
    // IMS NFs must NOT be in the core set.
    expect(CORE_5GC_NFS.has('KAMAILIO')).toBe(false);
    expect(CORE_5GC_NFS.has('RTPENGINE')).toBe(false);
  });
});

describe('splitCoreAndIms — ANR1 #9 6737560904 real shape', () => {
  it('reports core=healthy and ims=offline when only Kamailio+RTPengine exited', () => {
    // Forme exacte publiée par ANR1 : 10 NFs 5GC running, Kamailio
    // + RTPengine exited. Pré-0.13.3 → coreHealth=offline (bug).
    // Post-0.13.3 → coreHealth=healthy, imsHealth=offline.
    const nfs = {
      AMF: { process_state: 'running', health: 'healthy', observed: true },
      SMF: { process_state: 'running', health: 'healthy', observed: true },
      UPF: { process_state: 'running', health: 'healthy', observed: true },
      NRF: { process_state: 'running', health: 'healthy', observed: true },
      AUSF: { process_state: 'running', health: 'healthy', observed: true },
      UDM: { process_state: 'running', health: 'healthy', observed: true },
      UDR: { process_state: 'running', health: 'healthy', observed: true },
      PCF: { process_state: 'running', health: 'healthy', observed: true },
      NSSF: { process_state: 'running', health: 'healthy', observed: true },
      BSF: { process_state: 'running', health: 'healthy', observed: true },
      Kamailio: { process_state: 'exited', health: 'not_available', observed: true },
      RTPengine: { process_state: 'exited', health: 'not_available', observed: true },
    };
    const { core, ims } = splitCoreAndIms(nfs);
    expect(core).toBe('healthy');
    expect(ims).toBe('offline');
  });

  it('reports core=offline when a 5GC NF is exited', () => {
    const nfs = {
      AMF: { process_state: 'exited' },
      SMF: { process_state: 'running' },
      Kamailio: { process_state: 'running' },
    };
    const { core, ims } = splitCoreAndIms(nfs);
    expect(core).toBe('offline');
    expect(ims).toBe('healthy');
  });

  it('is case-insensitive on NF names (amf == AMF)', () => {
    const nfs = {
      amf: { process_state: 'running' },
      smf: { process_state: 'running' },
      upf: { process_state: 'running' },
      nrf: { process_state: 'running' },
      ausf: { process_state: 'running' },
      udm: { process_state: 'running' },
      udr: { process_state: 'running' },
      pcf: { process_state: 'running' },
      nssf: { process_state: 'running' },
      bsf: { process_state: 'running' },
    };
    const { core, ims } = splitCoreAndIms(nfs);
    expect(core).toBe('healthy');
    expect(ims).toBe('unknown'); // aucune IMS = unknown, pas offline
  });

  it('ims=unknown when no IMS NF is observed', () => {
    const nfs = {
      AMF: { process_state: 'running' },
    };
    const { core, ims } = splitCoreAndIms(nfs);
    expect(core).toBe('healthy');
    expect(ims).toBe('unknown');
  });
});
