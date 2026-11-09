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

// 0.13.4 (ANR1 #10 6740653880) — forme TABLEAU émise par
// polaris-control-api 0.29.16 et 0.30.0 en production.
// `apps/api/src/lib.rs::network_function_observation` sérialise
// chaque NF comme un objet `{nf, container, process_state, …}`
// et `GET /lab` publie `observed.nfs: Array<...>`. La 0.13.3
// présupposait une MAP ; `Object.entries` ne lui livrait que des
// clés `"0".."11"` → coreHealth=unknown systématique.
import realApiLabResponse from './fixtures/polaris-api-0.29.16-lab-real-array.json';
import type { WireNfObservation } from '@/data/queries';

describe('splitCoreAndIms — forme ARRAY réelle API 0.29.16/0.30.0', () => {
  it('route les 10 NFs 5GC vers core et Kamailio/RTPengine vers ims sur le payload RÉEL ANR1', () => {
    const nfs = realApiLabResponse.observed.nfs as unknown as WireNfObservation[];
    // Prouve que c'est bien un tableau à l'ingestion (prévient
    // tout drift silencieux de la fixture).
    expect(Array.isArray(nfs)).toBe(true);
    expect(nfs.length).toBe(12);
    // Prouve que Object.entries sur un tableau donnait bien
    // `"0".."11"` — c'est la cause racine ANR1.
    const naiveKeys = Object.entries(nfs).map(([k]) => k);
    expect(naiveKeys).toEqual([
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11',
    ]);

    // Résultat attendu par ANR1 : core=healthy, ims=offline.
    const { core, ims } = splitCoreAndIms(nfs);
    expect(core).toBe('healthy');
    expect(ims).toBe('offline');
  });

  it('accepte aussi la forme MAP historique (tolérance arrière)', () => {
    const map: Record<string, { process_state: string }> = {};
    for (const entry of realApiLabResponse.observed.nfs as unknown as WireNfObservation[]) {
      map[entry.nf as string] = { process_state: entry.process_state as string };
    }
    const { core, ims } = splitCoreAndIms(map);
    expect(core).toBe('healthy');
    expect(ims).toBe('offline');
  });

  it('ligne sans nf tombe en IMS sans faire basculer le cœur', () => {
    const nfs: WireNfObservation[] = [
      { nf: 'AMF', process_state: 'running' },
      { nf: 'SMF', process_state: 'running' },
      { nf: 'UPF', process_state: 'running' },
      { nf: 'NRF', process_state: 'running' },
      { nf: 'AUSF', process_state: 'running' },
      { nf: 'UDM', process_state: 'running' },
      { nf: 'UDR', process_state: 'running' },
      { nf: 'PCF', process_state: 'running' },
      { nf: 'NSSF', process_state: 'running' },
      { nf: 'BSF', process_state: 'running' },
      // entrée anonyme — ne doit PAS marquer le cœur offline.
      { process_state: 'exited' } as WireNfObservation,
    ];
    const { core, ims } = splitCoreAndIms(nfs);
    expect(core).toBe('healthy');
    expect(ims).toBe('offline');
  });
});
