import { useLab, useLabObserved, useUes } from '@/data/queries';

export type HealthState = 'healthy' | 'degraded' | 'offline' | 'unknown';

export interface LabTopbarState {
  coreHealth: HealthState;
  /**
   * 0.13.3 (#9 6737560904, #10 6737561274) : l'état IMS (Kamailio,
   * RTPengine) est séparé du cœur 5G. ANR1 a prouvé que
   * `observed.nfs` contient à la fois les 10 NFs 5GC et les deux
   * fonctions IMS optionnelles ; l'agrégation naïve pré-0.13.3
   * marquait `coreHealth=offline` dès qu'une seule entrée IMS
   * passait en `exited`, alors que le cœur 5G était en ligne.
   */
  imsHealth: HealthState;
  plmn: string;
  tac: string;
  liveUes: number;
  maxUes: number;
}

const DEFAULT_PLMN = '001/01';
const DEFAULT_TAC = '200';

/**
 * 0.13.3 : NFs qui composent le **cœur 5G**. Ordre canonique 3GPP
 * TS 23.501 clause 6.2. Toute entrée `observed.nfs[k]` dont la
 * clé normalisée (upper-case) n'est PAS dans ce set est traitée
 * comme IMS / fonction optionnelle (ex. Kamailio, RTPengine) et
 * contribue uniquement à `imsHealth`.
 */
export const CORE_5GC_NFS: ReadonlySet<string> = new Set([
  'AMF',
  'SMF',
  'UPF',
  'NRF',
  'AUSF',
  'UDM',
  'UDR',
  'PCF',
  'NSSF',
  'BSF',
]);

export function toHealth(state: string | undefined): HealthState {
  if (!state) return 'unknown';
  const normalised = state.toLowerCase();
  if (normalised === 'running' || normalised === 'healthy') return 'healthy';
  if (normalised === 'degraded' || normalised === 'starting') return 'degraded';
  if (normalised === 'exited' || normalised === 'stopped' || normalised === 'crashed') return 'offline';
  return 'unknown';
}

/**
 * 0.13.3 : règle d'agrégation partagée par le cœur 5G et l'IMS.
 * Jamais de mélange — un appelant passe UNIQUEMENT ses propres
 * entrées (le filtrage 5GC/IMS est fait en amont).
 */
export function aggregate(states: HealthState[]): HealthState {
  if (states.length === 0) return 'unknown';
  if (states.every((s) => s === 'healthy')) return 'healthy';
  if (states.some((s) => s === 'offline')) return 'offline';
  return 'degraded';
}

/**
 * 0.13.3 : scinde une map `observed.nfs` en deux agrégats
 * `(core, ims)`. Fonction pure, testable sans react-query —
 * utilisée par `useLabTopbarState` et par les tests unitaires.
 *
 * 0.13.4 (ANR1 #10 6740653880) : accepte DEUX formes de wire :
 *   * **Tableau** `WireNfObservation[]` — forme émise par
 *     polaris-control-api 0.29.16/0.30.0 en production
 *     (`apps/api/src/lib.rs::network_function_observation`).
 *     Chaque entrée porte son `nf` (AMF, SMF, …, Kamailio,
 *     RTPengine), utilisé pour router vers `core` ou `ims`.
 *   * **Map** `Record<name, status>` — forme historique 0.7.0,
 *     conservée pour tolérance aux backends anciens ou simulés.
 *
 * ANR1 a prouvé que le passage array→map en 0.13.3 cassait le
 * routage : `Object.entries` renvoyait des clés `"0".."11"`
 * (indices de tableau) → `CORE_5GC_NFS.has("0".toUpperCase())`
 * jamais vrai → tout tombait en `imsHealth` et coreHealth
 * restait `unknown`.
 */
export function splitCoreAndIms(
  nfs:
    | Record<string, { process_state?: string }>
    | ReadonlyArray<{ nf?: string; process_state?: string }>,
): { core: HealthState; ims: HealthState } {
  const coreStates: HealthState[] = [];
  const imsStates: HealthState[] = [];
  const entries: Array<[string, { process_state?: string }]> = Array.isArray(nfs)
    ? nfs.map((entry) => [entry.nf ?? '', entry])
    : Object.entries(nfs);
  for (const [name, status] of entries) {
    if (!name) {
      // Ligne sans `nf` : impossible de router. On la place en
      // IMS par défaut (fail-closed sur le cœur 5G — on ne
      // marque PAS le cœur "offline" sur une entrée anonyme).
      imsStates.push(toHealth(status.process_state));
      continue;
    }
    const state = toHealth(status.process_state);
    if (CORE_5GC_NFS.has(name.toUpperCase())) {
      coreStates.push(state);
    } else {
      imsStates.push(state);
    }
  }
  return { core: aggregate(coreStates), ims: aggregate(imsStates) };
}

export function useLabTopbarState(): LabTopbarState {
  const lab = useLab();
  const observed = useLabObserved();
  const ues = useUes();

  const open5gs = observed.data?.observed?.open5gs;
  const nfs = observed.data?.observed?.nfs;

  let coreHealth: HealthState = 'unknown';
  let imsHealth: HealthState = 'unknown';
  const hasNfs = nfs
    ? Array.isArray(nfs)
      ? nfs.length > 0
      : Object.keys(nfs).length > 0
    : false;
  if (hasNfs && nfs) {
    const split = splitCoreAndIms(nfs);
    coreHealth = split.core;
    imsHealth = split.ims;
  } else if (open5gs) {
    // Fallback historique : pas de `nfs`, on retombe sur
    // l'agrégat `open5gs`. L'IMS reste `unknown` dans ce mode.
    coreHealth = toHealth(open5gs.process_state);
  }

  return {
    coreHealth,
    imsHealth,
    plmn: DEFAULT_PLMN,
    tac: DEFAULT_TAC,
    liveUes: ues.data?.active_count ?? 0,
    maxUes: lab.data?.max_ues ?? ues.data?.configured_count ?? 0,
  };
}
