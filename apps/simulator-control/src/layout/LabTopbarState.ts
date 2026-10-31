import { useLab, useLabObserved, useUes } from '@/data/queries';

export interface LabTopbarState {
  coreHealth: 'healthy' | 'degraded' | 'offline' | 'unknown';
  plmn: string;
  tac: string;
  liveUes: number;
  maxUes: number;
}

const DEFAULT_PLMN = '001/01';
const DEFAULT_TAC = '200';

function toHealth(state: string | undefined): LabTopbarState['coreHealth'] {
  if (!state) return 'unknown';
  const normalised = state.toLowerCase();
  if (normalised === 'running' || normalised === 'healthy') return 'healthy';
  if (normalised === 'degraded' || normalised === 'starting') return 'degraded';
  if (normalised === 'exited' || normalised === 'stopped' || normalised === 'crashed') return 'offline';
  return 'unknown';
}

export function useLabTopbarState(): LabTopbarState {
  const lab = useLab();
  const observed = useLabObserved();
  const ues = useUes();

  const open5gs = observed.data?.observed?.open5gs;
  let coreHealth: LabTopbarState['coreHealth'] = 'unknown';
  const nfs = observed.data?.observed?.nfs;
  if (nfs) {
    const states = Object.values(nfs).map((nf) => toHealth(nf.process_state));
    if (states.length > 0) {
      if (states.every((s) => s === 'healthy')) coreHealth = 'healthy';
      else if (states.some((s) => s === 'offline')) coreHealth = 'offline';
      else coreHealth = 'degraded';
    }
  } else if (open5gs) {
    coreHealth = toHealth(open5gs.process_state);
  }

  return {
    coreHealth,
    plmn: DEFAULT_PLMN,
    tac: DEFAULT_TAC,
    liveUes: ues.data?.active_count ?? 0,
    maxUes: lab.data?.max_ues ?? ues.data?.configured_count ?? 0,
  };
}
