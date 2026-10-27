import type { EvidenceLevel } from '@shared/types';

export type TopologyNodeKind =
  | 'UE'
  | 'RAN'
  | 'GNB'
  | 'ENB'
  | 'AMF'
  | 'SMF'
  | 'UPF'
  | 'OTHER_NF'
  | 'PROBE_PHYSICAL'
  | 'PROBE_VIRTUAL'
  | 'INTERFACE';

export type TopologyNodeData = {
  kind: TopologyNodeKind;
  label: string;
  sublabel?: string;
  evidence: EvidenceLevel;
  status?: string;
  details?: Record<string, string | number | null | undefined>;
};

export type TopologyEdgeKind =
  | 'NG-C'
  | 'NG-U'
  | 'N4'
  | 'SBI'
  | 'MONITOR'
  | 'LINK';

export type TopologyEdgeData = {
  kind: TopologyEdgeKind;
  evidence: EvidenceLevel;
  label?: string;
  packetRatePps?: number | null;
};
