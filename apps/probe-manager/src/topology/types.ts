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
  /**
   * Human-readable source of the evidence (e.g. "backend topology/links",
   * "operator-supplied mapping"). Rendered in the inspector so the UI can
   * explain *why* an edge carries a given evidence tag.
   */
  evidenceSource?: string;
};

/**
 * Explicit verified mapping between a capture interface and a 5G network
 * function. Only present when the backend (or an operator-reviewed
 * configuration file) has independently confirmed the association. The
 * frontend MUST NOT fabricate these.
 *
 * `evidence` must be `CONFIGURED` or `DISCOVERED`. `UNKNOWN`/`INFERRED`
 * values are rejected because they would re-introduce the plane-name
 * heuristic that this contract is designed to prevent.
 */
export type VerifiedInterfaceMapping = {
  /** Logical interface label returned by the backend (`/interfaces[].interface`). */
  interface: string;
  /** Target node id in the topology (e.g. "amf", "upf"). */
  networkFunction: 'amf' | 'smf' | 'upf' | 'gnb' | 'enb' | string;
  /** Protocol family carried over the link. */
  kind: TopologyEdgeKind;
  evidence: Extract<EvidenceLevel, 'CONFIGURED' | 'DISCOVERED'>;
  evidenceSource: string;
};
