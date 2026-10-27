import type { Edge, Node } from '@xyflow/react';
import type {
  CaptureInterface,
  EvidenceLevel,
  Probe,
} from '@shared/types';
import type {
  TopologyEdgeData,
  TopologyEdgeKind,
  TopologyNodeData,
  TopologyNodeKind,
  VerifiedInterfaceMapping,
} from './types';

// Logical column assignment per node kind. The order matches the typical
// 5G SA topology left → right so the layout stays readable.
const COLUMN_ORDER: TopologyNodeKind[] = [
  'UE',
  'RAN',
  'GNB',
  'ENB',
  'AMF',
  'SMF',
  'OTHER_NF',
  'UPF',
  'PROBE_PHYSICAL',
  'PROBE_VIRTUAL',
  'INTERFACE',
];

const COLUMN_X = 220;
const ROW_Y = 140;
const BASE_X = 80;
const BASE_Y = 60;

export type TopologyGraph = {
  nodes: Node<TopologyNodeData>[];
  edges: Edge<TopologyEdgeData>[];
};

function node(
  id: string,
  kind: TopologyNodeKind,
  label: string,
  evidence: EvidenceLevel,
  options: Partial<TopologyNodeData> = {},
): Node<TopologyNodeData> {
  const columnIndex = COLUMN_ORDER.indexOf(kind);
  return {
    id,
    type: 'telecom',
    position: { x: BASE_X + columnIndex * COLUMN_X, y: BASE_Y },
    data: {
      kind,
      label,
      evidence,
      ...options,
    },
  };
}

function placeInColumn(nodes: Node<TopologyNodeData>[]) {
  const counts: Partial<Record<TopologyNodeKind, number>> = {};
  for (const n of nodes) {
    const count = counts[n.data.kind] ?? 0;
    n.position = {
      ...n.position,
      y: BASE_Y + count * ROW_Y,
    };
    counts[n.data.kind] = count + 1;
  }
}

function telecomEdge(
  id: string,
  source: string,
  target: string,
  data: TopologyEdgeData,
): Edge<TopologyEdgeData> {
  return {
    id,
    source,
    target,
    type: 'smoothstep',
    data,
    label: data.label ?? data.kind,
    animated: data.evidence === 'DISCOVERED',
  };
}

/**
 * Infer which plane an interface *name* suggests, used solely to render an
 * `INFERRED` hint edge. This function returns `null` for interface names
 * that do not match a known plane prefix (the edge is simply omitted
 * rather than classified `UNKNOWN`, which would clutter the view with
 * speculative lines).
 */
function inferPlaneFromName(
  interfaceLabel: string,
): { kind: TopologyEdgeKind; targetNf: string } | null {
  const upper = interfaceLabel.toUpperCase();
  // Longest/most specific first.
  if (upper.includes('SBI')) return { kind: 'SBI', targetNf: 'amf' };
  if (upper.includes('N2')) return { kind: 'NG-C', targetNf: 'amf' };
  if (upper.includes('N3')) return { kind: 'NG-U', targetNf: 'upf' };
  if (upper.includes('N4')) return { kind: 'N4', targetNf: 'smf' };
  return null;
}

export type BuildTopologyInput = {
  probes?: Probe[];
  interfaces?: CaptureInterface[];
  /**
   * Explicit verified mappings between interfaces and NFs. Each mapping
   * becomes a CONFIGURED or DISCOVERED edge — depending on its own
   * evidence level — and prevents the heuristic INFERRED edge for the
   * same (interface, nf) pair.
   *
   * The frontend never synthesizes these; they must come from the
   * backend (future `/topology/links` contract) or from an operator-
   * reviewed configuration file.
   */
  verifiedMappings?: VerifiedInterfaceMapping[];
};

export function buildTopology({
  probes = [],
  interfaces = [],
  verifiedMappings = [],
}: BuildTopologyInput): TopologyGraph {
  const nodes: Node<TopologyNodeData>[] = [];
  const edges: Edge<TopologyEdgeData>[] = [];
  const added = new Set<string>();

  const ensure = (
    id: string,
    kind: TopologyNodeKind,
    label: string,
    evidence: EvidenceLevel,
    options?: Partial<TopologyNodeData>,
  ) => {
    if (added.has(id)) return;
    added.add(id);
    nodes.push(node(id, kind, label, evidence, options));
  };

  // Core 5G SA scaffold. Always INFERRED when nothing is reported — a
  // topology view is pointless without a baseline. Backend evidence
  // never upgrades them from here; a separate contract would be
  // required to publish a node as DISCOVERED.
  const scaffold: Array<[string, TopologyNodeKind, string]> = [
    ['ue', 'UE', 'UE'],
    ['gnb', 'GNB', 'gNB'],
    ['amf', 'AMF', 'AMF'],
    ['smf', 'SMF', 'SMF'],
    ['upf', 'UPF', 'UPF'],
  ];
  for (const [id, kind, label] of scaffold) {
    ensure(id, kind, label, 'INFERRED', {
      sublabel: 'Inferred from 5G SA reference topology',
    });
  }

  edges.push(
    telecomEdge('e-ue-gnb', 'ue', 'gnb', {
      kind: 'LINK',
      evidence: 'INFERRED',
      label: 'Uu',
      evidenceSource: '5G SA reference scaffold',
    }),
    telecomEdge('e-gnb-amf', 'gnb', 'amf', {
      kind: 'NG-C',
      evidence: 'INFERRED',
      evidenceSource: '5G SA reference scaffold',
    }),
    telecomEdge('e-amf-smf', 'amf', 'smf', {
      kind: 'SBI',
      evidence: 'INFERRED',
      evidenceSource: '5G SA reference scaffold',
    }),
    telecomEdge('e-smf-upf', 'smf', 'upf', {
      kind: 'N4',
      evidence: 'INFERRED',
      evidenceSource: '5G SA reference scaffold',
    }),
    telecomEdge('e-gnb-upf', 'gnb', 'upf', {
      kind: 'NG-U',
      evidence: 'INFERRED',
      evidenceSource: '5G SA reference scaffold',
    }),
  );

  // Add real probes (backend evidence).
  for (const probe of probes) {
    const kind: TopologyNodeKind =
      probe.probe_type === 'physical' ? 'PROBE_PHYSICAL' : 'PROBE_VIRTUAL';
    ensure(probe.probe_id, kind, probe.name, 'DISCOVERED', {
      status: probe.online ? 'ONLINE' : 'OFFLINE',
      sublabel: probe.host,
      details: {
        'Probe ID': probe.probe_id,
        'Capture state': probe.capture_state,
        'CPU %': probe.cpu_usage_percent ?? null,
      },
    });
  }

  // Track (interface, nf) pairs that have an explicit verified mapping
  // so the heuristic INFERRED edge is suppressed for those pairs only.
  const verifiedByInterface = new Map<string, VerifiedInterfaceMapping[]>();
  for (const mapping of verifiedMappings) {
    const list = verifiedByInterface.get(mapping.interface) ?? [];
    list.push(mapping);
    verifiedByInterface.set(mapping.interface, list);
  }

  // Add real interfaces as leaf nodes.
  for (const iface of interfaces) {
    const id = `iface:${iface.interface}`;
    ensure(id, 'INTERFACE', iface.interface, 'DISCOVERED', {
      status: iface.status,
      sublabel: iface.protocol,
      details: {
        'Linux device': iface.device ?? null,
        'Capture point': iface.capture_point,
        'Live capture': iface.live_capture_available ? 'authorized' : 'gated',
      },
    });

    const owningProbe = probes.find((probe) =>
      probe.connected_interfaces.includes(iface.interface),
    );
    if (owningProbe) {
      edges.push(
        telecomEdge(
          `e-${owningProbe.probe_id}-${id}`,
          owningProbe.probe_id,
          id,
          {
            kind: 'MONITOR',
            evidence: 'DISCOVERED',
            label: 'Monitors',
            evidenceSource: `probe ${owningProbe.probe_id} reports this interface as a capture point`,
          },
        ),
      );
    }

    const explicitMappings = verifiedByInterface.get(iface.interface) ?? [];
    const explicitNfTargets = new Set(
      explicitMappings.map((mapping) => mapping.networkFunction),
    );

    // Emit CONFIGURED/DISCOVERED edges from explicit verified mappings.
    for (const mapping of explicitMappings) {
      edges.push(
        telecomEdge(`e-${id}-${mapping.networkFunction}-verified`, id, mapping.networkFunction, {
          kind: mapping.kind,
          evidence: mapping.evidence,
          label: mapping.kind,
          evidenceSource: mapping.evidenceSource,
        }),
      );
    }

    // Only emit the plane-name heuristic edge when no verified mapping
    // covers the same NF. The heuristic edge is tagged INFERRED because
    // an interface name is not configuration evidence — Section 2 of the
    // review brief.
    const inferredHint = inferPlaneFromName(iface.interface);
    if (inferredHint && !explicitNfTargets.has(inferredHint.targetNf)) {
      edges.push(
        telecomEdge(`e-${id}-${inferredHint.targetNf}-inferred`, id, inferredHint.targetNf, {
          kind: inferredHint.kind,
          evidence: 'INFERRED',
          label: `${inferredHint.kind} (inferred from name)`,
          evidenceSource:
            'interface name prefix matches a 5G plane; no backend-verified mapping was supplied',
        }),
      );
    }
  }

  // Layout: distribute by column.
  placeInColumn(nodes);
  return { nodes, edges };
}
