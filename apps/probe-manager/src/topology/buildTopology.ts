import type { Edge, Node } from '@xyflow/react';
import type {
  CaptureInterface,
  EvidenceLevel,
  Probe,
} from '@shared/types';
import type { TopologyEdgeData, TopologyNodeData, TopologyNodeKind } from './types';

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

function placeInColumn(
  nodes: Node<TopologyNodeData>[],
  kinds: TopologyNodeKind[] | 'ALL' = 'ALL',
) {
  const counts: Partial<Record<TopologyNodeKind, number>> = {};
  for (const n of nodes) {
    if (kinds !== 'ALL' && !kinds.includes(n.data.kind)) continue;
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

export function buildTopology({
  probes = [],
  interfaces = [],
}: {
  probes?: Probe[];
  interfaces?: CaptureInterface[];
}): TopologyGraph {
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

  // Core 5G SA scaffold. We ALWAYS show these as INFERRED when nothing is
  // reported — a topology view is pointless without a baseline. They become
  // CONFIGURED/DISCOVERED when the backend confirms them.
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
    }),
    telecomEdge('e-gnb-amf', 'gnb', 'amf', {
      kind: 'NG-C',
      evidence: 'INFERRED',
    }),
    telecomEdge('e-amf-smf', 'amf', 'smf', {
      kind: 'SBI',
      evidence: 'INFERRED',
    }),
    telecomEdge('e-smf-upf', 'smf', 'upf', {
      kind: 'N4',
      evidence: 'INFERRED',
    }),
    telecomEdge('e-gnb-upf', 'gnb', 'upf', {
      kind: 'NG-U',
      evidence: 'INFERRED',
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

  // Add real interfaces as leaf nodes that attach to the probe reporting
  // them (DISCOVERED) and to the nearest NF (INFERRED unless the capture
  // point tags it explicitly).
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
        telecomEdge(`e-${owningProbe.probe_id}-${id}`, owningProbe.probe_id, id, {
          kind: 'MONITOR',
          evidence: 'DISCOVERED',
          label: 'Monitors',
        }),
      );
    }
    // Associate the interface with the nearest NF based on the plane label.
    const plane = iface.interface.toUpperCase();
    if (plane.includes('N2')) {
      edges.push(
        telecomEdge(`e-${id}-amf`, id, 'amf', {
          kind: 'NG-C',
          evidence: 'CONFIGURED',
        }),
      );
    } else if (plane.includes('N3')) {
      edges.push(
        telecomEdge(`e-${id}-upf`, id, 'upf', {
          kind: 'NG-U',
          evidence: 'CONFIGURED',
        }),
      );
    } else if (plane.includes('N4')) {
      edges.push(
        telecomEdge(`e-${id}-smf`, id, 'smf', {
          kind: 'N4',
          evidence: 'CONFIGURED',
        }),
      );
    } else if (plane.includes('SBI')) {
      edges.push(
        telecomEdge(`e-${id}-amf-sbi`, id, 'amf', {
          kind: 'SBI',
          evidence: 'CONFIGURED',
        }),
      );
    }
  }

  // Layout: distribute by column.
  placeInColumn(nodes);
  return { nodes, edges };
}
