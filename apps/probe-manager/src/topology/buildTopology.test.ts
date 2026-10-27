import { describe, expect, it } from 'vitest';
import { buildTopology } from './buildTopology';
import type { CaptureInterface, Probe } from '@shared/types';
import type { VerifiedInterfaceMapping } from './types';

function makeInterface(partial: Partial<CaptureInterface> & { interface: string }): CaptureInterface {
  return {
    protocol: 'unknown',
    capture_point: 'unspecified',
    source: 'config',
    status: 'UP',
    device: 'veth0',
    live_capture_available: false,
    packet_count: null,
    file_size: null,
    capture_start: null,
    capture_end: null,
    ...partial,
  };
}

function makeProbe(partial: Partial<Probe> & { probe_id: string }): Probe {
  return {
    name: partial.name ?? partial.probe_id,
    host: 'lab.internal',
    probe_type: 'virtual',
    version: '1.0.0',
    health: 'HEALTHY',
    online: true,
    connected_interfaces: [],
    capture_state: 'READY',
    packet_rate_pps: null,
    decode_rate_eps: null,
    packet_drops: null,
    cpu_usage_percent: null,
    memory_usage_bytes: null,
    disk_usage_percent: null,
    historical_packet_count: 0,
    telemetry_status: 'MEASURED',
    distributed: false,
    ...partial,
  };
}

describe('buildTopology — scaffold', () => {
  it('always emits the 5G SA inferred scaffold even without probes', () => {
    const graph = buildTopology({});
    const scaffoldIds = ['ue', 'gnb', 'amf', 'smf', 'upf'];
    for (const id of scaffoldIds) {
      const node = graph.nodes.find((n) => n.id === id);
      expect(node, `scaffold node ${id} missing`).toBeDefined();
      expect(node?.data.evidence).toBe('INFERRED');
    }
    const scaffoldEdges = graph.edges.filter(
      (edge) => edge.data?.evidenceSource === '5G SA reference scaffold',
    );
    expect(scaffoldEdges.length).toBeGreaterThanOrEqual(5);
    for (const edge of scaffoldEdges) {
      expect(edge.data?.evidence).toBe('INFERRED');
    }
  });
});

describe('buildTopology — plane-name heuristic MUST NOT certify connectivity', () => {
  it.each([
    { label: 'N2', targetNf: 'amf', kind: 'NG-C' },
    { label: 'N3', targetNf: 'upf', kind: 'NG-U' },
    { label: 'N4', targetNf: 'smf', kind: 'N4' },
    { label: 'SBI', targetNf: 'amf', kind: 'SBI' },
  ])(
    'name "$label" alone produces an INFERRED edge to $targetNf, never CONFIGURED',
    ({ label, targetNf, kind }) => {
      const graph = buildTopology({
        interfaces: [makeInterface({ interface: label })],
      });
      const heuristicEdge = graph.edges.find(
        (edge) =>
          edge.source === `iface:${label}` && edge.target === targetNf,
      );
      expect(heuristicEdge, `expected an edge from iface:${label} to ${targetNf}`).toBeDefined();
      expect(heuristicEdge?.data?.evidence).toBe('INFERRED');
      expect(heuristicEdge?.data?.kind).toBe(kind);
      expect(heuristicEdge?.data?.evidenceSource).toMatch(/no backend-verified mapping/i);

      // And no edge for this interface should ever be CONFIGURED/DISCOVERED
      // without an explicit mapping.
      const upgraded = graph.edges.filter(
        (edge) =>
          edge.source === `iface:${label}` &&
          (edge.data?.evidence === 'CONFIGURED' ||
            edge.data?.evidence === 'DISCOVERED'),
      );
      expect(upgraded, 'plane-name alone must not certify a connection').toEqual([]);
    },
  );

  it('does not emit a heuristic edge for interface names outside the known plane prefixes', () => {
    const graph = buildTopology({
      interfaces: [makeInterface({ interface: 'management-0' })],
    });
    const heuristicEdges = graph.edges.filter(
      (edge) =>
        edge.source === 'iface:management-0' &&
        edge.data?.evidenceSource?.includes('interface name prefix'),
    );
    expect(heuristicEdges).toEqual([]);
  });

  it('still renders the interface node (DISCOVERED) and probe→interface MONITOR edge', () => {
    const graph = buildTopology({
      probes: [makeProbe({ probe_id: 'p1', connected_interfaces: ['N2'] })],
      interfaces: [makeInterface({ interface: 'N2' })],
    });
    const ifaceNode = graph.nodes.find((n) => n.id === 'iface:N2');
    expect(ifaceNode?.data.evidence).toBe('DISCOVERED');
    const monitorEdge = graph.edges.find(
      (edge) =>
        edge.source === 'p1' &&
        edge.target === 'iface:N2' &&
        edge.data?.kind === 'MONITOR',
    );
    expect(monitorEdge?.data?.evidence).toBe('DISCOVERED');
  });
});

describe('buildTopology — explicit verified mappings', () => {
  const verifiedN2: VerifiedInterfaceMapping = {
    interface: 'N2',
    networkFunction: 'amf',
    kind: 'NG-C',
    evidence: 'CONFIGURED',
    evidenceSource: 'operator-reviewed /topology/links',
  };

  it('upgrades the edge to CONFIGURED and suppresses the INFERRED hint for the same NF', () => {
    const graph = buildTopology({
      interfaces: [makeInterface({ interface: 'N2' })],
      verifiedMappings: [verifiedN2],
    });
    const edgesForIface = graph.edges.filter(
      (edge) => edge.source === 'iface:N2' && edge.target === 'amf',
    );
    // Only the verified edge, no duplicate heuristic edge.
    expect(edgesForIface).toHaveLength(1);
    expect(edgesForIface[0]?.data?.evidence).toBe('CONFIGURED');
    expect(edgesForIface[0]?.data?.evidenceSource).toBe(
      'operator-reviewed /topology/links',
    );
  });

  it('does not touch unrelated interfaces when a mapping is supplied', () => {
    const graph = buildTopology({
      interfaces: [
        makeInterface({ interface: 'N2' }),
        makeInterface({ interface: 'N3' }),
      ],
      verifiedMappings: [verifiedN2],
    });
    const n3Edges = graph.edges.filter((edge) => edge.source === 'iface:N3');
    for (const edge of n3Edges) {
      // N3 was NOT in the verified set — it must stay INFERRED (plane-name hint).
      expect(edge.data?.evidence).toBe('INFERRED');
    }
  });

  it('accepts DISCOVERED evidence from a verified mapping', () => {
    const graph = buildTopology({
      interfaces: [makeInterface({ interface: 'N3' })],
      verifiedMappings: [
        {
          interface: 'N3',
          networkFunction: 'upf',
          kind: 'NG-U',
          evidence: 'DISCOVERED',
          evidenceSource: 'backend topology/links probe',
        },
      ],
    });
    const edge = graph.edges.find(
      (e) => e.source === 'iface:N3' && e.target === 'upf',
    );
    expect(edge?.data?.evidence).toBe('DISCOVERED');
    expect(edge?.animated).toBe(true);
  });
});

describe('buildTopology — missing evidence honesty', () => {
  it('reports no verified or discovered edges when nothing is reported', () => {
    const graph = buildTopology({});
    const certifiedEdges = graph.edges.filter(
      (edge) =>
        edge.data?.evidence === 'DISCOVERED' ||
        edge.data?.evidence === 'CONFIGURED',
    );
    expect(certifiedEdges).toEqual([]);
  });
});
