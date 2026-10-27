import { describe, it, expect } from 'vitest';
import { buildTopology } from './buildTopology';

describe('buildTopology', () => {
  it('emits the 5G SA inferred scaffold even when no probes are reported', () => {
    const graph = buildTopology({ probes: [], interfaces: [] });
    const kinds = graph.nodes.map((node) => node.data.kind);
    expect(kinds).toEqual(expect.arrayContaining(['UE', 'GNB', 'AMF', 'SMF', 'UPF']));
    expect(
      graph.nodes.every((node) =>
        ['INFERRED', 'DISCOVERED', 'CONFIGURED', 'UNKNOWN'].includes(
          node.data.evidence,
        ),
      ),
    ).toBe(true);
  });

  it('marks a backend-reported probe as DISCOVERED and attaches its interfaces', () => {
    const graph = buildTopology({
      probes: [
        {
          probe_id: 'oiran-vprobe-01',
          name: 'OIRAN vProbe 01',
          host: 'host-01',
          probe_type: 'virtual',
          version: '2.3.0',
          health: 'HEALTHY',
          online: true,
          connected_interfaces: ['N2'],
          capture_state: 'READY',
          packet_rate_pps: null,
          decode_rate_eps: null,
          packet_drops: null,
          cpu_usage_percent: 12,
          memory_usage_bytes: 200_000_000,
          disk_usage_percent: 40,
          historical_packet_count: 0,
          telemetry_status: 'MEASURED',
          distributed: false,
        },
      ],
      interfaces: [
        {
          interface: 'N2',
          protocol: 'NGAP',
          capture_point: 'gNB ↔ AMF',
          source: 'config',
          status: 'UP',
          device: 'eth0',
          live_capture_available: true,
          packet_count: null,
          file_size: null,
          capture_start: null,
          capture_end: null,
        },
      ],
    });

    const probe = graph.nodes.find((node) => node.id === 'oiran-vprobe-01');
    expect(probe).toBeDefined();
    expect(probe?.data.evidence).toBe('DISCOVERED');
    const iface = graph.nodes.find((node) => node.id === 'iface:N2');
    expect(iface?.data.evidence).toBe('DISCOVERED');
    const monitorEdge = graph.edges.find(
      (edge) => edge.source === 'oiran-vprobe-01' && edge.target === 'iface:N2',
    );
    expect(monitorEdge?.data?.kind).toBe('MONITOR');
    const n2Edge = graph.edges.find(
      (edge) => edge.source === 'iface:N2' && edge.target === 'amf',
    );
    expect(n2Edge?.data?.evidence).toBe('CONFIGURED');
  });
});
