// 2.5.1 — N3 aggregate helper contract. Locks the wire shape between
// live-probe 0.2.6 (`live-probe-n3-flow-aggregator`) and the Analyzer
// so neither side can drift without the test tripping.

import { describe, expect, it } from 'vitest';
import {
  formatN3AggregateLabel,
  isN3Aggregate,
  summarizeN3Aggregate,
  N3_AGGREGATOR_DECODER_PREFIX,
  N3_AGGREGATOR_PAYLOAD_PREFIX,
} from './n3Aggregate';
import type { CallFlowEvent, InformationElement } from '../types/api';

function ie(name: string, value: string): InformationElement {
  return { id: null, name, length: 0, value, raw_sha256: null, status: 'DECODED' };
}

function event(overrides: Partial<CallFlowEvent> = {}): CallFlowEvent {
  return {
    event_id: 'ev-n3-01',
    timestamp: '2026-10-26T22:44:41.513Z',
    timestamp_ns: '1792872281513000000',
    interface: 'N3',
    protocol: 'GTP-U',
    message_name: 'G-PDU',
    source_participant: 'gNB',
    destination_participant: 'UPF',
    direction: 'UPLINK',
    decoded_ie_tree: [
      ie('teid', '0x000000b3'),
      ie('aggregate_packet_count', '128456'),
      ie('aggregate_wire_bytes', '148967424'),
      ie('aggregate_first_seen_ns', '1792872281100000000'),
      ie('aggregate_last_seen_ns', '1792872281513000000'),
      ie('qfi', '9'),
    ],
    decoding_status: 'DECODED',
    semantic_status: 'NORMAL',
    association: 'SESSION',
    procedure_group: 'User plane',
    packet_references: [
      {
        source_file: 'capture://N3.pcapng',
        packet_number: 1,
        byte_offset: 128,
        interface_id: 2,
        captured_length: 100,
        original_length: 1250,
      },
    ],
    capture_id: 'cap-n3-live',
    decoder_name: 'live-probe-n3-flow-aggregator-0.1.0',
    decoder_version: '0.1.0',
    raw_payload_reference: 'n3-flow-aggregate:cap-n3-live:0x000000b3:1-128456',
    errors: [],
    ...overrides,
  };
}

describe('isN3Aggregate', () => {
  it('detects by decoder name prefix', () => {
    expect(isN3Aggregate(event())).toBe(true);
  });

  it('detects by raw payload reference prefix', () => {
    expect(
      isN3Aggregate(
        event({ decoder_name: 'decoder-gtpu', raw_payload_reference: 'n3-flow-aggregate:…' }),
      ),
    ).toBe(true);
  });

  it('falls back on the IE names when both decoder and payload labels are absent', () => {
    expect(
      isN3Aggregate(
        event({
          decoder_name: 'decoder-gtpu',
          raw_payload_reference: 'sha256:00',
        }),
      ),
    ).toBe(true);
  });

  it('does not flag a per-packet GTP-U event', () => {
    expect(
      isN3Aggregate(
        event({
          decoder_name: 'decoder-gtpu',
          raw_payload_reference: 'sha256:00',
          decoded_ie_tree: [ie('teid', '0x000000b3')],
        }),
      ),
    ).toBe(false);
  });

  it('does not flag non-N3 events even with aggregate-sounding names', () => {
    expect(
      isN3Aggregate(
        event({
          interface: 'N2',
          decoder_name: 'decoder-ngap',
          raw_payload_reference: 'sha256:00',
          decoded_ie_tree: [ie('aggregate_packet_count', '1')],
        }),
      ),
    ).toBe(false);
  });

  it('exposes the agreed wire-prefix constants', () => {
    expect(N3_AGGREGATOR_DECODER_PREFIX).toBe('live-probe-n3-flow-aggregator');
    expect(N3_AGGREGATOR_PAYLOAD_PREFIX).toBe('n3-flow-aggregate:');
  });
});

describe('summarizeN3Aggregate', () => {
  it('parses every counter and keeps teid / qfi raw', () => {
    const s = summarizeN3Aggregate(event());
    expect(s.teid).toBe('0x000000b3');
    expect(s.qfi).toBe('9');
    expect(s.packetCount).toBe(128_456);
    expect(s.wireBytes).toBe(148_967_424);
    expect(s.firstSeenNs).toBe('1792872281100000000');
    expect(s.lastSeenNs).toBe('1792872281513000000');
  });

  it('tolerates missing optional fields without throwing', () => {
    const s = summarizeN3Aggregate(
      event({
        decoded_ie_tree: [ie('teid', '0x000000b3')],
      }),
    );
    expect(s.teid).toBe('0x000000b3');
    expect(s.qfi).toBeNull();
    expect(s.packetCount).toBeNull();
    expect(s.wireBytes).toBeNull();
  });
});

describe('formatN3AggregateLabel', () => {
  it('renders the mockup label: "N3 agg · TEID 0x… · N pkts · N MiB · QFI N"', () => {
    expect(formatN3AggregateLabel(event())).toBe(
      'N3 agg · TEID 0x000000b3 · 128,456 pkts · 142.1 MiB · QFI 9',
    );
  });

  it('falls back to byte count under 1 MiB', () => {
    expect(
      formatN3AggregateLabel(
        event({
          decoded_ie_tree: [
            ie('teid', '0x1'),
            ie('aggregate_packet_count', '12'),
            ie('aggregate_wire_bytes', '512'),
          ],
        }),
      ),
    ).toBe('N3 agg · TEID 0x1 · 12 pkts · 512 B');
  });

  it('omits segments when the counter is missing', () => {
    expect(
      formatN3AggregateLabel(
        event({
          decoded_ie_tree: [ie('teid', '0x1')],
        }),
      ),
    ).toBe('N3 agg · TEID 0x1');
  });
});
