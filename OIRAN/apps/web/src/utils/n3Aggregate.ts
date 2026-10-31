// 2.5.1 — Analyzer helper for N3 aggregate rows (Codex e3376a1 /
// live-probe 0.2.6). The live-probe emits one `NormalizedEvent` per
// TEID × 5-tuple × QFI tunnel for N3 (never per packet) and tags the
// event with:
//   - `decoder_name` starting with `live-probe-n3-flow-aggregator`
//   - `raw_payload_reference` starting with `n3-flow-aggregate:`
//   - `decoded_ie_tree` containing four `InformationElement` entries
//     (`aggregate_packet_count`, `aggregate_wire_bytes`,
//     `aggregate_first_seen_ns`, `aggregate_last_seen_ns`)
//   - a `teid` + optional `qfi` field that remain in the IE tree too
//     (lifted from session_identifiers on the backend side).
//
// The Call-flow page uses `summarizeN3Aggregate()` to turn these into
// a single row that reads e.g.:
//   "N3 agg · TEID 0x000000b3 · 128 456 pkts · 142.1 MiB · QFI 9".
//
// Subscriber identity rule: the aggregate carries IP addresses in the
// outer 5-tuple only; no IMSI / IMEI / TMSI / GUTI / RNTI ever reaches
// it (identities live on the NGAP leg and are joined by TEID, not by
// identity).

import type { CallFlowEvent, InformationElement } from '../types/api';

export const N3_AGGREGATOR_DECODER_PREFIX = 'live-probe-n3-flow-aggregator';
export const N3_AGGREGATOR_PAYLOAD_PREFIX = 'n3-flow-aggregate:';

export function isN3Aggregate(event: CallFlowEvent): boolean {
  if (event.decoder_name.startsWith(N3_AGGREGATOR_DECODER_PREFIX)) return true;
  if (event.raw_payload_reference.startsWith(N3_AGGREGATOR_PAYLOAD_PREFIX)) return true;
  if (event.interface !== 'N3') return false;
  // Fallback: any event whose decoded_ie_tree carries the aggregate
  // counter names, regardless of decoder label.
  return event.decoded_ie_tree.some((ie) =>
    [
      'aggregate_packet_count',
      'aggregate_wire_bytes',
      'aggregate_first_seen_ns',
      'aggregate_last_seen_ns',
    ].includes(ie.name),
  );
}

export interface N3AggregateSummary {
  teid: string | null;
  qfi: string | null;
  packetCount: number | null;
  wireBytes: number | null;
  firstSeenNs: string | null;
  lastSeenNs: string | null;
}

function pickIe(tree: InformationElement[], name: string): InformationElement | null {
  for (const ie of tree) {
    if (ie.name === name) return ie;
    if (ie.children) {
      const nested = pickIe(ie.children, name);
      if (nested) return nested;
    }
  }
  return null;
}

function parseIntSafe(value: string | null | undefined): number | null {
  if (value == null) return null;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : null;
}

export function summarizeN3Aggregate(event: CallFlowEvent): N3AggregateSummary {
  const teid = pickIe(event.decoded_ie_tree, 'teid');
  const qfi = pickIe(event.decoded_ie_tree, 'qfi');
  const packet = pickIe(event.decoded_ie_tree, 'aggregate_packet_count');
  const wire = pickIe(event.decoded_ie_tree, 'aggregate_wire_bytes');
  const first = pickIe(event.decoded_ie_tree, 'aggregate_first_seen_ns');
  const last = pickIe(event.decoded_ie_tree, 'aggregate_last_seen_ns');
  return {
    teid: teid?.value ?? null,
    qfi: qfi?.value ?? null,
    packetCount: parseIntSafe(packet?.value),
    wireBytes: parseIntSafe(wire?.value),
    firstSeenNs: first?.value ?? null,
    lastSeenNs: last?.value ?? null,
  };
}

export function formatN3AggregateLabel(event: CallFlowEvent): string {
  const summary = summarizeN3Aggregate(event);
  const parts: string[] = ['N3 agg'];
  if (summary.teid) parts.push(`TEID ${summary.teid}`);
  if (summary.packetCount != null)
    parts.push(`${summary.packetCount.toLocaleString('en-US')} pkts`);
  if (summary.wireBytes != null) {
    const mb = summary.wireBytes / (1024 * 1024);
    parts.push(mb >= 1 ? `${mb.toFixed(1)} MiB` : `${summary.wireBytes} B`);
  }
  if (summary.qfi) parts.push(`QFI ${summary.qfi}`);
  return parts.join(' · ');
}
