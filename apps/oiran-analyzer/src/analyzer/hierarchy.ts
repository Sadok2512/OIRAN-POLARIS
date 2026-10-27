// Build the UE → PDU Session → PFCP / GTP-U / Flows hierarchy that the
// Session Explorer renders. Everything is derived from backend-reported
// data: no synthetic UE, no synthetic PDU session, no synthetic
// correlation.
import type {
  CallFlow,
  CallFlowEvent,
  Confidence,
  Session,
  UeContext,
} from '@shared/types';

export type HierarchyPduSession = {
  pduSessionId: string;
  session: Session;
  interfaces: string[];
  pfcpSeids: string[];
  gtpuTeids: string[];
  flows: HierarchyFlow[];
  eventCount: number;
  correlation: Confidence;
};

export type HierarchyUe = {
  ueContextId: string;
  context: UeContext;
  pduSessions: HierarchyPduSession[];
  nasEventCount: number;
  totalSessions: number;
};

export type HierarchyFlow = {
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'OTHER';
  source: string;
  destination: string;
  packetCount: number;
};

/**
 * Group a flat list of backend sessions under their reported UE
 * context. Multi-UE isolation is preserved by keying strictly on
 * `ue_context_id`. Multi-PDU-session UEs appear with every reported
 * `pdu_session_id` listed as a child.
 *
 * UEs with no backend-reported pseudonym fall back to the raw context
 * id so the tree does not render a blank label. The function never
 * fabricates a UE from a session alone — a Session whose `ue_context_id`
 * does not resolve to a known UeContext is placed under an explicit
 * `UNKNOWN` bucket by `buildUnknownBucket`.
 */
export function buildHierarchy(
  ues: UeContext[],
  sessions: Session[],
  callFlowsBySessionId?: Map<string, CallFlow | undefined>,
): HierarchyUe[] {
  const ueById = new Map<string, UeContext>();
  for (const ue of ues) ueById.set(ue.ue_context_id, ue);

  // Group sessions by UE context id.
  const grouped = new Map<string, Session[]>();
  for (const session of sessions) {
    const key = session.ue_context_id;
    if (!ueById.has(key)) continue;
    const list = grouped.get(key) ?? [];
    list.push(session);
    grouped.set(key, list);
  }

  const hierarchy: HierarchyUe[] = [];
  for (const [ueId, list] of grouped) {
    const context = ueById.get(ueId)!;
    const pduSessions = list.map((session) =>
      buildPduSessionNode(session, callFlowsBySessionId?.get(session.session_id)),
    );
    hierarchy.push({
      ueContextId: ueId,
      context,
      pduSessions,
      nasEventCount: countNasEvents(pduSessions),
      totalSessions: list.length,
    });
  }
  // Stable ordering by first PDU timestamp (fallback: UE pseudonym).
  hierarchy.sort((a, b) => {
    const ta = a.pduSessions[0]?.session.start_timestamp ?? '';
    const tb = b.pduSessions[0]?.session.start_timestamp ?? '';
    if (ta && tb) return ta.localeCompare(tb);
    return a.context.ue_pseudonym.localeCompare(b.context.ue_pseudonym);
  });
  return hierarchy;
}

/**
 * Separate bucket for sessions whose UE context the backend did not
 * publish. Must stay visible so operators can see unresolved data —
 * never silently merged into a neighbouring UE.
 */
export function buildUnknownBucket(
  ues: UeContext[],
  sessions: Session[],
): HierarchyPduSession[] {
  const known = new Set(ues.map((u) => u.ue_context_id));
  const orphans = sessions.filter((s) => !known.has(s.ue_context_id));
  return orphans.map((session) => buildPduSessionNode(session, undefined));
}

function buildPduSessionNode(
  session: Session,
  callflow: CallFlow | undefined,
): HierarchyPduSession {
  const events: CallFlowEvent[] = callflow?.events ?? [];
  const pfcpSeids = Array.from(collectIeValues(events, /\b(?:F?SEID|seid)\b/i));
  const gtpuTeids = Array.from(collectIeValues(events, /\bTEID\b/i));
  const flows = aggregateFlows(events);
  return {
    pduSessionId: session.pdu_session_id,
    session,
    interfaces: session.interfaces,
    pfcpSeids,
    gtpuTeids,
    flows,
    eventCount: events.length || session.message_count,
    correlation: session.correlation_status,
  };
}

function countNasEvents(pduSessions: HierarchyPduSession[]): number {
  // Approximation: NAS events live on N2 (NAS-5GMM) and inside PDU
  // sessions on N2 (NAS-5GSM). We expose only the raw backend-reported
  // message counts; the renderer labels this honestly as "NAS / Mobility".
  return pduSessions.reduce(
    (sum, node) =>
      sum +
      node.interfaces.filter((iface) => iface.toUpperCase().includes('N2'))
        .length,
    0,
  );
}

function collectIeValues(
  events: CallFlowEvent[],
  nameRegex: RegExp,
): Set<string> {
  const seen = new Set<string>();
  for (const event of events) {
    walkIe(event.decoded_ie_tree, (ie) => {
      if (nameRegex.test(ie.name) && ie.value) seen.add(ie.value);
    });
  }
  return seen;
}

function walkIe(
  tree: CallFlowEvent['decoded_ie_tree'],
  visit: (ie: CallFlowEvent['decoded_ie_tree'][number]) => void,
): void {
  for (const ie of tree) {
    visit(ie);
    if (ie.children?.length) walkIe(ie.children, visit);
  }
}

function aggregateFlows(events: CallFlowEvent[]): HierarchyFlow[] {
  const flows = new Map<string, HierarchyFlow>();
  for (const event of events) {
    // User-plane events live on N3 (GTP-U). Signaling events (N2, N4,
    // SBI) are not flows.
    if (!/^N3$|GTP|USERPLANE/i.test(event.interface)) continue;
    const protocol = normalizeProtocol(event.protocol);
    const key = `${protocol}|${event.source_participant}|${event.destination_participant}`;
    const existing = flows.get(key);
    if (existing) {
      existing.packetCount += 1;
    } else {
      flows.set(key, {
        protocol,
        source: event.source_participant,
        destination: event.destination_participant,
        packetCount: 1,
      });
    }
  }
  return [...flows.values()].sort((a, b) => b.packetCount - a.packetCount);
}

function normalizeProtocol(protocol: string): HierarchyFlow['protocol'] {
  const upper = protocol.toUpperCase();
  if (upper.includes('TCP')) return 'TCP';
  if (upper.includes('UDP')) return 'UDP';
  if (upper.includes('ICMP')) return 'ICMP';
  return 'OTHER';
}
