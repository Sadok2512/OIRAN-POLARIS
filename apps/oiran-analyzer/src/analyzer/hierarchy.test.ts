import { describe, expect, it } from 'vitest';
import { buildHierarchy, buildUnknownBucket } from './hierarchy';
import type { CallFlow, Session, UeContext } from '@shared/types';

function makeUe(partial: Partial<UeContext> & { ue_context_id: string }): UeContext {
  return {
    ue_pseudonym: partial.ue_context_id,
    ran_endpoint: '',
    amf_endpoint: '',
    association_id: '',
    lifecycle_generation: 0,
    state: 'ACTIVE',
    first_timestamp_ns: '0',
    last_timestamp_ns: '0',
    event_count: 0,
    session_count: 0,
    ...partial,
  };
}

function makeSession(partial: Partial<Session> & { session_id: string; ue_context_id: string; pdu_session_id: string }): Session {
  return {
    dataset_id: 'ds-1',
    technology: '5G SA',
    ue_pseudonym: partial.ue_context_id,
    serving_node: 'gNB',
    procedure: 'PDU Session Establishment',
    start_timestamp: '2026-10-27T10:00:00Z',
    end_timestamp: '2026-10-27T10:01:00Z',
    duration_ns: '60000000000',
    interfaces: ['N2', 'N4'],
    message_count: 10,
    source_event_count: 10,
    background_event_count: 0,
    correlation_status: 'STRONG',
    decode_completeness: { decoded: 10, partial: 0, unresolved_fields: 0 },
    state: 'ACTIVE',
    ...partial,
  };
}

describe('hierarchy — multi-UE isolation', () => {
  it('keeps two UEs strictly separate even when they share a PDU session id', () => {
    const h = buildHierarchy(
      [makeUe({ ue_context_id: 'ue-A' }), makeUe({ ue_context_id: 'ue-B' })],
      [
        makeSession({ session_id: 's1', ue_context_id: 'ue-A', pdu_session_id: '1' }),
        makeSession({ session_id: 's2', ue_context_id: 'ue-B', pdu_session_id: '1' }),
      ],
    );
    expect(h).toHaveLength(2);
    const ueA = h.find((u) => u.ueContextId === 'ue-A');
    const ueB = h.find((u) => u.ueContextId === 'ue-B');
    expect(ueA?.pduSessions.map((p) => p.session.session_id)).toEqual(['s1']);
    expect(ueB?.pduSessions.map((p) => p.session.session_id)).toEqual(['s2']);
  });
});

describe('hierarchy — multiple PDU sessions per UE', () => {
  it('lists both PDU sessions under the same UE', () => {
    const h = buildHierarchy(
      [makeUe({ ue_context_id: 'ue-A' })],
      [
        makeSession({ session_id: 's1', ue_context_id: 'ue-A', pdu_session_id: '1' }),
        makeSession({ session_id: 's2', ue_context_id: 'ue-A', pdu_session_id: '2' }),
      ],
    );
    expect(h).toHaveLength(1);
    expect(h[0].pduSessions.map((p) => p.pduSessionId)).toEqual(['1', '2']);
  });
});

describe('hierarchy — multiple PFCP sessions / GTP-U tunnels per PDU', () => {
  it('extracts SEIDs and TEIDs from the backend decoded tree', () => {
    const callflow: CallFlow = {
      callflow_id: 'cf-1',
      session_id: 's1',
      technology: '5G SA',
      start_timestamp: '2026-10-27T10:00:00Z',
      end_timestamp: '2026-10-27T10:01:00Z',
      participants: [],
      interfaces: ['N2', 'N4', 'N3'],
      procedures: [],
      events: [
        {
          event_id: 'e1',
          timestamp: '2026-10-27T10:00:00Z',
          timestamp_ns: '0',
          interface: 'N4',
          protocol: 'PFCP',
          message_name: 'Session Establishment Request',
          source_participant: 'SMF',
          destination_participant: 'UPF',
          direction: 'OUT',
          decoded_ie_tree: [
            { id: 1, name: 'F-SEID', length: 8, value: '0x1111', raw_sha256: null, status: 'DECODED' },
            { id: 2, name: 'F-SEID', length: 8, value: '0x2222', raw_sha256: null, status: 'DECODED' },
          ],
          decoding_status: 'DECODED',
          semantic_status: 'NORMAL',
          association: 'SESSION',
          procedure_group: 'PFCP',
          packet_references: [],
          capture_id: 'cap-1',
          decoder_name: 'pfcp',
          decoder_version: '1.0',
          raw_payload_reference: '',
          errors: [],
        },
        {
          event_id: 'e2',
          timestamp: '2026-10-27T10:00:01Z',
          timestamp_ns: '1',
          interface: 'N3',
          protocol: 'GTP-U',
          message_name: 'G-PDU',
          source_participant: 'gNB',
          destination_participant: 'UPF',
          direction: 'OUT',
          decoded_ie_tree: [
            { id: null, name: 'TEID', length: 4, value: '0xDEADBEEF', raw_sha256: null, status: 'DECODED' },
          ],
          decoding_status: 'DECODED',
          semantic_status: 'NORMAL',
          association: 'SESSION',
          procedure_group: 'USER_PLANE',
          packet_references: [],
          capture_id: 'cap-1',
          decoder_name: 'gtpu',
          decoder_version: '1.0',
          raw_payload_reference: '',
          errors: [],
        },
      ],
      correlation_edges: [],
      correlation_status: { N2_N4: 'STRONG', N4_N3: 'STRONG', E2E: 'STRONG' },
      decoder_versions: {},
      schema_version: '1',
      capture_references: ['cap-1'],
      accounting: {
        source_events: 2,
        session_events: 2,
        background_events: 0,
        unmatched_events: 0,
        duplicate_events: 0,
        extra_events: 0,
      },
      unresolved_fields: 0,
    };
    const h = buildHierarchy(
      [makeUe({ ue_context_id: 'ue-A' })],
      [makeSession({ session_id: 's1', ue_context_id: 'ue-A', pdu_session_id: '1' })],
      new Map([['s1', callflow]]),
    );
    const node = h[0].pduSessions[0];
    expect(node.pfcpSeids).toEqual(expect.arrayContaining(['0x1111', '0x2222']));
    expect(node.gtpuTeids).toEqual(['0xDEADBEEF']);
  });
});

describe('hierarchy — unknown correlation handling', () => {
  it('keeps orphan sessions in a dedicated unknown bucket, never merging into another UE', () => {
    const ues = [makeUe({ ue_context_id: 'ue-A' })];
    const sessions = [
      makeSession({ session_id: 's1', ue_context_id: 'ue-A', pdu_session_id: '1' }),
      makeSession({
        session_id: 's2',
        ue_context_id: 'ue-UNKNOWN',
        pdu_session_id: '1',
        correlation_status: 'UNKNOWN',
      }),
    ];
    const h = buildHierarchy(ues, sessions);
    const unknown = buildUnknownBucket(ues, sessions);
    expect(h).toHaveLength(1);
    expect(h[0].pduSessions.map((p) => p.session.session_id)).toEqual(['s1']);
    expect(unknown.map((p) => p.session.session_id)).toEqual(['s2']);
  });
});

describe('hierarchy — missing fields render honestly', () => {
  it('does not fabricate IDs when the decoded tree is empty', () => {
    const h = buildHierarchy(
      [makeUe({ ue_context_id: 'ue-A' })],
      [makeSession({ session_id: 's1', ue_context_id: 'ue-A', pdu_session_id: '1' })],
    );
    const node = h[0].pduSessions[0];
    expect(node.pfcpSeids).toEqual([]);
    expect(node.gtpuTeids).toEqual([]);
    expect(node.qfis).toEqual([]);
    expect(node.flows).toEqual([]);
    expect(node.ueIp).toBe('');
    expect(node.directions).toEqual({});
  });
});

describe('hierarchy — defensive IE walker (backend ships Value, not strict array)', () => {
  function sessionWithIe(): Session {
    return makeSession({
      session_id: 's-ie',
      ue_context_id: 'ue-A',
      pdu_session_id: '1',
    });
  }
  function callflowWithIe(tree: unknown): CallFlow {
    return {
      callflow_id: 'cf',
      session_id: 's-ie',
      technology: '5G',
      start_timestamp: '',
      end_timestamp: '',
      participants: [],
      interfaces: [],
      procedures: [],
      events: [
        {
          event_id: 'e1',
          timestamp: '',
          timestamp_ns: '0',
          interface: 'N4',
          protocol: 'PFCP',
          message_name: 'SessionEstablishmentRequest',
          source_participant: 'SMF',
          destination_participant: 'UPF',
          direction: 'OUT',
          decoded_ie_tree: tree as never,
          decoding_status: 'DECODED',
          semantic_status: 'NORMAL',
          association: 'SESSION',
          procedure_group: 'PFCP',
          packet_references: [],
          capture_id: 'c1',
          decoder_name: 'pfcp',
          decoder_version: '1.0',
          raw_payload_reference: '',
          errors: [],
        },
      ],
      correlation_edges: [],
      correlation_status: { N2_N4: 'UNKNOWN', N4_N3: 'UNKNOWN', E2E: 'UNKNOWN' },
      decoder_versions: {},
      schema_version: '1',
      capture_references: [],
      accounting: {
        source_events: 1,
        session_events: 1,
        background_events: 0,
        unmatched_events: 0,
        duplicate_events: 0,
        extra_events: 0,
      },
      unresolved_fields: 0,
    };
  }

  it.each([null, undefined, {}, 'string', 42, [null, undefined, 'junk']])(
    'does not crash on malformed decoded_ie_tree = %p',
    (tree) => {
      const session = sessionWithIe();
      const callflow = callflowWithIe(tree);
      const h = buildHierarchy(
        [makeUe({ ue_context_id: 'ue-A' })],
        [session],
        new Map([[session.session_id, callflow]]),
      );
      expect(h[0].pduSessions[0].pfcpSeids).toEqual([]);
      expect(h[0].pduSessions[0].gtpuTeids).toEqual([]);
    },
  );

  it('extracts QFI values from the decoded tree', () => {
    const session = makeSession({
      session_id: 's-qfi',
      ue_context_id: 'ue-A',
      pdu_session_id: '1',
    });
    const callflow = callflowWithIe([
      { name: 'QFI', value: '9', children: [] },
      { name: 'QoSFlowID', value: '5', children: [] },
    ]);
    const h = buildHierarchy(
      [makeUe({ ue_context_id: 'ue-A' })],
      [session],
      new Map([[session.session_id, callflow]]),
    );
    expect(h[0].pduSessions[0].qfis).toEqual(expect.arrayContaining(['9', '5']));
  });
});

describe('hierarchy — runtime evidence surfacing', () => {
  it('merges TEIDs reported by runtime_evidence with those from the IE tree', () => {
    const session = makeSession({
      session_id: 's-live',
      ue_context_id: 'ue-A',
      pdu_session_id: '1',
      runtime_evidence: {
        ue_ip: '10.46.0.5',
        teids: ['0xRUNTIME-1', '0xRUNTIME-2'],
        directions: { '0xRUNTIME-1': 'UL', '0xRUNTIME-2': 'DL' },
      },
    });
    const callflow: CallFlow = {
      callflow_id: 'cf',
      session_id: 's-live',
      technology: '5G',
      start_timestamp: '',
      end_timestamp: '',
      participants: [],
      interfaces: [],
      procedures: [],
      events: [
        {
          event_id: 'e1',
          timestamp: '',
          timestamp_ns: '0',
          interface: 'N3',
          protocol: 'GTP-U',
          message_name: 'G-PDU',
          source_participant: 'gNB',
          destination_participant: 'UPF',
          direction: 'OUT',
          decoded_ie_tree: [
            { id: null, name: 'TEID', length: 4, value: '0xIE-ONLY', raw_sha256: null, status: 'DECODED' },
          ],
          decoding_status: 'DECODED',
          semantic_status: 'NORMAL',
          association: 'SESSION',
          procedure_group: 'USER_PLANE',
          packet_references: [],
          capture_id: 'c1',
          decoder_name: 'gtpu',
          decoder_version: '1.0',
          raw_payload_reference: '',
          errors: [],
        },
      ],
      correlation_edges: [],
      correlation_status: {
        N2_N4: 'UNKNOWN',
        N4_N3: 'UNKNOWN',
        E2E: 'UNKNOWN',
      },
      decoder_versions: {},
      schema_version: '1',
      capture_references: [],
      accounting: {
        source_events: 1,
        session_events: 1,
        background_events: 0,
        unmatched_events: 0,
        duplicate_events: 0,
        extra_events: 0,
      },
      unresolved_fields: 0,
    };
    const h = buildHierarchy(
      [makeUe({ ue_context_id: 'ue-A' })],
      [session],
      new Map([[session.session_id, callflow]]),
    );
    const node = h[0].pduSessions[0];
    expect(node.gtpuTeids).toEqual(
      expect.arrayContaining(['0xIE-ONLY', '0xRUNTIME-1', '0xRUNTIME-2']),
    );
    expect(node.ueIp).toBe('10.46.0.5');
    expect(node.directions['0xRUNTIME-1']).toBe('UL');
    expect(node.directions['0xRUNTIME-2']).toBe('DL');
  });
});
