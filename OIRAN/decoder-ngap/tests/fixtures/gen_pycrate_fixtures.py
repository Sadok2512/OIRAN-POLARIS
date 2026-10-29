#!/usr/bin/env python3
"""Generate NGAP APER ground-truth fixtures from the real TS 38.413 ASN.1
module shipped with pycrate (pycrate_asn1dir.NGAP). Values are synthetic:
PLMNs are 001/01 (test PLMN), IPs are TEST-NET-1/2 (RFC 5737), TEIDs are
fictional (notably 0x11223344 for the guard-rail), NAS-PDU is a plain
5GMM Registration Reject.

Run inside the asn1tools venv (pycrate is installed there):
    /tmp/asn1tools-env/bin/python3 .../gen_pycrate_fixtures.py

Writes:
    pycrate_fixtures.json  — list of {name, pdu_type, hex, bytes, notes}
"""
import json

from pycrate_asn1dir import NGAP

ies_mod = NGAP.NGAP_IEs
pdu_mod = NGAP.NGAP_PDU_Contents
desc_mod = NGAP.NGAP_PDU_Descriptions


def encode(type_name, module, value):
    t = getattr(module, type_name)
    t.set_val(value)
    return t.to_aper()


FIXTURES = []


def add(name, pdu_type, module, value, notes=''):
    data = encode(pdu_type, module, value)
    FIXTURES.append({
        'name': name,
        'pdu_type': pdu_type,
        'module': module.__name__.rsplit('.', 1)[-1],
        'hex': data.hex(),
        'bytes': len(data),
        'notes': notes,
    })


# ---- Transfer-level fixtures (used by decode_pdu_session_resource_setup_*
# _transfer public entry points) ----

# T1: minimal Request — UL tunnel + PDU session type + 1 QFI.
add('request_transfer_minimal',
    'PDUSessionResourceSetupRequestTransfer', ies_mod,
    {'protocolIEs': [
        {'id': 139, 'criticality': 'reject',
         'value': ('UPTransportLayerInformation', ('gTPTunnel', {
             'transportLayerAddress': (0xc0000201, 32),
             'gTP-TEID': b'\x11\x22\x33\x44',
         }))},
        {'id': 134, 'criticality': 'reject',
         'value': ('PDUSessionType', 'ipv4')},
        {'id': 136, 'criticality': 'reject',
         'value': ('QosFlowSetupRequestList', [
             {'qosFlowIdentifier': 5,
              'qosFlowLevelQosParameters': {
                  'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 9}),
                  'allocationAndRetentionPriority': {
                      'priorityLevelARP': 7,
                      'pre-emptionCapability': 'may-trigger-pre-emption',
                      'pre-emptionVulnerability': 'not-pre-emptable',
                  },
              }},
         ])},
    ]},
    'TEID=0x11223344 QFI=5 fiveQI=9 ARP=(7,may,not) IPv4 192.0.2.1')

# T2: Request with AMBR and 3 QFIs including GBR on one of them.
add('request_transfer_with_ambr_gbr',
    'PDUSessionResourceSetupRequestTransfer', ies_mod,
    {'protocolIEs': [
        {'id': 130, 'criticality': 'reject',
         'value': ('PDUSessionAggregateMaximumBitRate', {
             'pDUSessionAggregateMaximumBitRateDL': 2_000_000,
             'pDUSessionAggregateMaximumBitRateUL': 1_000_000,
         })},
        {'id': 139, 'criticality': 'reject',
         'value': ('UPTransportLayerInformation', ('gTPTunnel', {
             'transportLayerAddress': (0xc0000202, 32),
             'gTP-TEID': b'\x00\x00\xbe\xef',
         }))},
        {'id': 134, 'criticality': 'reject',
         'value': ('PDUSessionType', 'ipv6')},
        {'id': 136, 'criticality': 'reject',
         'value': ('QosFlowSetupRequestList', [
             {'qosFlowIdentifier': 1,
              'qosFlowLevelQosParameters': {
                  'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 5}),
                  'allocationAndRetentionPriority': {
                      'priorityLevelARP': 1,
                      'pre-emptionCapability': 'shall-not-trigger-pre-emption',
                      'pre-emptionVulnerability': 'pre-emptable',
                  }}},
             {'qosFlowIdentifier': 9,
              'qosFlowLevelQosParameters': {
                  'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 7}),
                  'allocationAndRetentionPriority': {
                      'priorityLevelARP': 15,
                      'pre-emptionCapability': 'may-trigger-pre-emption',
                      'pre-emptionVulnerability': 'pre-emptable',
                  },
                  'gBR-QosInformation': {
                      'maximumFlowBitRateDL': 2_000_000,
                      'maximumFlowBitRateUL': 1_000_000,
                      'guaranteedFlowBitRateDL': 1_500_000,
                      'guaranteedFlowBitRateUL': 750_000,
                  }}},
             {'qosFlowIdentifier': 63,
              'qosFlowLevelQosParameters': {
                  'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 255}),
                  'allocationAndRetentionPriority': {
                      'priorityLevelARP': 8,
                      'pre-emptionCapability': 'may-trigger-pre-emption',
                      'pre-emptionVulnerability': 'not-pre-emptable',
                  }}},
         ])},
    ]},
    'AMBR + 3 QFIs including GBR QoS on QFI 9')

# T3: Response — minimal.
add('response_transfer_minimal',
    'PDUSessionResourceSetupResponseTransfer', ies_mod,
    {'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (0xc0000203, 32),
            'gTP-TEID': b'\x11\x22\x33\x44',
        }),
        'associatedQosFlowList': [{'qosFlowIdentifier': 5}],
    }},
    'DL TEID=0x11223344 associated QFI=5')

# T4: Response — all optionals + extension redundant DL tunnel.
add('response_transfer_all_optionals',
    'PDUSessionResourceSetupResponseTransfer', ies_mod,
    {'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (0xc0000204, 32),
            'gTP-TEID': b'\x00\x00\xa0\xa0',
        }),
        'associatedQosFlowList': [{'qosFlowIdentifier': 1}],
     },
     'additionalDLQosFlowPerTNLInformation': [
         {'qosFlowPerTNLInformation': {
             'uPTransportLayerInformation': ('gTPTunnel', {
                 'transportLayerAddress': (0xc0000205, 32),
                 'gTP-TEID': b'\x00\x00\xa0\xa1',
             }),
             'associatedQosFlowList': [{'qosFlowIdentifier': 2}],
         }},
     ],
     'securityResult': {
         'integrityProtectionResult': 'performed',
         'confidentialityProtectionResult': 'performed',
     },
     'qosFlowFailedToSetupList': [
         {'qosFlowIdentifier': 20, 'cause': ('misc', 'unspecified')},
     ]},
    'Top-level additional DL + security + failed; redundant is an extension')


# ---- Guard-rail fixture: TEID=0x11223344 and QFI=5 must round-trip exactly.
add('guard_rail_teid_11223344_qfi_5',
    'PDUSessionResourceSetupRequestTransfer', ies_mod,
    {'protocolIEs': [
        {'id': 139, 'criticality': 'reject',
         'value': ('UPTransportLayerInformation', ('gTPTunnel', {
             'transportLayerAddress': (0x0a4d0b16, 32),
             'gTP-TEID': b'\x11\x22\x33\x44',
         }))},
        {'id': 134, 'criticality': 'reject',
         'value': ('PDUSessionType', 'ipv4')},
        {'id': 136, 'criticality': 'reject',
         'value': ('QosFlowSetupRequestList', [
             {'qosFlowIdentifier': 5,
              'qosFlowLevelQosParameters': {
                  'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 9}),
                  'allocationAndRetentionPriority': {
                      'priorityLevelARP': 1,
                      'pre-emptionCapability': 'shall-not-trigger-pre-emption',
                      'pre-emptionVulnerability': 'not-pre-emptable',
                  }}},
         ])},
    ]},
    'Guard-rail: exact TEID=0x11223344 and QFI=5 round-trip')


# ---- Full-PDU fixtures (NGAP messages wrapped in NGAP-PDU) ----

def build_setup_request_pdu(session_items):
    """Build a complete InitiatingMessage NGAP-PDU for
    PDUSessionResourceSetupRequest with the given per-session items.
    Each session_item is a dict with pDUSessionID + nested transfer bytes.
    """
    ies = [
        {'id': 10, 'criticality': 'reject',
         'value': ('AMF-UE-NGAP-ID', 12)},
        {'id': 85, 'criticality': 'reject',
         'value': ('RAN-UE-NGAP-ID', 12)},
        {'id': 74, 'criticality': 'reject',
         'value': ('PDUSessionResourceSetupListSUReq', session_items)},
    ]
    return ('initiatingMessage', {
        'procedureCode': 29,
        'criticality': 'reject',
        'value': ('PDUSessionResourceSetupRequest', {'protocolIEs': ies}),
    })


def build_setup_response_pdu(session_items):
    return ('successfulOutcome', {
        'procedureCode': 29,
        'criticality': 'reject',
        'value': ('PDUSessionResourceSetupResponse', {'protocolIEs': [
            {'id': 10, 'criticality': 'ignore',
             'value': ('AMF-UE-NGAP-ID', 12)},
            {'id': 85, 'criticality': 'ignore',
             'value': ('RAN-UE-NGAP-ID', 12)},
            {'id': 75, 'criticality': 'ignore',
             'value': ('PDUSessionResourceSetupListSURes', session_items)},
        ]}),
    })


def build_initial_context_setup_request_pdu(cxt_items):
    return ('initiatingMessage', {
        'procedureCode': 14,
        'criticality': 'reject',
        'value': ('InitialContextSetupRequest', {'protocolIEs': [
            {'id': 10, 'criticality': 'reject',
             'value': ('AMF-UE-NGAP-ID', 12)},
            {'id': 85, 'criticality': 'reject',
             'value': ('RAN-UE-NGAP-ID', 12)},
            {'id': 28, 'criticality': 'reject',
             'value': ('GUAMI', {
                 'pLMNIdentity': b'\x00\xf1\x10',
                 'aMFRegionID': (0x02, 8),
                 'aMFSetID': (0x40, 10),
                 'aMFPointer': (0x00, 6),
             })},
            {'id': 71, 'criticality': 'reject',
             'value': ('PDUSessionResourceSetupListCxtReq', cxt_items)},
            {'id': 94, 'criticality': 'reject',
             'value': ('SecurityKey', (0, 256))},
            {'id': 119, 'criticality': 'reject',
             'value': ('UESecurityCapabilities', {
                 'nRencryptionAlgorithms': (0xe000, 16),
                 'nRintegrityProtectionAlgorithms': (0xc000, 16),
                 'eUTRAencryptionAlgorithms': (0xe000, 16),
                 'eUTRAintegrityProtectionAlgorithms': (0xc000, 16),
             })},
        ]}),
    })


def build_initial_context_setup_response_pdu(cxt_items):
    return ('successfulOutcome', {
        'procedureCode': 14,
        'criticality': 'reject',
        'value': ('InitialContextSetupResponse', {'protocolIEs': [
            {'id': 10, 'criticality': 'ignore',
             'value': ('AMF-UE-NGAP-ID', 12)},
            {'id': 85, 'criticality': 'ignore',
             'value': ('RAN-UE-NGAP-ID', 12)},
            {'id': 72, 'criticality': 'ignore',
             'value': ('PDUSessionResourceSetupListCxtRes', cxt_items)},
        ]}),
    })


minimal_req_transfer = encode(
    'PDUSessionResourceSetupRequestTransfer', ies_mod,
    {'protocolIEs': [
        {'id': 139, 'criticality': 'reject',
         'value': ('UPTransportLayerInformation', ('gTPTunnel', {
             'transportLayerAddress': (0x0a4d0b17, 32),
             'gTP-TEID': b'\x11\x22\x33\x44',
         }))},
        {'id': 134, 'criticality': 'reject',
         'value': ('PDUSessionType', 'ipv4')},
        {'id': 136, 'criticality': 'reject',
         'value': ('QosFlowSetupRequestList', [
             {'qosFlowIdentifier': 5,
              'qosFlowLevelQosParameters': {
                  'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 9}),
                  'allocationAndRetentionPriority': {
                      'priorityLevelARP': 1,
                      'pre-emptionCapability': 'shall-not-trigger-pre-emption',
                      'pre-emptionVulnerability': 'not-pre-emptable',
                  }}},
         ])},
    ]})

minimal_res_transfer = encode(
    'PDUSessionResourceSetupResponseTransfer', ies_mod,
    {'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (0x0a4d0b18, 32),
            'gTP-TEID': b'\x11\x22\x33\x44',
        }),
        'associatedQosFlowList': [{'qosFlowIdentifier': 5}],
    }})


# P1: Full PDUSessionResourceSetupRequest, 1 session (SU-Req).
add('pdu_setup_request_1_session', 'NGAP_PDU', desc_mod,
    build_setup_request_pdu([{
        'pDUSessionID': 5,
        's-NSSAI': {'sST': b'\x01'},
        'pDUSessionResourceSetupRequestTransfer': minimal_req_transfer,
    }]),
    'Full PDU: 1 session, SU-Req path, SST-only')

# P2: Full PDUSessionResourceSetupResponse, 1 session (SU-Res).
add('pdu_setup_response_1_session', 'NGAP_PDU', desc_mod,
    build_setup_response_pdu([{
        'pDUSessionID': 5,
        'pDUSessionResourceSetupResponseTransfer': minimal_res_transfer,
    }]),
    'Full PDU: 1 session, SU-Res path')

# P3: InitialContextSetupRequest with 1 session via Cxt-Req path.
add('pdu_initial_context_setup_request_1_session', 'NGAP_PDU', desc_mod,
    build_initial_context_setup_request_pdu([{
        'pDUSessionID': 5,
        's-NSSAI': {'sST': b'\x01'},
        'pDUSessionResourceSetupRequestTransfer': minimal_req_transfer,
    }]),
    'InitialContextSetupRequest carrying 1 PDU session (Cxt-Req path)')

# P4: InitialContextSetupResponse with 1 session via Cxt-Res path.
add('pdu_initial_context_setup_response_1_session', 'NGAP_PDU', desc_mod,
    build_initial_context_setup_response_pdu([{
        'pDUSessionID': 5,
        'pDUSessionResourceSetupResponseTransfer': minimal_res_transfer,
    }]),
    'InitialContextSetupResponse carrying 1 PDU session (Cxt-Res path)')


# Write out.
with open('/tmp/ngap-asn1/pycrate_fixtures.json', 'w') as f:
    json.dump(FIXTURES, f, indent=2)

for f in FIXTURES:
    print(f"{f['name']:48s} {f['bytes']:4d}B  {f['hex']}")
