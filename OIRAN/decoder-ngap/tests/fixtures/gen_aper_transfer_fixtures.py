#!/usr/bin/env python3
"""Generate NGAP APER fixtures from the minimal TS 38.413 subset using asn1tools."""
import asn1tools
import json

ngap = asn1tools.compile_files('/tmp/ngap-asn1/minimal.asn', 'per')

fixtures = []


def add(name, pdu_type, value, notes=''):
    encoded = ngap.encode(pdu_type, value)
    roundtrip = ngap.decode(pdu_type, encoded)
    fixtures.append({
        'name': name,
        'pdu_type': pdu_type,
        'hex': encoded.hex(),
        'bytes': len(encoded),
        'value': value,
        'roundtrip': roundtrip,
        'notes': notes,
    })


# ---- Response Transfer fixtures ----

# R1: minimal — single QFI, no optionals.
add('response_minimal', 'PDUSessionResourceSetupResponseTransfer', {
    'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (b'\xc0\x00\x02\x01', 32),
            'gTP-TEID': b'\xca\xfe\xba\xbe',
        }),
        'associatedQosFlowList': [{'qosFlowIdentifier': 5}],
    },
}, 'IPv4 TEST-NET-1, 1 QFI, no optionals')

# R2: 3 QFIs with mapping indicator on one of them
add('response_three_qfi_with_mapping', 'PDUSessionResourceSetupResponseTransfer', {
    'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (b'\xc0\x00\x02\x02', 32),
            'gTP-TEID': b'\x00\x00\xbe\xef',
        }),
        'associatedQosFlowList': [
            {'qosFlowIdentifier': 1},
            {'qosFlowIdentifier': 9, 'qosFlowMappingIndication': 'ul'},
            {'qosFlowIdentifier': 63},
        ],
    },
}, '3 QFIs including one with ul mapping indication')

# R3: additionalDLQosFlowPerTNLInformation list of 2 extra tunnels
add('response_additional_dl_list', 'PDUSessionResourceSetupResponseTransfer', {
    'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (b'\xc0\x00\x02\x03', 32),
            'gTP-TEID': b'\x00\x00\x00\x01',
        }),
        'associatedQosFlowList': [{'qosFlowIdentifier': 2}],
    },
    'additionalDLQosFlowPerTNLInformation': [
        {'qosFlowPerTNLInformation': {
            'uPTransportLayerInformation': ('gTPTunnel', {
                'transportLayerAddress': (b'\xc0\x00\x02\x04', 32),
                'gTP-TEID': b'\x00\x00\x00\x02',
            }),
            'associatedQosFlowList': [{'qosFlowIdentifier': 3}],
        }},
        {'qosFlowPerTNLInformation': {
            'uPTransportLayerInformation': ('gTPTunnel', {
                'transportLayerAddress': (b'\xc0\x00\x02\x05', 32),
                'gTP-TEID': b'\x00\x00\x00\x03',
            }),
            'associatedQosFlowList': [{'qosFlowIdentifier': 4}, {'qosFlowIdentifier': 5}],
        }},
    ],
}, '2 additional DL per-TNL tunnels')

# R4: qosFlowFailedToSetupList with causes
add('response_failed_list', 'PDUSessionResourceSetupResponseTransfer', {
    'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (b'\xc0\x00\x02\x06', 32),
            'gTP-TEID': b'\x12\x34\x56\x78',
        }),
        'associatedQosFlowList': [{'qosFlowIdentifier': 3}],
    },
    'qosFlowFailedToSetupList': [
        {'qosFlowIdentifier': 4, 'cause': ('radioNetwork', 'unspecified')},
        {'qosFlowIdentifier': 7, 'cause': ('transport', 'transport-resource-unavailable')},
        {'qosFlowIdentifier': 12, 'cause': ('nas', 'authentication-failure')},
    ],
}, '3 failed QFIs with different cause groups')

# R5: SecurityResult present with mixed state
add('response_security_result', 'PDUSessionResourceSetupResponseTransfer', {
    'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (b'\xc0\x00\x02\x07', 32),
            'gTP-TEID': b'\x00\x00\x01\x01',
        }),
        'associatedQosFlowList': [{'qosFlowIdentifier': 15}],
    },
    'securityResult': {
        'integrityProtectionResult': 'performed',
        'confidentialityProtectionResult': 'not-performed',
    },
}, 'Security result present, integrity=performed, confidentiality=not-performed')

# R6: All optionals present
add('response_all_optionals', 'PDUSessionResourceSetupResponseTransfer', {
    'dLQosFlowPerTNLInformation': {
        'uPTransportLayerInformation': ('gTPTunnel', {
            'transportLayerAddress': (b'\xc0\x00\x02\x08', 32),
            'gTP-TEID': b'\x00\x00\xa0\xa0',
        }),
        'associatedQosFlowList': [{'qosFlowIdentifier': 1}],
    },
    'additionalDLQosFlowPerTNLInformation': [
        {'qosFlowPerTNLInformation': {
            'uPTransportLayerInformation': ('gTPTunnel', {
                'transportLayerAddress': (b'\xc0\x00\x02\x09', 32),
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
    ],
}, 'All optionals present: additional, security, failed')


# ---- Request Transfer fixtures ----

# Q1: minimal — only required fields
add('request_minimal', 'PDUSessionResourceSetupRequestTransfer', {
    'uLNGU-UP-TNLInformation': ('gTPTunnel', {
        'transportLayerAddress': (b'\x0a\x4d\x0b\x16', 32),
        'gTP-TEID': b'\xca\xfe\xba\xbe',
    }),
    'pDUSessionType': 'ipv4',
    'qosFlowSetupRequestList': [{
        'qosFlowIdentifier': 1,
        'qosFlowLevelQosParameters': {
            'qoS-Characteristics': ('nonDynamic5QI', {'fiveQI': 9}),
            'allocationAndRetentionPriority': {
                'priorityLevelARP': 7,
                'pre-emptionCapability': 'may-trigger-pre-emption',
                'pre-emptionVulnerability': 'not-pre-emptable',
            },
        },
    }],
}, 'Minimal request transfer, 1 QFI, nonDynamic5QI=9, ARP priority 7')

# Q2: 3 QFIs
add('request_three_qfi_non_dynamic_5qi', 'PDUSessionResourceSetupRequestTransfer', {
    'uLNGU-UP-TNLInformation': ('gTPTunnel', {
        'transportLayerAddress': (b'\x0a\x4d\x0b\x17', 32),
        'gTP-TEID': b'\x00\x00\xbe\xef',
    }),
    'pDUSessionType': 'ipv6',
    'qosFlowSetupRequestList': [
        {
            'qosFlowIdentifier': 1,
            'qosFlowLevelQosParameters': {
                'qoS-Characteristics': ('nonDynamic5QI', {'fiveQI': 5}),
                'allocationAndRetentionPriority': {
                    'priorityLevelARP': 1,
                    'pre-emptionCapability': 'shall-not-trigger-pre-emption',
                    'pre-emptionVulnerability': 'pre-emptable',
                },
            },
        },
        {
            'qosFlowIdentifier': 9,
            'qosFlowLevelQosParameters': {
                'qoS-Characteristics': ('nonDynamic5QI', {'fiveQI': 7}),
                'allocationAndRetentionPriority': {
                    'priorityLevelARP': 15,
                    'pre-emptionCapability': 'may-trigger-pre-emption',
                    'pre-emptionVulnerability': 'pre-emptable',
                },
            },
        },
        {
            'qosFlowIdentifier': 63,
            'qosFlowLevelQosParameters': {
                'qoS-Characteristics': ('nonDynamic5QI', {'fiveQI': 255}),
                'allocationAndRetentionPriority': {
                    'priorityLevelARP': 8,
                    'pre-emptionCapability': 'may-trigger-pre-emption',
                    'pre-emptionVulnerability': 'not-pre-emptable',
                },
            },
        },
    ],
}, '3 QFIs with varying 5QI/ARP/capability/vulnerability')

# Q3: gBR-QosInformation optional present
add('request_with_gbr', 'PDUSessionResourceSetupRequestTransfer', {
    'uLNGU-UP-TNLInformation': ('gTPTunnel', {
        'transportLayerAddress': (b'\x0a\x4d\x0b\x18', 32),
        'gTP-TEID': b'\x01\x02\x03\x04',
    }),
    'pDUSessionType': 'ethernet',
    'qosFlowSetupRequestList': [{
        'qosFlowIdentifier': 5,
        'qosFlowLevelQosParameters': {
            'qoS-Characteristics': ('nonDynamic5QI', {'fiveQI': 1}),
            'allocationAndRetentionPriority': {
                'priorityLevelARP': 3,
                'pre-emptionCapability': 'may-trigger-pre-emption',
                'pre-emptionVulnerability': 'not-pre-emptable',
            },
            'gBR-QosInformation': {
                'maximumFlowBitRateDL': 2_000_000,
                'maximumFlowBitRateUL': 1_000_000,
                'guaranteedFlowBitRateDL': 1_500_000,
                'guaranteedFlowBitRateUL': 750_000,
            },
        },
    }],
}, 'GBR QoS parameters present on QFI 5')

# Q4: dynamic5QI
add('request_with_dynamic_5qi', 'PDUSessionResourceSetupRequestTransfer', {
    'uLNGU-UP-TNLInformation': ('gTPTunnel', {
        'transportLayerAddress': (b'\x0a\x4d\x0b\x19', 32),
        'gTP-TEID': b'\x05\x06\x07\x08',
    }),
    'pDUSessionType': 'ipv4v6',
    'qosFlowSetupRequestList': [{
        'qosFlowIdentifier': 10,
        'qosFlowLevelQosParameters': {
            'qoS-Characteristics': ('dynamic5QI', {
                'priorityLevelQos': 42,
                'packetDelayBudget': 100,
                'packetErrorRate': {'pERScalar': 1, 'pERExponent': 6},
            }),
            'allocationAndRetentionPriority': {
                'priorityLevelARP': 2,
                'pre-emptionCapability': 'may-trigger-pre-emption',
                'pre-emptionVulnerability': 'pre-emptable',
            },
        },
    }],
}, 'dynamic5QI with priority 42, PDB 100ms, PER 1e-6')

# Q5: reflectiveQoSAttribute present
add('request_with_reflective_qos', 'PDUSessionResourceSetupRequestTransfer', {
    'uLNGU-UP-TNLInformation': ('gTPTunnel', {
        'transportLayerAddress': (b'\x0a\x4d\x0b\x1a', 32),
        'gTP-TEID': b'\x09\x0a\x0b\x0c',
    }),
    'pDUSessionType': 'unstructured',
    'qosFlowSetupRequestList': [{
        'qosFlowIdentifier': 20,
        'qosFlowLevelQosParameters': {
            'qoS-Characteristics': ('nonDynamic5QI', {'fiveQI': 2}),
            'allocationAndRetentionPriority': {
                'priorityLevelARP': 5,
                'pre-emptionCapability': 'may-trigger-pre-emption',
                'pre-emptionVulnerability': 'pre-emptable',
            },
            'reflectiveQoSAttribute': 'subject-to',
        },
    }],
}, 'Reflective QoS subject-to on QFI 20')


# ---- Outer list fixtures (PDUSessionResourceSetupListSUReq/SURes) ----

# The inner transfer OCTET STRING is kept to a 1-byte stub so the outer-walker
# ground truth stays small and deterministic. The outer walker is responsible
# for extracting the transfer bytes verbatim; the inner decoder is already
# validated by the request_* / response_* fixtures above.
TRANSFER_STUB = b'\xab'

add('list_sureq_1_session_sst_only', 'PDUSessionResourceSetupListSUReq', [
    {
        'pDUSessionID': 5,
        's-NSSAI': {'sST': b'\x01'},
        'pDUSessionResourceSetupRequestTransfer': TRANSFER_STUB,
    },
], 'SU-Req 1 session SST-only no NAS-PDU no iE-Ext')

add('list_sureq_1_session_with_nas_pdu', 'PDUSessionResourceSetupListSUReq', [
    {
        'pDUSessionID': 7,
        'pDUSessionNAS-PDU': b'\x7e\x00\x44\x6f',
        's-NSSAI': {'sST': b'\x01'},
        'pDUSessionResourceSetupRequestTransfer': TRANSFER_STUB,
    },
], 'SU-Req 1 session with 4-byte NAS-PDU SST-only')

add('list_sureq_1_session_sst_sd', 'PDUSessionResourceSetupListSUReq', [
    {
        'pDUSessionID': 9,
        's-NSSAI': {'sST': b'\x01', 'sD': b'\x02\x03\x04'},
        'pDUSessionResourceSetupRequestTransfer': TRANSFER_STUB,
    },
], 'SU-Req 1 session SST+SD slice differentiator')

add('list_sureq_1_session_item_ie_ext', 'PDUSessionResourceSetupListSUReq', [
    {
        'pDUSessionID': 11,
        's-NSSAI': {'sST': b'\x01'},
        'pDUSessionResourceSetupRequestTransfer': TRANSFER_STUB,
        'iE-Extensions': {'dummy': 0},
    },
], 'SU-Req 1 session item iE-Extensions present')

add('list_sureq_3_sessions_mixed', 'PDUSessionResourceSetupListSUReq', [
    {
        'pDUSessionID': 1,
        'pDUSessionNAS-PDU': b'\x7e\x00\x44\x6f',
        's-NSSAI': {'sST': b'\x01'},
        'pDUSessionResourceSetupRequestTransfer': TRANSFER_STUB,
    },
    {
        'pDUSessionID': 2,
        's-NSSAI': {'sST': b'\x01', 'sD': b'\x01\x02\x03'},
        'pDUSessionResourceSetupRequestTransfer': TRANSFER_STUB,
    },
    {
        'pDUSessionID': 3,
        's-NSSAI': {'sST': b'\x02'},
        'pDUSessionResourceSetupRequestTransfer': TRANSFER_STUB,
        'iE-Extensions': {'dummy': 0},
    },
], 'SU-Req 3 sessions: #1 NAS-PDU, #2 SST+SD, #3 iE-Ext')

add('list_sures_1_session', 'PDUSessionResourceSetupListSURes', [
    {
        'pDUSessionID': 5,
        'pDUSessionResourceSetupResponseTransfer': TRANSFER_STUB,
    },
], 'SU-Res 1 session')

add('list_sures_3_sessions_item_ie_ext', 'PDUSessionResourceSetupListSURes', [
    {
        'pDUSessionID': 1,
        'pDUSessionResourceSetupResponseTransfer': TRANSFER_STUB,
    },
    {
        'pDUSessionID': 2,
        'pDUSessionResourceSetupResponseTransfer': TRANSFER_STUB,
    },
    {
        'pDUSessionID': 3,
        'pDUSessionResourceSetupResponseTransfer': TRANSFER_STUB,
        'iE-Extensions': {'dummy': 0},
    },
], 'SU-Res 3 sessions, last with iE-Ext')


# Write to file
output = []
for f in fixtures:
    output.append({
        'name': f['name'],
        'pdu_type': f['pdu_type'],
        'hex': f['hex'],
        'bytes': f['bytes'],
        'notes': f['notes'],
    })

with open('/tmp/ngap-asn1/fixtures.json', 'w') as f:
    json.dump(output, f, indent=2)

for f in fixtures:
    print(f"{f['name']:38s} {f['bytes']:3d}B  {f['hex']}")
