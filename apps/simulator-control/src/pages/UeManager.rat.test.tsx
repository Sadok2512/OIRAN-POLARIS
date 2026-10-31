import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  renderPduCell,
  renderRegistrationCell,
  isCanonicalLteProfile,
  recordFromLteProfile,
  resolveUeRatAssociation,
} from './UeManager';
import type { LteProfile, NodeItem, UeProfile, UeState } from '@/data/polarisTypes';
import type { UeProfileRecord } from '@/ue/profileModel';

const profile = (id: string, servingGnb: string): UeProfileRecord => ({
  id, owner: `DEMO ${id}`, servingGnb, createdAt: 1, updatedAt: 1,
});

const node = (id: string, technology: string, simulator: string, coreLinked = false): NodeItem => ({
  id, name: id, technology, simulator, plmn: '001/01', cell_id: 'demo',
  link_ip: '10.77.0.1', n2_endpoint: coreLinked ? '10.77.1.1' : null,
  n3_endpoint: coreLinked ? '10.77.2.1' : null,
  n2_state: coreLinked && !/LTE/i.test(technology) ? 'CONNECTED' : 'NOT_OBSERVED',
  n3_state: coreLinked && !/LTE/i.test(technology) ? 'CONNECTED' : 'NOT_OBSERVED',
  s1_state: coreLinked && /LTE/i.test(technology) ? 'CONNECTED' : 'NOT_OBSERVED',
  epc_state: coreLinked && /LTE/i.test(technology) ? 'running' : 'NOT_OBSERVED',
  process_state: coreLinked ? 'running' : 'unknown', health: 'unknown', configured: true,
  controller_owned: false, uptime_seconds: null,
  actions: { start: false, stop: false, reason: 'READ_ONLY' },
});

const configured = (id: string, servingGnb: string, simulator: string): UeProfile => ({
  id, profile: `${id}.yaml`, serving_gnb: servingGnb, simulator, state: 'CONFIGURED',
  configured: true, controller_owned: false,
});

const lteProfile = (): LteProfile => ({
  schema_version: 'polaris.lte-profile.v1', profile_id: 'LTE-SRSUE-TEST-01',
  technology: 'LTE 4G', simulator: 'srsUE', serving_ran: 'ENB-01',
  serving_ran_type: 'srsENB', revision: 1, owner: 'POLARIS_CONTROLLER',
  enabled: false, runtime_state: 'UNKNOWN', apn: 'NOT_AVAILABLE', max_running_ues: 1,
  configuration_sha256: '0'.repeat(64), compose_model_sha256: null,
  scenario_id: 'lte-e2e-certification-v1', scenario_revision: 1,
  scenario_sha256: '1'.repeat(64), grant_required: true,
  evidence_schema: 'oiran-polaris.lte-e2e-evidence.v1', last_observed_at_epoch_s: null,
});

describe('UE Manager RAT/simulator evidence resolution', () => {
  it('accepts only the canonical LTE profile contract and never invents runtime state', () => {
    expect(isCanonicalLteProfile(lteProfile())).toBe(true);
    expect(isCanonicalLteProfile({ ...lteProfile(), serving_ran: undefined })).toBe(false);
    const record = recordFromLteProfile(lteProfile());
    expect(record.id).toBe('LTE-SRSUE-TEST-01');
    expect(record).not.toHaveProperty('registration_state');
    expect(record).not.toHaveProperty('ue_ip');
  });
  it('proves UE-01 as 5G SA / UERANSIM through configured profile + GNB-01', () => {
    expect(resolveUeRatAssociation(
      profile('UE-01', 'GNB-01'), undefined,
      configured('UE-01', 'GNB-01', 'UERANSIM'),
      [node('GNB-01', '5G SA', 'UERANSIM', true)],
      true,
    )).toEqual({
      technology: '5G SA', simulator: 'UERANSIM', servingRan: 'GNB-01',
      servingRanType: 'gNB', core: 'Open5GS 5GC',
    });
  });

  it('proves UE-201 from backend serving-node evidence even when runtime omits RAT fields', () => {
    const runtime = {
      id: 'UE-201', serving_node: 'GNB-01', registration_state: 'DEREGISTERED',
      pdu_session: 'INACTIVE', ue_ip: null, traffic_state: 'IDLE', last_event: null,
      controller_owned: true,
    } satisfies UeState;
    expect(resolveUeRatAssociation(
      profile('UE-201', 'GNB-01'), runtime,
      configured('UE-201', 'GNB-01', 'UERANSIM'),
      [node('GNB-01', '5G SA', 'UERANSIM', true)],
      true,
    ).simulator).toBe('UERANSIM');
  });

  it('maps the canonical LTE profile to LTE / srsUE / srsENB / EPC', () => {
    const runtime = {
      id: 'LTE-SRSUE-TEST-01', serving_node: 'ENB-01', technology: 'LTE 4G', simulator: 'srsRAN',
      registration_state: 'ATTACHED', attach_state: 'ATTACHED', pdu_session: 'ACTIVE',
      ue_ip: '10.45.0.10', traffic_state: 'IDLE', last_event: null, controller_owned: true,
    } satisfies UeState;
    expect(resolveUeRatAssociation(
      profile('LTE-SRSUE-TEST-01', 'ENB-01'), runtime, undefined,
      [node('ENB-01', 'LTE', 'srsRAN', true)],
      true,
    )).toEqual({
      technology: 'LTE 4G', simulator: 'srsUE', servingRan: 'ENB-01',
      servingRanType: 'srsENB', core: 'Open5GS EPC',
    });
  });

  it('returns UNKNOWN instead of inferring an unproved association', () => {
    expect(resolveUeRatAssociation(
      profile('UE-UNKNOWN', ''), undefined, undefined, [],
    )).toEqual({
      technology: 'UNKNOWN', simulator: 'UNKNOWN', servingRan: 'UNKNOWN',
      servingRanType: 'UNKNOWN', core: 'UNKNOWN',
    });
  });

  it('keeps the core UNKNOWN when the serving RAN has no observed core endpoint', () => {
    const association = resolveUeRatAssociation(
      profile('LTE-SRSUE-TEST-01', 'ENB-01'), undefined,
      configured('LTE-SRSUE-TEST-01', 'ENB-01', 'srsRAN'),
      [node('ENB-01', 'LTE', 'srsRAN')],
      true,
    );
    expect(association.technology).toBe('LTE 4G');
    expect(association.simulator).toBe('srsUE');
    expect(association.core).toBe('UNKNOWN');
  });

  it('renders runtime fields as UNKNOWN when no observation exists', () => {
    render(<>{renderRegistrationCell(undefined, true)}{renderPduCell(undefined, true)}</>);
    expect(screen.getAllByText('UNKNOWN')).toHaveLength(2);
  });
});
