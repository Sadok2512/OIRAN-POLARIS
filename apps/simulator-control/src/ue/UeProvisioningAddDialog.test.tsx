// 0.7.1 — Add UE dialog contract. The LOT reduces create to five fields:
// UE ID + gNB + Owner + Note + masked IMSI. The onSubmit payload must
// match the slim shape {ue_id, gnb_id, owner, note, imsi} exactly.

import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { UeProvisioningAddDialog } from './UeProvisioningAddDialog';
import type { WireGnb } from '@/data/profileApi';
import type { Owner } from '@/data/provisioningApi';

const GNBS: WireGnb[] = [
  { gnb_id: 'GNB-01', link_ip: '10.77.0.20' },
  { gnb_id: 'GNB-02', link_ip: '10.77.0.21' },
];
const OWNERS: Owner[] = [
  { id: 'ops-nancy', name: 'Nancy Operator', role: 'Operator', email: null },
];

function renderDialog(overrides: Partial<Parameters<typeof UeProvisioningAddDialog>[0]> = {}) {
  const onClose = vi.fn();
  const onSubmit = vi.fn().mockResolvedValue(undefined);
  const props: Parameters<typeof UeProvisioningAddDialog>[0] = {
    open: true,
    onClose,
    onSubmit,
    gnbs: GNBS,
    owners: OWNERS,
    gnbsLoading: false,
    ownersLoading: false,
    gnbsError: null,
    ownersError: null,
    submitting: false,
    submitError: null,
    ...overrides,
  };
  const utils = render(<UeProvisioningAddDialog {...props} />);
  return { ...utils, onClose, onSubmit };
}

describe('UeProvisioningAddDialog (0.7.1 slim contract)', () => {
  it('exposes exactly five fields (UE ID, gNB, Owner, Note, IMSI) — Name is gone', () => {
    renderDialog();
    expect(screen.getByTestId('ue-add-ue-id')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-gnb')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-owner')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-note')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-imsi')).toBeInTheDocument();
    expect(screen.queryByTestId('ue-add-name')).toBeNull();
    expect(screen.getByTestId('ue-add-imsi')).toHaveAttribute('type', 'password');
  });

  it('rejects a malformed UE ID and surfaces the UE-NN hint', async () => {
    const user = userEvent.setup();
    renderDialog();
    await user.type(screen.getByTestId('ue-add-ue-id'), 'not-a-ue-id');
    await user.selectOptions(screen.getByTestId('ue-add-gnb'), 'GNB-01');
    await user.selectOptions(screen.getByTestId('ue-add-owner'), 'ops-nancy');
    await user.type(screen.getByTestId('ue-add-imsi'), '001010000000201');
    await user.click(screen.getByTestId('ue-add-submit'));
    await screen.findByTestId('ue-add-ue-id-error');
    expect(screen.getByTestId('ue-add-ue-id-error').textContent).toMatch(/UE-NN/);
  });

  it('normalises IMSI (raw digits) and sends the slim body {ue_id, gnb_id, owner, note, imsi}', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderDialog();
    await user.type(screen.getByTestId('ue-add-ue-id'), 'UE-01');
    await user.selectOptions(screen.getByTestId('ue-add-gnb'), 'GNB-01');
    await user.selectOptions(screen.getByTestId('ue-add-owner'), 'ops-nancy');
    await user.type(screen.getByTestId('ue-add-note'), 'provisioning hand-off');
    // Raw digits (no imsi- prefix) must be normalised before submit.
    await user.type(screen.getByTestId('ue-add-imsi'), '001010000000201');
    await user.click(screen.getByTestId('ue-add-submit'));
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith({
        ue_id: 'UE-01',
        gnb_id: 'GNB-01',
        owner: 'ops-nancy',
        note: 'provisioning hand-off',
        imsi: 'imsi-001010000000201',
      }),
    );
    // No 0.11-era carriers leak into the payload.
    const payload = onSubmit.mock.calls[0][0] as Record<string, unknown>;
    for (const forbidden of [
      'provisioning_slot',
      'k',
      'opc',
      'keep_identity',
      'plmn_mcc',
      'plmn_mnc',
      'dnn',
      'sst',
      'sd',
      'scenario_id',
      'auto_run_scenario',
      'name',
    ]) {
      expect(payload).not.toHaveProperty(forbidden);
    }
    // IMSI input is scrubbed.
    expect(screen.getByTestId('ue-add-imsi')).toHaveValue('');
  });

  it('accepts the already-prefixed IMSI without re-prefixing', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderDialog();
    await user.type(screen.getByTestId('ue-add-ue-id'), 'UE-02');
    await user.selectOptions(screen.getByTestId('ue-add-gnb'), 'GNB-01');
    await user.selectOptions(screen.getByTestId('ue-add-owner'), 'ops-nancy');
    await user.type(screen.getByTestId('ue-add-imsi'), 'imsi-208930000000001');
    await user.click(screen.getByTestId('ue-add-submit'));
    await waitFor(() =>
      expect((onSubmit.mock.calls[0][0] as { imsi: string }).imsi).toBe('imsi-208930000000001'),
    );
  });

  it('shows "Backend pending" when a dropdown has no options', () => {
    renderDialog({ gnbs: [], owners: [] });
    expect(screen.getByTestId('ue-add-gnb')).toBeDisabled();
    expect(screen.getByTestId('ue-add-owner')).toBeDisabled();
    expect(screen.getByTestId('ue-add-gnb').textContent).toMatch(/Backend pending/i);
  });
});
