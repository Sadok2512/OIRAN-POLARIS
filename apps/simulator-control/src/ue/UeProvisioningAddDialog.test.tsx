// 0.6.0 — Add UE dialog contract. The LOT reduces create to four fields:
// Name + gNB + Note + masked IMSI. Everything else comes back from the
// backend after save (PROTECTED).

import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { provisionedMutationFromValues, UeProvisioningAddDialog } from './UeProvisioningAddDialog';
import type { WireGnb } from '@/data/profileApi';
import type { Owner } from '@/data/provisioningApi';

const GNBS: WireGnb[] = [
  { gnb_id: 'GNB-01', link_ip: '10.77.0.20' },
  { gnb_id: 'GNB-02', link_ip: '10.77.0.21' },
];
const OWNERS: Owner[] = [
  { id: 'ops-nancy', name: 'Nancy Operator', role: 'Operator', email: null },
  { id: 'eng-remy', name: 'Rémy Engineer', role: 'Engineer', email: null },
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

describe('UeProvisioningAddDialog', () => {
  it('maps Add UE to the minimal API 0.15.2 subscriber contract without K or OPc', () => {
    expect(
      provisionedMutationFromValues({
        name: 'UE-201',
        serving_gnb: 'GNB-01',
        owner: 'ops-nancy',
        note: 'production check',
        imsi: '001010000000201',
      }),
    ).toEqual({
      ue_id: 'UE-201',
      name: 'UE-201',
      gnb_id: 'GNB-01',
      owner: 'ops-nancy',
      note: 'production check',
      imsi: '001010000000201',
    });
  });

  it('exposes only the four create-time fields (Name, gNB, Owner, Note, IMSI)', () => {
    renderDialog();
    expect(screen.getByTestId('ue-add-name')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-gnb')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-owner')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-note')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-imsi')).toBeInTheDocument();
    // IMSI stays masked (password input type) — the operator never sees it echoed.
    expect(screen.getByTestId('ue-add-imsi')).toHaveAttribute('type', 'password');
  });

  it('refuses to submit without a valid imsi-<digits> and surfaces the hint', async () => {
    const user = userEvent.setup();
    renderDialog();
    await user.type(screen.getByTestId('ue-add-name'), 'UE under test');
    await user.selectOptions(screen.getByTestId('ue-add-gnb'), 'GNB-01');
    await user.selectOptions(screen.getByTestId('ue-add-owner'), 'ops-nancy');
    const imsi = screen.getByTestId('ue-add-imsi');
    await user.type(imsi, 'not-an-imsi');
    imsi.blur();
    await screen.findByTestId('ue-add-imsi-error');
    expect(screen.getByTestId('ue-add-submit')).toBeDisabled();
  });

  it('forwards values to onSubmit and clears IMSI from the input after submit', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderDialog();
    await user.type(screen.getByTestId('ue-add-name'), 'UE under test');
    await user.selectOptions(screen.getByTestId('ue-add-gnb'), 'GNB-01');
    await user.selectOptions(screen.getByTestId('ue-add-owner'), 'ops-nancy');
    await user.type(screen.getByTestId('ue-add-note'), 'provisioning hand-off');
    await user.type(screen.getByTestId('ue-add-imsi'), 'imsi-208930000000001');
    await user.click(screen.getByTestId('ue-add-submit'));
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith({
        name: 'UE under test',
        serving_gnb: 'GNB-01',
        owner: 'ops-nancy',
        note: 'provisioning hand-off',
        imsi: 'imsi-208930000000001',
      }),
    );
    expect(screen.getByTestId('ue-add-imsi')).toHaveValue('');
  });

  it('accepts the canonical 15-digit IMSI form without a prefix', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderDialog();
    await user.type(screen.getByTestId('ue-add-name'), 'UE-201');
    await user.selectOptions(screen.getByTestId('ue-add-gnb'), 'GNB-01');
    await user.selectOptions(screen.getByTestId('ue-add-owner'), 'ops-nancy');
    await user.type(screen.getByTestId('ue-add-imsi'), '001010000000201');
    await user.click(screen.getByTestId('ue-add-submit'));
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ imsi: '001010000000201' })),
    );
  });

  it('shows "Backend pending" when a dropdown has no options', () => {
    renderDialog({ gnbs: [], owners: [] });
    const gnbSelect = screen.getByTestId('ue-add-gnb');
    const ownerSelect = screen.getByTestId('ue-add-owner');
    expect(gnbSelect).toBeDisabled();
    expect(ownerSelect).toBeDisabled();
    expect(gnbSelect).toHaveTextContent(/Backend pending/i);
    expect(ownerSelect).toHaveTextContent(/Backend pending/i);
  });
});
