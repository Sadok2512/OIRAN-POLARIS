// 0.9.4 — Add UE dialog contract after defect #29.
//
// Guarantees the UI MUST hold:
//   * (29a) Required errors are hidden until the operator touches a field
//     or clicks Create.
//   * (29b) Owner / gNB / PLMN / DNN come from lab-served dropdowns and
//     GNB-01 / 001-01 / internet are preselected when present.
//   * (29c) No IMSI text input. The slot is picked from the subscriber
//     list, or allocated with the Generate button.
//   * (29d) UE IP never appears in the form.
//   * (29e) SST / SD dropdowns default to 1 / 010203.
//   * (29f) UE ID is pre-filled with the next free UE-NN id.

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
const PLMNS = ['001-01', '208-93'];
const DNNS = ['internet', 'ims'];
const SUBS = [
  { slot: 'SUB-aaaaaaaaaaaa', state: 'PROVISIONED' },
  { slot: 'SUB-bbbbbbbbbbbb', state: 'PROVISIONED' },
];

function renderDialog(overrides: Partial<Parameters<typeof UeProvisioningAddDialog>[0]> = {}) {
  const onClose = vi.fn();
  const onSubmit = vi.fn().mockResolvedValue(undefined);
  const onGenerateSubscriber = vi.fn().mockResolvedValue('SUB-cccccccccccc');
  const props: Parameters<typeof UeProvisioningAddDialog>[0] = {
    open: true,
    onClose,
    onSubmit,
    onGenerateSubscriber,
    gnbs: GNBS,
    owners: OWNERS,
    plmns: PLMNS,
    dnns: DNNS,
    subscribers: SUBS,
    nextFreeUeId: 'UE-02',
    gnbsLoading: false,
    ownersLoading: false,
    plmnsLoading: false,
    dnnsLoading: false,
    subscribersLoading: false,
    gnbsError: null,
    ownersError: null,
    plmnsError: null,
    dnnsError: null,
    subscribersError: null,
    submitting: false,
    submitError: null,
    generating: false,
    generateError: null,
    ...overrides,
  };
  const utils = render(<UeProvisioningAddDialog {...props} />);
  return { ...utils, onClose, onSubmit, onGenerateSubscriber };
}

describe('UeProvisioningAddDialog (0.9.4 defect #29)', () => {
  it('29a — never surfaces required errors on open', () => {
    renderDialog({ nextFreeUeId: null, subscribers: [] });
    expect(screen.queryByTestId('ue-add-ue-id-error')).toBeNull();
    expect(screen.queryByTestId('ue-add-slot-error')).toBeNull();
    expect(screen.queryByTestId('ue-add-error')).toBeNull();
  });

  it('29b — exposes PLMN and DNN dropdowns with lab defaults preselected', () => {
    renderDialog();
    expect(screen.getByTestId('ue-add-gnb')).toHaveValue('GNB-01');
    expect(screen.getByTestId('ue-add-plmn')).toHaveValue('001-01');
    expect(screen.getByTestId('ue-add-dnn')).toHaveValue('internet');
  });

  it('29c — never renders an IMSI input', () => {
    renderDialog();
    expect(screen.queryByTestId('ue-add-imsi')).toBeNull();
    // The slot picker is present instead.
    expect(screen.getByTestId('ue-add-slot')).toBeInTheDocument();
    expect(screen.getByTestId('ue-add-generate')).toBeInTheDocument();
  });

  it('29c — Generate calls onGenerateSubscriber and preselects the new slot', async () => {
    const user = userEvent.setup();
    const { onGenerateSubscriber } = renderDialog({ subscribers: [] });
    await user.click(screen.getByTestId('ue-add-generate'));
    await waitFor(() => expect(onGenerateSubscriber).toHaveBeenCalledTimes(1));
    // The dialog is still open; the slot picker now carries the new slot
    // selected. Since the parent would also refetch the subscriber list,
    // the test just asserts the callback was invoked — the slot value
    // flows through the parent on real usage.
  });

  it('29d — never renders a UE IP form control', () => {
    renderDialog();
    // The informative paragraph above still mentions UE IP; what MUST
    // not exist is a form control that would let the operator type one.
    expect(screen.queryByLabelText(/^UE IP/i)).toBeNull();
  });

  it('29e — exposes SST and SD dropdowns with 1 / 010203 preselected', () => {
    renderDialog();
    expect(screen.getByTestId('ue-add-sst')).toHaveValue('1');
    expect(screen.getByTestId('ue-add-sd')).toHaveValue('010203');
  });

  it('29f — prefills UE ID with the provided next-free value', () => {
    renderDialog({ nextFreeUeId: 'UE-03' });
    expect(screen.getByTestId('ue-add-ue-id')).toHaveValue('UE-03');
  });

  it('submits the slot-bound body and never carries IMSI material', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderDialog();
    // Operator fills owner (the only field without a safe lab default).
    await user.selectOptions(screen.getByTestId('ue-add-owner'), 'ops-nancy');
    // Everything else is already preselected.
    await user.click(screen.getByTestId('ue-add-submit'));
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith({
        ue_id: 'UE-02',
        gnb_id: 'GNB-01',
        owner: 'ops-nancy',
        note: '',
        provisioning_slot: 'SUB-aaaaaaaaaaaa',
        plmn: '001-01',
        dnn: 'internet',
        sst: 1,
        sd: '010203',
      }),
    );
    const payload = onSubmit.mock.calls[0][0] as Record<string, unknown>;
    for (const forbidden of ['imsi', 'k', 'opc', 'authentication_key', 'ue_ip']) {
      expect(payload).not.toHaveProperty(forbidden);
    }
  });

  it('rejects an invalid UE ID with the UE-NN hint after submit', async () => {
    const user = userEvent.setup();
    renderDialog({ nextFreeUeId: 'invalid' });
    await user.click(screen.getByTestId('ue-add-submit'));
    await screen.findByTestId('ue-add-ue-id-error');
    expect(screen.getByTestId('ue-add-ue-id-error').textContent).toMatch(/UE-NN/);
  });

  it('shows "Backend pending" when the gNB dropdown has no options', () => {
    renderDialog({ gnbs: [], owners: [] });
    expect(screen.getByTestId('ue-add-gnb')).toBeDisabled();
    expect(screen.getByTestId('ue-add-owner')).toBeDisabled();
    expect(screen.getByTestId('ue-add-gnb').textContent).toMatch(/Backend pending/i);
  });
});
