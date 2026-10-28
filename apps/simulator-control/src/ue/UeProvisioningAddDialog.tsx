// 0.6.0 — Minimal "Add UE" dialog used when the `polarisProvisioning`
// flag is ON. The LOT reduces the create flow to Name + gNB + Note +
// masked IMSI; every other field (PLMN, DNN, S-NSSAI, provisioning
// status, revision, …) comes back FROM the backend after the POST and
// shows up in the UE detail card.
//
// Design notes:
//   * IMSI is typed into a password input ("masked") and never kept in
//     state after submit. The read of the created profile returns the
//     literal "PROTECTED" instead of the digits.
//   * gNB list comes from `GET /gnbs`; when the backend returns 404 or
//     the hook has no data yet, we fall back to a disabled select with
//     the honest "Backend pending" label — operator cannot submit until
//     a real gNB id is available.
//   * Owner comes from `GET /owners` under the same contract.

import { useEffect, useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import type { WireGnb, WireProvisionedUeProfileMutation } from '@/data/profileApi';
import type { Owner } from '@/data/provisioningApi';

const IMSI_RE = /^(?:imsi-)?\d{15}$/;

export interface UeProvisioningAddValues {
  name: string;
  serving_gnb: string;
  owner: string;
  note: string;
  /** Written once; cleared from state immediately after submit. */
  imsi: string;
}

export function provisionedMutationFromValues(
  values: UeProvisioningAddValues,
): WireProvisionedUeProfileMutation {
  return {
    ue_id: values.name,
    name: values.name,
    gnb_id: values.serving_gnb,
    owner: values.owner,
    note: values.note,
    imsi: values.imsi,
  };
}

interface State {
  name: string;
  serving_gnb: string;
  owner: string;
  note: string;
  imsi: string;
  imsiTouched: boolean;
}

const EMPTY: State = {
  name: '',
  serving_gnb: '',
  owner: '',
  note: '',
  imsi: '',
  imsiTouched: false,
};

export function UeProvisioningAddDialog({
  open,
  onClose,
  onSubmit,
  gnbs,
  owners,
  gnbsLoading,
  ownersLoading,
  gnbsError,
  ownersError,
  submitting,
  submitError,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (values: UeProvisioningAddValues) => Promise<void>;
  gnbs: WireGnb[];
  owners: Owner[];
  gnbsLoading: boolean;
  ownersLoading: boolean;
  gnbsError: string | null;
  ownersError: string | null;
  submitting: boolean;
  submitError: string | null;
}) {
  const [state, setState] = useState<State>(EMPTY);
  useEffect(() => {
    if (!open) setState(EMPTY);
  }, [open]);

  if (!open) return null;

  const imsiInvalid = state.imsiTouched && !IMSI_RE.test(state.imsi);
  const canSubmit =
    !submitting &&
    !!state.name.trim() &&
    !!state.serving_gnb &&
    !!state.owner &&
    IMSI_RE.test(state.imsi);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    const values: UeProvisioningAddValues = {
      name: state.name.trim(),
      serving_gnb: state.serving_gnb,
      owner: state.owner,
      note: state.note.trim(),
      imsi: state.imsi.trim(),
    };
    // Scrub the secret from component state immediately. The parent
    // forwards `values` to the backend without keeping its own copy.
    setState((prev) => ({ ...prev, imsi: '', imsiTouched: false }));
    await onSubmit(values);
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ue-provisioning-add-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4"
      data-testid="ue-provisioning-add-dialog"
    >
      <form
        className="ep-card w-full max-w-xl p-5 flex flex-col gap-3 my-4"
        onSubmit={handleSubmit}
      >
        <header className="flex items-center justify-between">
          <h2 id="ue-provisioning-add-title" className="text-ep-lg font-semibold">
            Add UE
          </h2>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onClose}
            aria-label="Close"
          >
            <X width={13} height={13} />
          </button>
        </header>

        <p className="text-ep-xs text-text-secondary">
          Only four fields at create-time. The PLMN, DNN, S-NSSAI and provisioning status come back
          from the backend and show up in the UE detail card.
        </p>

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">Name</span>
          <input
            className="ep-input"
            value={state.name}
            onChange={(event) => setState((prev) => ({ ...prev, name: event.target.value }))}
            maxLength={128}
            data-testid="ue-add-name"
            required
          />
        </label>

        <DropdownField
          label="gNB"
          value={state.serving_gnb}
          onChange={(value) => setState((prev) => ({ ...prev, serving_gnb: value }))}
          options={gnbs.map((item) => ({ value: item.gnb_id, label: `${item.gnb_id}` }))}
          loading={gnbsLoading}
          error={gnbsError}
          testid="ue-add-gnb"
        />

        <DropdownField
          label="Owner"
          value={state.owner}
          onChange={(value) => setState((prev) => ({ ...prev, owner: value }))}
          options={owners.map((item) => ({ value: item.id, label: `${item.name} (${item.role})` }))}
          loading={ownersLoading}
          error={ownersError}
          testid="ue-add-owner"
        />

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">Note</span>
          <input
            className="ep-input"
            value={state.note}
            onChange={(event) => setState((prev) => ({ ...prev, note: event.target.value }))}
            maxLength={255}
            data-testid="ue-add-note"
            placeholder="Optional"
          />
        </label>

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
            IMSI (masked)
          </span>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            className="ep-input mono"
            value={state.imsi}
            onChange={(event) => setState((prev) => ({ ...prev, imsi: event.target.value }))}
            onBlur={() => setState((prev) => ({ ...prev, imsiTouched: true }))}
            placeholder="001010000000201 or imsi-001010000000201"
            aria-invalid={imsiInvalid ? 'true' : 'false'}
            data-testid="ue-add-imsi"
          />
          <span className="text-ep-xs text-text-secondary">
            Stored once in the request body, never kept in browser state. The backend reads it back
            as <code className="mono">PROTECTED</code>.
          </span>
          {imsiInvalid && (
            <span className="text-ep-xs text-error flex items-start gap-1" data-testid="ue-add-imsi-error">
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              IMSI must contain exactly 15 digits, with an optional <code className="mono">imsi-</code> prefix.
            </span>
          )}
        </label>

        {submitError && (
          <p role="alert" className="text-ep-sm text-error flex items-start gap-1" data-testid="ue-add-error">
            <AlertTriangle width={13} height={13} className="mt-0.5 shrink-0" />
            {submitError}
          </p>
        )}

        <footer className="flex items-center justify-end gap-2 pt-2 border-t border-border">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onClose}
            disabled={submitting}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="ep-button ep-button-sm ep-button-primary"
            disabled={!canSubmit}
            data-testid="ue-add-submit"
          >
            {submitting ? 'Saving…' : 'Save UE'}
          </button>
        </footer>
      </form>
    </div>
  );
}

function DropdownField({
  label,
  value,
  onChange,
  options,
  loading,
  error,
  testid,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  loading: boolean;
  error: string | null;
  testid: string;
}) {
  const empty = !loading && options.length === 0;
  return (
    <label className="flex flex-col gap-1 text-ep-sm">
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary">{label}</span>
      <select
        className="ep-input"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={loading || empty}
        data-testid={testid}
      >
        <option value="">
          {loading ? 'Loading…' : empty ? 'Backend pending — no options returned' : `Choose ${label.toLowerCase()}`}
        </option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {error && (
        <span className="text-ep-xs text-warning flex items-start gap-1">
          <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
          {error}
        </span>
      )}
    </label>
  );
}
