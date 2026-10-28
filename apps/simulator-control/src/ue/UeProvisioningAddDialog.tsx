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
import type { WireGnb } from '@/data/profileApi';
import type { Owner } from '@/data/provisioningApi';
import {
  isImsiValid,
  isUeIdValid,
  normalizeImsi,
  UE_ID_HINT,
} from '@/data/identityFormats';

/**
 * 0.7.1 — The create-time body `POST /ue-profiles` accepts exactly these
 * five fields. Any 0.11-era carrier (plmn_mcc / plmn_mnc / dnn / sst /
 * sd / provisioning_slot / k / opc / keep_identity / scenario_id /
 * auto_run_scenario) is rejected by the backend.
 */
export interface UeProvisioningAddValues {
  ue_id: string;
  gnb_id: string;
  owner: string;
  note: string;
  /** Normalised IMSI (`imsi-<5-15 digits>`). Cleared from state after submit. */
  imsi: string;
}

interface State {
  ue_id: string;
  gnb_id: string;
  owner: string;
  note: string;
  imsi: string;
  touched: boolean;
}

const EMPTY: State = {
  ue_id: '',
  gnb_id: '',
  owner: '',
  note: '',
  imsi: '',
  touched: false,
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

  const ueIdInvalid = state.touched && !isUeIdValid(state.ue_id);
  const imsiInvalid = state.touched && !isImsiValid(state.imsi);
  const canSubmit =
    !submitting &&
    isUeIdValid(state.ue_id) &&
    !!state.gnb_id &&
    !!state.owner &&
    isImsiValid(state.imsi);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setState((prev) => ({ ...prev, touched: true }));
    if (!canSubmit) return;
    const normalisedImsi = normalizeImsi(state.imsi);
    if (!normalisedImsi) return;
    const values: UeProvisioningAddValues = {
      ue_id: state.ue_id.trim(),
      gnb_id: state.gnb_id,
      owner: state.owner,
      note: state.note.trim(),
      imsi: normalisedImsi,
    };
    // Scrub the secret from component state immediately. The parent
    // forwards `values` to the backend without keeping its own copy.
    setState((prev) => ({ ...prev, imsi: '' }));
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
          Five fields. POST <code className="mono">/ue-profiles</code> sends only{' '}
          <code className="mono">{'{ue_id, gnb_id, owner, note, imsi}'}</code>; PLMN, DNN, S-NSSAI
          and provisioning status come back from the backend.
        </p>

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">UE ID</span>
          <input
            className="ep-input mono"
            value={state.ue_id}
            onChange={(event) => setState((prev) => ({ ...prev, ue_id: event.target.value }))}
            onBlur={() => setState((prev) => ({ ...prev, touched: true }))}
            maxLength={16}
            placeholder="UE-01"
            aria-invalid={ueIdInvalid ? 'true' : 'false'}
            data-testid="ue-add-ue-id"
            required
          />
          {ueIdInvalid ? (
            <span className="text-ep-xs text-error flex items-start gap-1" data-testid="ue-add-ue-id-error">
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              {UE_ID_HINT}
            </span>
          ) : (
            <span className="text-ep-xs text-text-secondary">{UE_ID_HINT}</span>
          )}
        </label>

        <DropdownField
          label="gNB"
          value={state.gnb_id}
          onChange={(value) => setState((prev) => ({ ...prev, gnb_id: value }))}
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
            onBlur={() => setState((prev) => ({ ...prev, touched: true }))}
            placeholder="001010000000201 or imsi-001010000000201"
            aria-invalid={imsiInvalid ? 'true' : 'false'}
            data-testid="ue-add-imsi"
          />
          <span className="text-ep-xs text-text-secondary">
            Accepts raw digits ("001010000000201") or prefixed ("imsi-001010000000201"); normalised
            before send. Stored once in the request body, never kept in browser state. The backend
            reads it back as <code className="mono">PROTECTED</code>.
          </span>
          {imsiInvalid && (
            <span className="text-ep-xs text-error flex items-start gap-1" data-testid="ue-add-imsi-error">
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              IMSI must be 5–15 digits, optionally prefixed with <code className="mono">imsi-</code>.
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
