// 0.9.4 — Add UE dialog aligned on defect #29.
//
// Flow:
//   * UE ID is pre-filled with the next free `UE-NN` id (29f), editable.
//   * Owner, Serving gNB, PLMN and DNN come from the lab inventories
//     (/owners, /gnbs, /plmns, /dnns). When the lab defaults are present
//     the dialog preselects GNB-01, PLMN 001/01 and DNN internet (29b).
//   * S-NSSAI is picked from fixed SST / SD dropdowns, defaults 1 /
//     010203 (29e).
//   * No IMSI text input (29c). The operator either picks an already
//     provisioned subscriber slot (SUB-… — identity PROTECTED) or clicks
//     Generate to allocate a fresh subscriber server-side (POST
//     /subscribers/generate). The IMSI never crosses the browser.
//   * UE IP stays out of the form (29d) — the backend fills it after the
//     attach completes.
//   * Required-field errors stay hidden until the operator either
//     touches a field or clicks Create (29a).

import { useEffect, useState } from 'react';
import { AlertTriangle, Sparkles, X } from 'lucide-react';
import type { WireGnb } from '@/data/profileApi';
import type { Owner } from '@/data/provisioningApi';
import { isUeIdValid, UE_ID_HINT } from '@/data/identityFormats';
import {
  LAB_DEFAULT_DNNS,
  LAB_DEFAULT_SD,
  LAB_DEFAULT_SST,
  LAB_SD_OPTIONS,
  LAB_SST_OPTIONS,
  sanitizeSd,
} from '@/subscribers/subscriberOptions';

/** The lab defaults #29b targets explicitly. Kept here so the test and
 * the dialog share one source of truth. */
export const LAB_DEFAULT_GNB_ID = 'GNB-01';
export const LAB_DEFAULT_PLMN_ID = '001-01';
export const LAB_DEFAULT_DNN = LAB_DEFAULT_DNNS[0] ?? 'internet';

/** Subscriber slot entry surfaced by the slot picker. Identity is always
 * PROTECTED — we only ever reference the opaque slot id. */
export interface SubscriberSlot {
  slot: string;
  state: string;
}

/** Request body sent to POST /ue-profiles.
 *
 * 0.9.4 — The IMSI text input is gone (#29c); the operator binds to a
 * provisioning slot instead. The server resolves the identity for the
 * SUB-… reference and never surfaces it to the UI. */
export interface UeProvisioningAddValues {
  ue_id: string;
  gnb_id: string;
  owner: string;
  note: string;
  provisioning_slot: string;
  plmn: string;
  dnn: string;
  sst: number;
  sd: string | null;
}

interface State {
  ue_id: string;
  gnb_id: string;
  owner: string;
  note: string;
  slot: string;
  plmn: string;
  dnn: string;
  sst: number;
  sd: string;
  touched: boolean;
}

function initialState(
  nextFreeUeId: string | null,
  gnbs: WireGnb[],
  plmns: string[],
  dnns: string[],
  subscribers: SubscriberSlot[],
): State {
  // Preselect GNB-01 / PLMN 001-01 / DNN internet when present (29b).
  const defaultGnb =
    gnbs.find((item) => item.gnb_id === LAB_DEFAULT_GNB_ID)?.gnb_id ?? gnbs[0]?.gnb_id ?? '';
  const defaultPlmn =
    plmns.find((value) => value === LAB_DEFAULT_PLMN_ID) ?? plmns[0] ?? LAB_DEFAULT_PLMN_ID;
  const defaultDnn =
    dnns.find((value) => value === LAB_DEFAULT_DNN) ?? dnns[0] ?? LAB_DEFAULT_DNN;
  const defaultSlot = subscribers[0]?.slot ?? '';
  return {
    ue_id: nextFreeUeId ?? '',
    gnb_id: defaultGnb,
    owner: '',
    note: '',
    slot: defaultSlot,
    plmn: defaultPlmn,
    dnn: defaultDnn,
    sst: LAB_DEFAULT_SST,
    sd: LAB_DEFAULT_SD ?? '',
    touched: false,
  };
}

export function UeProvisioningAddDialog({
  open,
  onClose,
  onSubmit,
  onGenerateSubscriber,
  gnbs,
  owners,
  plmns,
  dnns,
  subscribers,
  nextFreeUeId,
  gnbsLoading,
  ownersLoading,
  plmnsLoading,
  dnnsLoading,
  subscribersLoading,
  gnbsError,
  ownersError,
  plmnsError,
  dnnsError,
  subscribersError,
  submitting,
  submitError,
  generating,
  generateError,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (values: UeProvisioningAddValues) => Promise<void>;
  /** Operator-triggered allocation. Must return the slot id to preselect. */
  onGenerateSubscriber: () => Promise<string | null>;
  gnbs: WireGnb[];
  owners: Owner[];
  plmns: string[];
  dnns: string[];
  subscribers: SubscriberSlot[];
  nextFreeUeId: string | null;
  gnbsLoading: boolean;
  ownersLoading: boolean;
  plmnsLoading: boolean;
  dnnsLoading: boolean;
  subscribersLoading: boolean;
  gnbsError: string | null;
  ownersError: string | null;
  plmnsError: string | null;
  dnnsError: string | null;
  subscribersError: string | null;
  submitting: boolean;
  submitError: string | null;
  generating: boolean;
  generateError: string | null;
}) {
  const [state, setState] = useState<State>(() =>
    initialState(nextFreeUeId, gnbs, plmns, dnns, subscribers),
  );

  // Rebuild defaults every time the dialog opens so a fresh invocation
  // reflects any new inventory loaded in the background.
  useEffect(() => {
    if (!open) return;
    setState(initialState(nextFreeUeId, gnbs, plmns, dnns, subscribers));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  if (!open) return null;

  const ueIdInvalid = state.touched && !isUeIdValid(state.ue_id);
  const slotInvalid = state.touched && !state.slot;
  const canSubmit =
    !submitting &&
    isUeIdValid(state.ue_id) &&
    !!state.gnb_id &&
    !!state.owner &&
    !!state.slot &&
    !!state.plmn &&
    !!state.dnn;

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setState((prev) => ({ ...prev, touched: true }));
    if (!canSubmit) return;
    const values: UeProvisioningAddValues = {
      ue_id: state.ue_id.trim(),
      gnb_id: state.gnb_id,
      owner: state.owner,
      note: state.note.trim(),
      provisioning_slot: state.slot,
      plmn: state.plmn,
      dnn: state.dnn,
      sst: state.sst,
      sd: sanitizeSd(state.sd),
    };
    await onSubmit(values);
  }

  async function handleGenerate() {
    const nextSlot = await onGenerateSubscriber();
    if (nextSlot) {
      setState((prev) => ({ ...prev, slot: nextSlot }));
    }
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
          Identity material stays <strong>PROTECTED</strong>: the dialog never carries
          IMSI / K / OPc. The UE IP is assigned by the backend after attach.
        </p>

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">UE ID</span>
          <input
            className="ep-input mono"
            value={state.ue_id}
            onChange={(event) => setState((prev) => ({ ...prev, ue_id: event.target.value }))}
            onBlur={() => setState((prev) => ({ ...prev, touched: true }))}
            maxLength={16}
            placeholder={nextFreeUeId ?? 'UE-01'}
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
            <span className="text-ep-xs text-text-secondary">
              {UE_ID_HINT} · pre-filled with the next free id when available.
            </span>
          )}
        </label>

        <DropdownField
          label="Serving gNB"
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

        <DropdownField
          label="PLMN"
          value={state.plmn}
          onChange={(value) => setState((prev) => ({ ...prev, plmn: value }))}
          options={plmns.map((value) => ({ value, label: value }))}
          loading={plmnsLoading}
          error={plmnsError}
          testid="ue-add-plmn"
          nullableChoose={false}
        />

        <DropdownField
          label="DNN / APN"
          value={state.dnn}
          onChange={(value) => setState((prev) => ({ ...prev, dnn: value }))}
          options={dnns.map((value) => ({ value, label: value }))}
          loading={dnnsLoading}
          error={dnnsError}
          testid="ue-add-dnn"
          nullableChoose={false}
        />

        <div className="grid grid-cols-2 gap-3">
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-ep-xs uppercase tracking-wider text-text-secondary">SST</span>
            <select
              className="ep-input"
              value={state.sst}
              onChange={(event) =>
                setState((prev) => ({ ...prev, sst: Number(event.target.value) }))
              }
              data-testid="ue-add-sst"
            >
              {LAB_SST_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-ep-xs uppercase tracking-wider text-text-secondary">SD</span>
            <select
              className="ep-input"
              value={state.sd || 'absent'}
              onChange={(event) =>
                setState((prev) => ({
                  ...prev,
                  sd: event.target.value === 'absent' ? '' : event.target.value,
                }))
              }
              data-testid="ue-add-sd"
            >
              {LAB_SD_OPTIONS.map((option) => (
                <option key={option.label} value={option.value ?? 'absent'}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <fieldset className="flex flex-col gap-1 text-ep-sm">
          <legend className="text-ep-xs uppercase tracking-wider text-text-secondary">
            Subscriber slot
          </legend>
          <div className="flex items-start gap-2">
            <select
              className="ep-input mono flex-1"
              value={state.slot}
              onChange={(event) => setState((prev) => ({ ...prev, slot: event.target.value }))}
              disabled={subscribersLoading || subscribers.length === 0}
              aria-invalid={slotInvalid ? 'true' : 'false'}
              data-testid="ue-add-slot"
            >
              <option value="">
                {subscribersLoading
                  ? 'Loading…'
                  : subscribers.length === 0
                    ? 'No provisioned subscriber yet — click Generate'
                    : 'Choose a provisioned slot (PROTECTED)'}
              </option>
              {subscribers.map((item) => (
                <option key={item.slot} value={item.slot}>
                  {item.slot} · {item.state}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="ep-button ep-button-sm"
              onClick={handleGenerate}
              disabled={generating}
              data-testid="ue-add-generate"
            >
              <Sparkles width={11} height={11} />
              {generating ? 'Generating…' : 'Generate'}
            </button>
          </div>
          {subscribersError && (
            <span className="text-ep-xs text-warning flex items-start gap-1">
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              {subscribersError}
            </span>
          )}
          {generateError && (
            <span
              className="text-ep-xs text-error flex items-start gap-1"
              data-testid="ue-add-generate-error"
            >
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              {generateError}
            </span>
          )}
          {slotInvalid && (
            <span
              className="text-ep-xs text-error flex items-start gap-1"
              data-testid="ue-add-slot-error"
            >
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              A provisioned slot is required. Pick one from the list or click Generate.
            </span>
          )}
          <span className="text-ep-xs text-text-secondary">
            Identity (SUPI / K / OPc) stays <code className="mono">PROTECTED</code>; the UI only
            ever references the opaque slot id.
          </span>
        </fieldset>

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
            disabled={submitting}
            data-testid="ue-add-submit"
          >
            {submitting ? 'Saving…' : 'Create'}
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
  nullableChoose = true,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  loading: boolean;
  error: string | null;
  testid: string;
  nullableChoose?: boolean;
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
        {(nullableChoose || loading || empty || value === '') && (
          <option value="">
            {loading
              ? 'Loading…'
              : empty
                ? 'Backend pending — no options returned'
                : `Choose ${label.toLowerCase()}`}
          </option>
        )}
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
