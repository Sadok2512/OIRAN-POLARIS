// Backend-mode UE profile dialog (flag `profileBackend`). Same dialog layout and
// field styling as UeProfileForm; fields follow the POLARIS 0.11.0 contract.
//
// Subscriber identity is WRITE-ONLY: SUPI, K and OPc are typed into password
// inputs, sent once in the request body, and never kept in component state
// after submit, in browser storage, or echoed back by the API ("PROTECTED").
// The preferred path is a provisioning slot: the backend reads the identity of
// a subscriber already provisioned in Open5GS, so nobody types a secret.

import { useEffect, useMemo, useState } from 'react';
import { X } from 'lucide-react';
import {
  BACKEND_UE_ID_RE,
  type WireGnb,
  type WireProvisioningSlot,
  type WireUeProfile,
  type WireUeProfileMutation,
} from '@/data/profileApi';
import type { ProfileFormMode } from './UeProfileForm';

type IdentitySource = 'slot' | 'manual' | 'keep';

interface FormState {
  ueId: string;
  name: string;
  servingGnb: string;
  mcc: string;
  mnc: string;
  dnn: string;
  sst: string;
  sd: string;
  identity: IdentitySource;
  slot: string;
  supi: string;
  authenticationKey: string;
  opc: string;
}

const HEX32 = /^[0-9a-fA-F]{32}$/;
const SUPI_RE = /^imsi-\d{5,15}$/;

function initialState(
  mode: ProfileFormMode,
  initial: WireUeProfile | null,
  template: WireUeProfile | null,
  gnbs: WireGnb[],
  freeSlot: string,
): FormState {
  const source = initial ?? template;
  return {
    ueId: mode === 'edit' && initial ? initial.ue_id : '',
    name: initial ? (mode === 'clone' ? `${initial.name} copy` : initial.name) : '',
    servingGnb: source?.serving_gnb ?? gnbs[0]?.gnb_id ?? '',
    mcc: source?.plmn.mcc ?? '',
    mnc: source?.plmn.mnc ?? '',
    dnn: source?.dnn ?? '',
    sst: source ? String(source.snssai.sst) : '',
    sd: source?.snssai.sd ?? '',
    identity: mode === 'create' ? (freeSlot ? 'slot' : 'manual') : 'keep',
    slot: freeSlot,
    supi: '',
    authenticationKey: '',
    opc: '',
  };
}

export function validateBackendForm(mode: ProfileFormMode, state: FormState): Record<string, string> {
  const issues: Record<string, string> = {};
  if (mode !== 'edit' && !BACKEND_UE_ID_RE.test(state.ueId)) {
    issues.ueId = 'Format UE-NN (01–99) or UE-NNNNN (00100–10000)';
  }
  if (mode === 'clone') return issues;
  if (!state.name.trim() || state.name.length > 128) issues.name = 'Name is required (≤128 chars)';
  if (!state.servingGnb) issues.servingGnb = 'Choose a gNB from the registry';
  if (!/^\d{3}$/.test(state.mcc)) issues.mcc = 'MCC: 3 digits';
  if (!/^\d{2,3}$/.test(state.mnc)) issues.mnc = 'MNC: 2 or 3 digits';
  if (!state.dnn.trim()) issues.dnn = 'DNN is required';
  const sst = Number(state.sst);
  if (!Number.isInteger(sst) || sst < 1 || sst > 255) issues.sst = 'SST: integer 1–255';
  if (state.sd && !/^[0-9a-fA-F]{6}$/.test(state.sd)) issues.sd = 'SD: 6 hex digits or empty';
  if (state.identity === 'slot' && !state.slot) issues.slot = 'No free provisioned subscriber';
  if (state.identity === 'manual') {
    if (!SUPI_RE.test(state.supi)) issues.supi = 'SUPI: imsi- followed by digits';
    if (!HEX32.test(state.authenticationKey)) issues.authenticationKey = 'K: 32 hex characters';
    if (!HEX32.test(state.opc)) issues.opc = 'OPc: 32 hex characters';
  }
  return issues;
}

export function mutationFromForm(state: FormState, scenarioId: string | null, autoRun: boolean): WireUeProfileMutation {
  const manual = state.identity === 'manual';
  return {
    ue_id: state.ueId,
    name: state.name.trim(),
    supi: manual ? state.supi : null,
    authentication_key: manual ? state.authenticationKey : null,
    opc: manual ? state.opc : null,
    ...(state.identity === 'slot' ? { provisioning_slot: state.slot } : {}),
    plmn_mcc: state.mcc,
    plmn_mnc: state.mnc,
    dnn: state.dnn.trim(),
    sst: Number(state.sst),
    sd: state.sd ? state.sd : null,
    serving_gnb: state.servingGnb,
    scenario_id: scenarioId,
    auto_run_scenario: autoRun,
  };
}

export function UeProfileBackendFormDialog({
  mode,
  open,
  initial,
  template,
  gnbs,
  slots,
  slotsError,
  busy,
  onSubmit,
  onCancel,
}: {
  mode: ProfileFormMode;
  open: boolean;
  /** The record being edited or cloned. */
  initial: WireUeProfile | null;
  /** Any existing record, used only to prefill PLMN/DNN/S-NSSAI on create. */
  template: WireUeProfile | null;
  gnbs: WireGnb[];
  slots: WireProvisioningSlot[];
  slotsError: Error | null;
  busy?: boolean;
  onSubmit: (body: WireUeProfileMutation, mode: ProfileFormMode) => Promise<void>;
  onCancel: () => void;
}) {
  const freeSlots = useMemo(() => slots.filter((slot) => !slot.bound_ue_id), [slots]);
  const [state, setState] = useState<FormState>(() =>
    initialState(mode, initial, template, gnbs, freeSlots[0]?.slot_id ?? ''),
  );
  const [serverError, setServerError] = useState('');

  useEffect(() => {
    if (!open) return;
    setState(initialState(mode, initial, template, gnbs, freeSlots[0]?.slot_id ?? ''));
    setServerError('');
    // Re-seed only when the dialog opens or its target changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, mode, initial]);

  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCancel();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onCancel]);

  if (!open) return null;

  const issues = validateBackendForm(mode, state);
  const title = mode === 'create' ? 'Add UE profile' : mode === 'edit' ? 'Edit UE profile' : 'Clone UE profile';

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setState((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (Object.keys(issues).length > 0) return;
    try {
      setServerError('');
      const body = mutationFromForm(
        state,
        initial?.scenario_id ?? null,
        initial?.auto_run_scenario ?? false,
      );
      await onSubmit(body, mode);
      // Drop typed secrets as soon as they have been sent.
      setState((prev) => ({ ...prev, supi: '', authenticationKey: '', opc: '' }));
    } catch (error) {
      const code = (error as { code?: string }).code;
      setServerError(code ?? (error as Error).message);
    }
  }

  const identityEditable = mode !== 'clone';

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ue-profile-backend-form-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      data-testid="ue-profile-backend-form"
    >
      <form onSubmit={handleSubmit} className="ep-card w-full max-w-xl p-5 flex flex-col gap-3">
        <header className="flex items-center justify-between">
          <h2 id="ue-profile-backend-form-title" className="text-ep-lg font-semibold">
            {title}
          </h2>
          <button type="button" className="ep-button ep-button-sm" onClick={onCancel} aria-label="Close">
            <X width={13} height={13} />
          </button>
        </header>

        <div className="grid grid-cols-2 gap-3">
          <Field label={mode === 'clone' ? 'New UE ID' : 'UE ID'} error={issues.ueId} required hint="UE-NN or UE-NNNNN">
            <input
              className="ep-input mono"
              value={state.ueId}
              onChange={(event) => set('ueId', event.target.value.trim())}
              disabled={busy || mode === 'edit'}
              autoFocus={mode !== 'edit'}
              data-testid="backend-profile-ue-id"
            />
          </Field>
          {mode === 'clone' ? (
            <p className="text-ep-xs text-text-secondary self-end">
              The clone gets new backend-generated subscriber material and starts as not provisioned.
            </p>
          ) : (
            <>
              <Field label="Name" error={issues.name} required>
                <input
                  className="ep-input"
                  value={state.name}
                  onChange={(event) => set('name', event.target.value)}
                  disabled={busy}
                  data-testid="backend-profile-name"
                />
              </Field>
              <Field label="Serving gNB" error={issues.servingGnb} required hint="From GET /gnbs">
                <select
                  className="ep-input"
                  value={state.servingGnb}
                  onChange={(event) => set('servingGnb', event.target.value)}
                  disabled={busy}
                  data-testid="backend-profile-gnb"
                >
                  {gnbs.length === 0 && <option value="">No gNB registered</option>}
                  {gnbs.map((gnb) => (
                    <option key={gnb.gnb_id} value={gnb.gnb_id}>
                      {gnb.gnb_id} · {gnb.link_ip}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="DNN" error={issues.dnn} required>
                <input
                  className="ep-input"
                  value={state.dnn}
                  onChange={(event) => set('dnn', event.target.value)}
                  disabled={busy}
                  data-testid="backend-profile-dnn"
                />
              </Field>
              <Field label="MCC" error={issues.mcc} required>
                <input
                  className="ep-input mono"
                  inputMode="numeric"
                  value={state.mcc}
                  onChange={(event) => set('mcc', event.target.value.trim())}
                  disabled={busy}
                  data-testid="backend-profile-mcc"
                />
              </Field>
              <Field label="MNC" error={issues.mnc} required>
                <input
                  className="ep-input mono"
                  inputMode="numeric"
                  value={state.mnc}
                  onChange={(event) => set('mnc', event.target.value.trim())}
                  disabled={busy}
                  data-testid="backend-profile-mnc"
                />
              </Field>
              <Field label="SST" error={issues.sst} required>
                <input
                  className="ep-input mono"
                  inputMode="numeric"
                  value={state.sst}
                  onChange={(event) => set('sst', event.target.value.trim())}
                  disabled={busy}
                  data-testid="backend-profile-sst"
                />
              </Field>
              <Field label="SD" error={issues.sd} hint="6 hex digits, optional">
                <input
                  className="ep-input mono"
                  value={state.sd}
                  onChange={(event) => set('sd', event.target.value.trim())}
                  disabled={busy}
                  data-testid="backend-profile-sd"
                />
              </Field>
            </>
          )}
        </div>

        {identityEditable && (
          <fieldset className="border border-border rounded-md p-3 flex flex-col gap-2">
            <legend className="text-ep-xs uppercase tracking-wider text-text-secondary px-1">
              Subscriber identity — write-only
            </legend>
            <div className="flex flex-wrap gap-3 text-ep-sm" role="radiogroup" aria-label="Identity source">
              {mode === 'edit' && (
                <label className="flex items-center gap-1">
                  <input
                    type="radio"
                    name="identity"
                    checked={state.identity === 'keep'}
                    onChange={() => set('identity', 'keep')}
                    disabled={busy}
                  />
                  Keep current (PROTECTED)
                </label>
              )}
              {mode === 'create' && (
                <label className="flex items-center gap-1">
                  <input
                    type="radio"
                    name="identity"
                    checked={state.identity === 'slot'}
                    onChange={() => set('identity', 'slot')}
                    disabled={busy || freeSlots.length === 0}
                    data-testid="backend-profile-identity-slot"
                  />
                  Provisioned subscriber
                </label>
              )}
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  name="identity"
                  checked={state.identity === 'manual'}
                  onChange={() => set('identity', 'manual')}
                  disabled={busy}
                  data-testid="backend-profile-identity-manual"
                />
                {mode === 'edit' ? 'Replace' : 'Enter manually'}
              </label>
            </div>

            {state.identity === 'slot' && (
              <Field
                label="Provisioned subscriber"
                error={issues.slot}
                hint="Already in Open5GS — the backend reads its identity, nothing is typed here."
              >
                <select
                  className="ep-input mono"
                  value={state.slot}
                  onChange={(event) => set('slot', event.target.value)}
                  disabled={busy}
                  data-testid="backend-profile-slot"
                >
                  {freeSlots.map((slot) => (
                    <option key={slot.slot_id} value={slot.slot_id}>
                      {slot.slot_id}
                    </option>
                  ))}
                </select>
              </Field>
            )}
            {mode === 'create' && slotsError && (
              <p className="text-ep-xs text-text-secondary" data-testid="backend-profile-slots-unavailable">
                Provisioned subscribers unavailable ({(slotsError as { code?: string }).code ?? slotsError.message}).
              </p>
            )}

            {state.identity === 'manual' && (
              <div className="grid grid-cols-3 gap-2">
                <Field label="SUPI" error={issues.supi}>
                  <input
                    type="password"
                    autoComplete="off"
                    className="ep-input mono"
                    placeholder="imsi-…"
                    value={state.supi}
                    onChange={(event) => set('supi', event.target.value.trim())}
                    disabled={busy}
                    data-testid="backend-profile-supi"
                  />
                </Field>
                <Field label="K" error={issues.authenticationKey}>
                  <input
                    type="password"
                    autoComplete="off"
                    className="ep-input mono"
                    value={state.authenticationKey}
                    onChange={(event) => set('authenticationKey', event.target.value.trim())}
                    disabled={busy}
                    data-testid="backend-profile-k"
                  />
                </Field>
                <Field label="OPc" error={issues.opc}>
                  <input
                    type="password"
                    autoComplete="off"
                    className="ep-input mono"
                    value={state.opc}
                    onChange={(event) => set('opc', event.target.value.trim())}
                    disabled={busy}
                    data-testid="backend-profile-opc"
                  />
                </Field>
                <p className="col-span-3 text-ep-xs text-text-secondary">
                  A manually entered subscriber must also be provisioned in Open5GS, otherwise the UE will
                  fail authentication. Never read back by the API.
                </p>
              </div>
            )}
          </fieldset>
        )}

        {serverError && (
          <p className="text-ep-sm text-error" role="alert" data-testid="backend-profile-server-error">
            {serverError}
          </p>
        )}

        <footer className="flex justify-end gap-2 pt-1 border-t border-border mt-1">
          <button type="button" className="ep-button ep-button-sm" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="submit"
            className="ep-button ep-button-sm ep-button-primary"
            disabled={busy || Object.keys(issues).length > 0}
            data-testid="backend-profile-submit"
          >
            {busy ? 'Saving…' : mode === 'edit' ? 'Save changes' : mode === 'clone' ? 'Clone profile' : 'Create profile'}
          </button>
        </footer>
      </form>
    </div>
  );
}

function Field({
  label,
  hint,
  error,
  required,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1 text-ep-sm">
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
        {label}
        {required && <span className="text-error ml-0.5">*</span>}
      </span>
      {children}
      {error ? (
        <span className="text-ep-xs text-error">{error}</span>
      ) : hint ? (
        <span className="text-ep-xs text-text-secondary">{hint}</span>
      ) : null}
    </label>
  );
}
