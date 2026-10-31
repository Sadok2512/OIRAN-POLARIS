// 0.6.1 — Real "Add subscriber" dialog wired to POST /subscribers.
//
// Secret material (K, OPc) is write-only. The three identity fields —
// IMSI, K, OPc — use password inputs; the state is scrubbed after the
// awaited `onSubmit` resolves so React never retains them across
// renders. The backend response carries the slot id and the two
// `PROTECTED` literals; the dialog surfaces them in a read-only banner
// so the operator sees the subscriber is in place.

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Lock, X } from 'lucide-react';
import { ApiError } from '@shared/api';
import {
  createSubscriber,
  useDnns,
  usePlmns,
  type PlmnSlice,
  type SubscriberCreateInput,
  type SubscriberCreateResponse,
} from '@/data/provisioningApi';
import { isImsiValid, normalizeImsi } from '@/data/identityFormats';

const HEX32 = /^[0-9a-fA-F]{32}$/;

interface State {
  imsi: string;
  k: string;
  opc: string;
  /** Serialised "sst/sd" key referencing one PlmnSlice entry. */
  slice: string;
  /** DNN id picked from /dnns. */
  dnn: string;
  ambr_uplink: string;
  ambr_downlink: string;
  touched: boolean;
}

// 0.10.0 — AMBR default raised to 1 Gbit/s in kbps (= 1_000_000). Operators
// were defaulting the field manually before every create; honest UX is to
// seed the field with the lab-standard throughput.
const DEFAULT_AMBR_KBPS = '1000000';

// 0.10.0 — Lab-standard S-NSSAI used when /plmns returns no slice descriptor
// (the deployed backend currently serves `{items: ["001-01"]}` without
// slices). We fall back to this pair and tag the option explicitly so the
// operator knows it comes from the lab, not from the backend inventory.
const LAB_FALLBACK_SST = 1;
const LAB_FALLBACK_SD = '010203';
const LAB_FALLBACK_SLICE_KEY = `${LAB_FALLBACK_SST}/${LAB_FALLBACK_SD}`;

const EMPTY: State = {
  imsi: '',
  k: '',
  opc: '',
  slice: '',
  dnn: '',
  ambr_uplink: DEFAULT_AMBR_KBPS,
  ambr_downlink: DEFAULT_AMBR_KBPS,
  touched: false,
};

function sliceKey(slice: PlmnSlice): string {
  return `${slice.sst}/${slice.sd ?? ''}`;
}

function parseSliceKey(key: string): { sst: number; sd: string | null } | null {
  const match = /^(\d+)\/([0-9a-fA-F]*)$/.exec(key);
  if (!match) return null;
  const sst = Number(match[1]);
  if (!Number.isInteger(sst) || sst < 1 || sst > 255) return null;
  const sd = match[2].length === 0 ? null : match[2];
  return { sst, sd };
}

export function AddSubscriberDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated?: (response: SubscriberCreateResponse) => void;
}) {
  const [state, setState] = useState<State>(EMPTY);
  const [submitting, setSubmitting] = useState(false);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [created, setCreated] = useState<SubscriberCreateResponse | null>(null);

  const plmns = usePlmns();
  const dnns = useDnns();

  // 0.10.0 — /plmns on the deployed backend returns `{items: string[]}`
  // (PLMN labels only, no slice descriptors). The 0.7.1 schema that
  // carries `.slices` is still typed here for forward compat. When no
  // slice is advertised we fall back to the lab-standard SST=1 / SD=010203
  // pair and tag the option explicitly so the operator sees it is a lab
  // value, not something read from the backend.
  const { sliceOptions, sliceFallback } = useMemo(() => {
    const map = new Map<string, { key: string; label: string; sst: number; sd: string | null }>();
    const rawItems = (plmns.data as unknown as { items?: unknown[] })?.items ?? [];
    let anySlice = false;
    for (const raw of rawItems) {
      if (!raw || typeof raw !== 'object') continue;
      const plmn = raw as Partial<{
        id: string;
        mcc: string;
        mnc: string;
        slices: PlmnSlice[];
      }>;
      const mccMnc = plmn.mcc && plmn.mnc ? `${plmn.mcc}/${plmn.mnc}` : plmn.id ?? '—';
      for (const slice of plmn.slices ?? []) {
        anySlice = true;
        const key = sliceKey(slice);
        if (map.has(key)) continue;
        const sliceLabel =
          slice.display_name ?? `S-NSSAI ${slice.sst}${slice.sd ? `/${slice.sd}` : ''}`;
        map.set(key, {
          key,
          label: `${mccMnc} · ${sliceLabel}`,
          sst: slice.sst,
          sd: slice.sd,
        });
      }
    }
    const fallback = !plmns.isLoading && !anySlice;
    if (fallback) {
      map.set(LAB_FALLBACK_SLICE_KEY, {
        key: LAB_FALLBACK_SLICE_KEY,
        label: `S-NSSAI ${LAB_FALLBACK_SST}/${LAB_FALLBACK_SD} · valeur du labo`,
        sst: LAB_FALLBACK_SST,
        sd: LAB_FALLBACK_SD,
      });
    }
    return { sliceOptions: Array.from(map.values()), sliceFallback: fallback };
  }, [plmns.data, plmns.isLoading]);

  // 0.10.0 — /dnns on the deployed backend returns `{items: string[]}`
  // (e.g. ["internet","ims"]). The old `Dnn[]` shape (objects with .dnn
  // and .description) is still valid: normalize both into `{value,label}`
  // so the dropdown stays honest and we no longer render a bare "·".
  const dnnOptions = useMemo(() => {
    const raw = (dnns.data as unknown as { items?: unknown[] })?.items ?? [];
    const seen = new Set<string>();
    const normalized: { value: string; label: string }[] = [];
    for (const entry of raw) {
      if (typeof entry === 'string') {
        if (seen.has(entry)) continue;
        seen.add(entry);
        normalized.push({ value: entry, label: entry });
        continue;
      }
      if (entry && typeof entry === 'object') {
        const record = entry as { id?: string; dnn?: string; description?: string };
        const value = record.dnn ?? record.id;
        if (!value || seen.has(value)) continue;
        seen.add(value);
        normalized.push({
          value,
          label: record.description ? `${value} · ${record.description}` : value,
        });
      }
    }
    return normalized;
  }, [dnns.data]);

  useEffect(() => {
    if (!open) {
      setState(EMPTY);
      setErrorCode(null);
      setErrorStatus(null);
      setErrorMessage(null);
      setCreated(null);
      setSubmitting(false);
    }
  }, [open]);

  if (!open) return null;

  const imsiInvalid = state.touched && !isImsiValid(state.imsi);
  const kInvalid = state.touched && !HEX32.test(state.k);
  const opcInvalid = state.touched && !HEX32.test(state.opc);
  const sliceParsed = parseSliceKey(state.slice);
  const sliceInvalid = state.touched && !sliceParsed;
  const dnnInvalid = state.touched && !state.dnn;
  const ulNum = Number(state.ambr_uplink);
  const dlNum = Number(state.ambr_downlink);
  const ambrInvalid =
    state.touched &&
    (!Number.isInteger(ulNum) || ulNum < 1 || !Number.isInteger(dlNum) || dlNum < 1);

  const plmnsEmpty = !plmns.isLoading && sliceOptions.length === 0;
  const dnnsEmpty = !dnns.isLoading && dnnOptions.length === 0;

  const canSubmit =
    !submitting &&
    !created &&
    isImsiValid(state.imsi) &&
    HEX32.test(state.k) &&
    HEX32.test(state.opc) &&
    !!sliceParsed &&
    !!state.dnn &&
    Number.isInteger(ulNum) && ulNum >= 1 &&
    Number.isInteger(dlNum) && dlNum >= 1;

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setState((prev) => ({ ...prev, touched: true }));
    if (!canSubmit || !sliceParsed) return;
    const normalisedImsi = normalizeImsi(state.imsi);
    if (!normalisedImsi) return;
    const input: SubscriberCreateInput = {
      imsi: normalisedImsi,
      k: state.k.trim(),
      opc: state.opc.trim(),
      sst: sliceParsed.sst,
      sd: sliceParsed.sd,
      dnns: [state.dnn],
      ambr: { uplink: ulNum, downlink: dlNum },
    };
    // Scrub secret material from local state BEFORE the network call
    // returns, so a slow backend can never pin them in memory.
    setState((prev) => ({ ...prev, imsi: '', k: '', opc: '' }));
    setSubmitting(true);
    setErrorCode(null);
    setErrorStatus(null);
    setErrorMessage(null);
    try {
      const response = await createSubscriber(input);
      setCreated(response);
      onCreated?.(response);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorCode(err.code);
        setErrorStatus(err.status);
        setErrorMessage(err.message);
      } else {
        setErrorCode('SUBSCRIBER_CREATE_FAILED');
        setErrorStatus(null);
        setErrorMessage((err as Error).message);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="add-subscriber-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4"
      data-testid="add-subscriber-dialog"
    >
      <form
        className="ep-card w-full max-w-xl p-5 flex flex-col gap-3 my-4"
        onSubmit={handleSubmit}
      >
        <header className="flex items-center justify-between">
          <h2 id="add-subscriber-title" className="text-ep-lg font-semibold">
            Add subscriber
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
          POST <code className="mono">/subscribers</code>. IMSI, K and OPc are typed in masked
          password inputs, sent once, and never kept in the browser state after submit.
        </p>

        <SecretField
          label="IMSI"
          placeholder="001010000000201 or imsi-001010000000201"
          value={state.imsi}
          onChange={(value) => setState((prev) => ({ ...prev, imsi: value }))}
          invalid={imsiInvalid}
          hint="Raw digits (5–15) or imsi-<digits>; normalised before send."
          testid="subscriber-imsi"
          onBlur={() => setState((prev) => ({ ...prev, touched: true }))}
        />

        <SecretField
          label="K"
          placeholder="32 hex digits"
          value={state.k}
          onChange={(value) => setState((prev) => ({ ...prev, k: value }))}
          invalid={kInvalid}
          hint="32 hex digits (128 bit permanent key)"
          testid="subscriber-k"
          onBlur={() => setState((prev) => ({ ...prev, touched: true }))}
        />

        <SecretField
          label="OPc"
          placeholder="32 hex digits"
          value={state.opc}
          onChange={(value) => setState((prev) => ({ ...prev, opc: value }))}
          invalid={opcInvalid}
          hint="32 hex digits (operator variant)"
          testid="subscriber-opc"
          onBlur={() => setState((prev) => ({ ...prev, touched: true }))}
        />

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
            Slice (S-NSSAI) · PLMN
          </span>
          <select
            className="ep-input mono"
            value={state.slice}
            onChange={(event) => setState((prev) => ({ ...prev, slice: event.target.value }))}
            disabled={plmnsEmpty || plmns.isLoading}
            aria-invalid={sliceInvalid ? 'true' : 'false'}
            data-testid="subscriber-slice"
          >
            <option value="">
              {plmns.isLoading
                ? 'Loading…'
                : plmnsEmpty
                  ? 'Backend pending — /plmns returned no slice'
                  : 'Choose a slice'}
            </option>
            {sliceOptions.map((option) => (
              <option key={option.key} value={option.key}>
                {option.label}
              </option>
            ))}
          </select>
          <span className="text-ep-xs text-text-secondary">
            Free SST/SD input is gone (hardening after two subscribers landed on 1/000001 and were
            not served). Slices come from <code className="mono">/plmns</code>.
          </span>
          {sliceFallback && (
            <span
              className="text-ep-xs text-warning flex items-start gap-1"
              data-testid="subscriber-slice-fallback"
            >
              <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
              /plmns ne publie pas de slice — proposition SST {LAB_FALLBACK_SST} / SD {LAB_FALLBACK_SD} (valeur du labo).
            </span>
          )}
        </label>

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">DNN</span>
          <select
            className="ep-input mono"
            value={state.dnn}
            onChange={(event) => setState((prev) => ({ ...prev, dnn: event.target.value }))}
            disabled={dnnsEmpty || dnns.isLoading}
            aria-invalid={dnnInvalid ? 'true' : 'false'}
            data-testid="subscriber-dnn"
          >
            <option value="">
              {dnns.isLoading
                ? 'Loading…'
                : dnnsEmpty
                  ? 'Backend pending — /dnns returned no entry'
                  : 'Choose a DNN'}
            </option>
            {dnnOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>

        <div className="grid gap-2 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
              AMBR uplink (kbps)
            </span>
            <input
              type="number"
              min={1}
              step={1}
              className="ep-input mono"
              value={state.ambr_uplink}
              onChange={(event) =>
                setState((prev) => ({ ...prev, ambr_uplink: event.target.value }))
              }
              aria-invalid={ambrInvalid ? 'true' : 'false'}
              data-testid="subscriber-ambr-ul"
            />
          </label>
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
              AMBR downlink (kbps)
            </span>
            <input
              type="number"
              min={1}
              step={1}
              className="ep-input mono"
              value={state.ambr_downlink}
              onChange={(event) =>
                setState((prev) => ({ ...prev, ambr_downlink: event.target.value }))
              }
              aria-invalid={ambrInvalid ? 'true' : 'false'}
              data-testid="subscriber-ambr-dl"
            />
          </label>
        </div>

        {errorCode && (
          <div
            role="alert"
            className="ep-card border-error/30 p-3 text-ep-sm text-error flex flex-col gap-1"
            data-testid="add-subscriber-error"
          >
            <p>
              {errorStatus ? <strong>HTTP {errorStatus}</strong> : null} ·{' '}
              <span className="mono">{errorCode}</span>
            </p>
            {errorMessage && (
              <p className="text-ep-xs text-text-secondary">{errorMessage}</p>
            )}
          </div>
        )}

        {created && (
          <div
            className="ep-card border-success/30 p-3 text-ep-sm flex flex-col gap-1"
            data-testid="add-subscriber-created"
          >
            <p>
              <strong>Subscriber created</strong> · slot{' '}
              <span className="mono">{created.slot_id}</span>
            </p>
            <p className="text-ep-xs text-text-secondary flex items-center gap-1">
              <Lock width={11} height={11} /> IMSI / K / OPc stored on the backend as
              <code className="mono"> PROTECTED</code>; the browser no longer holds them.
            </p>
          </div>
        )}

        <footer className="flex items-center justify-end gap-2 pt-2 border-t border-border">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onClose}
            disabled={submitting}
          >
            Close
          </button>
          <button
            type="submit"
            className="ep-button ep-button-sm ep-button-primary"
            disabled={!canSubmit}
            data-testid="add-subscriber-submit"
          >
            {submitting ? 'Creating…' : created ? 'Created' : 'Create subscriber'}
          </button>
        </footer>
      </form>
    </div>
  );
}

function SecretField({
  label,
  placeholder,
  value,
  onChange,
  invalid,
  hint,
  testid,
  onBlur,
}: {
  label: string;
  placeholder: string;
  value: string;
  onChange: (value: string) => void;
  invalid: boolean;
  hint: string;
  testid: string;
  onBlur: () => void;
}) {
  return (
    <label className="flex flex-col gap-1 text-ep-sm">
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary">{label}</span>
      <input
        type="password"
        autoComplete="off"
        spellCheck={false}
        placeholder={placeholder}
        className="ep-input mono"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onBlur={onBlur}
        aria-invalid={invalid ? 'true' : 'false'}
        data-testid={testid}
      />
      {invalid ? (
        <span className="text-ep-xs text-error flex items-start gap-1" data-testid={`${testid}-error`}>
          <AlertTriangle width={11} height={11} className="mt-0.5 shrink-0" />
          {hint}
        </span>
      ) : (
        <span className="text-ep-xs text-text-secondary">{hint}</span>
      )}
    </label>
  );
}
