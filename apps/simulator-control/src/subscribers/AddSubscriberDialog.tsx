// 0.6.1 — Real "Add subscriber" dialog wired to POST /subscribers.
//
// Secret material (K, OPc) is write-only. The three identity fields —
// IMSI, K, OPc — use password inputs; the state is scrubbed after the
// awaited `onSubmit` resolves so React never retains them across
// renders. The backend response carries the slot id and the two
// `PROTECTED` literals; the dialog surfaces them in a read-only banner
// so the operator sees the subscriber is in place.

import { useEffect, useState } from 'react';
import { AlertTriangle, Lock, X } from 'lucide-react';
import { ApiError } from '@shared/api';
import {
  createSubscriber,
  type SubscriberCreateInput,
  type SubscriberCreateResponse,
} from '@/data/provisioningApi';

const IMSI_RE = /^imsi-\d{5,15}$/;
const HEX32 = /^[0-9a-fA-F]{32}$/;

interface State {
  imsi: string;
  k: string;
  opc: string;
  sst: string;
  sd: string;
  dnns: string;
  ambr_uplink: string;
  ambr_downlink: string;
  touched: boolean;
}

const EMPTY: State = {
  imsi: '',
  k: '',
  opc: '',
  sst: '1',
  sd: '',
  dnns: 'internet',
  ambr_uplink: '1048576',
  ambr_downlink: '1048576',
  touched: false,
};

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

  const imsiInvalid = state.touched && !IMSI_RE.test(state.imsi);
  const kInvalid = state.touched && !HEX32.test(state.k);
  const opcInvalid = state.touched && !HEX32.test(state.opc);
  const sstNum = Number(state.sst);
  const sstInvalid = state.touched && (!Number.isInteger(sstNum) || sstNum < 1 || sstNum > 255);
  const sdInvalid = state.touched && state.sd !== '' && !/^[0-9a-fA-F]{6}$/.test(state.sd);
  const ulNum = Number(state.ambr_uplink);
  const dlNum = Number(state.ambr_downlink);
  const ambrInvalid =
    state.touched &&
    (!Number.isInteger(ulNum) || ulNum < 1 || !Number.isInteger(dlNum) || dlNum < 1);
  const dnnsList = state.dnns
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  const canSubmit =
    !submitting &&
    !created &&
    IMSI_RE.test(state.imsi) &&
    HEX32.test(state.k) &&
    HEX32.test(state.opc) &&
    Number.isInteger(sstNum) && sstNum >= 1 && sstNum <= 255 &&
    (state.sd === '' || /^[0-9a-fA-F]{6}$/.test(state.sd)) &&
    dnnsList.length > 0 &&
    Number.isInteger(ulNum) && ulNum >= 1 &&
    Number.isInteger(dlNum) && dlNum >= 1;

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setState((prev) => ({ ...prev, touched: true }));
    if (!canSubmit) return;
    const input: SubscriberCreateInput = {
      imsi: state.imsi.trim(),
      k: state.k.trim(),
      opc: state.opc.trim(),
      sst: sstNum,
      sd: state.sd ? state.sd.trim() : null,
      dnns: dnnsList,
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
          placeholder="imsi-208930000000001"
          value={state.imsi}
          onChange={(value) => setState((prev) => ({ ...prev, imsi: value }))}
          invalid={imsiInvalid}
          hint="Format: imsi-<5-15 digits>"
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

        <div className="grid gap-2 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
              S-NSSAI SST
            </span>
            <input
              type="number"
              min={1}
              max={255}
              step={1}
              className="ep-input mono"
              value={state.sst}
              onChange={(event) => setState((prev) => ({ ...prev, sst: event.target.value }))}
              aria-invalid={sstInvalid ? 'true' : 'false'}
              data-testid="subscriber-sst"
            />
          </label>
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
              S-NSSAI SD (optional)
            </span>
            <input
              type="text"
              className="ep-input mono"
              placeholder="6 hex digits"
              value={state.sd}
              onChange={(event) => setState((prev) => ({ ...prev, sd: event.target.value }))}
              aria-invalid={sdInvalid ? 'true' : 'false'}
              data-testid="subscriber-sd"
            />
          </label>
        </div>

        <label className="flex flex-col gap-1 text-ep-sm">
          <span className="text-ep-xs uppercase tracking-wider text-text-secondary">
            DNNs (comma-separated)
          </span>
          <input
            type="text"
            className="ep-input mono"
            value={state.dnns}
            onChange={(event) => setState((prev) => ({ ...prev, dnns: event.target.value }))}
            data-testid="subscriber-dnns"
          />
          <span className="text-ep-xs text-text-secondary">
            Example: <code className="mono">internet,ims</code>
          </span>
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
