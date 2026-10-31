import { useEffect, useRef, useState } from 'react';
import { KeyRound, Lock, Pencil } from 'lucide-react';
import { useDnns, useSubscriberDetail, useUpdateSubscriber } from '@/data/queries';
import type { WireSubscriberUpdate } from '@/data/profileApi';
import {
  LAB_DEFAULT_DNNS,
  LAB_DEFAULT_SD,
  LAB_DEFAULT_SST,
  LAB_SD_OPTIONS,
  LAB_SST_OPTIONS,
  sanitizeSd,
} from './subscriberOptions';

/** Edit dialog for `PUT /subscribers/:slot`.
 *
 * - SST, SD and DNN are presented as dropdowns (lab-served values only).
 * - K and OPc are write-only text inputs; empty = keep the stored value.
 *   The response never carries K or OPc back.
 */
export function SubscriberEditDialog({
  slot,
  open,
  onCancel,
  onSaved,
}: {
  slot: string;
  open: boolean;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const detail = useSubscriberDetail(open ? slot : null);
  const mutation = useUpdateSubscriber();
  const dnns = useDnns();

  const dialogRef = useRef<HTMLDivElement | null>(null);

  const [sst, setSst] = useState<number>(LAB_DEFAULT_SST);
  const [sdInput, setSdInput] = useState<string>(LAB_DEFAULT_SD ?? '');
  const [selectedDnns, setSelectedDnns] = useState<string[]>([...LAB_DEFAULT_DNNS]);
  const [uplink, setUplink] = useState<number>(1_000_000);
  const [downlink, setDownlink] = useState<number>(1_000_000);
  const [rotateKeys, setRotateKeys] = useState<boolean>(false);
  const [k, setK] = useState<string>('');
  const [opc, setOpc] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    const previousFocus = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();
    const handler = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCancel();
    };
    document.addEventListener('keydown', handler);
    return () => {
      document.removeEventListener('keydown', handler);
      previousFocus?.focus?.();
    };
  }, [open, onCancel]);

  useEffect(() => {
    if (!detail.data) return;
    const subscriber = detail.data.subscriber;
    setSst(subscriber.snssai.sst);
    setSdInput(subscriber.snssai.sd ?? '');
    setSelectedDnns(subscriber.dnns.length > 0 ? subscriber.dnns : [...LAB_DEFAULT_DNNS]);
    setUplink(subscriber.ambr.uplink);
    setDownlink(subscriber.ambr.downlink);
    setRotateKeys(false);
    setK('');
    setOpc('');
  }, [detail.data]);

  if (!open) return null;

  const dnnOptions = dnns.data?.items ?? [...LAB_DEFAULT_DNNS];

  function toggleDnn(name: string) {
    setSelectedDnns((previous) =>
      previous.includes(name) ? previous.filter((item) => item !== name) : [...previous, name],
    );
  }

  function onSave() {
    setError(null);
    if (selectedDnns.length === 0) {
      setError('At least one DNN is required.');
      return;
    }
    if (rotateKeys) {
      if (k.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(k)) {
        setError('K must be 32 hex characters.');
        return;
      }
      if (opc.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(opc)) {
        setError('OPc must be 32 hex characters.');
        return;
      }
    }
    const body: WireSubscriberUpdate = {
      sst,
      sd: sanitizeSd(sdInput),
      dnns: selectedDnns,
      ambr: { uplink, downlink },
    };
    if (rotateKeys) {
      body.k = k;
      body.opc = opc;
    }
    mutation.mutate(
      { slot, body },
      {
        onSuccess: () => onSaved(),
        onError: (err) => setError((err as Error).message ?? 'UPDATE_FAILED'),
      },
    );
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="subscriber-edit-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        className="ep-card w-full max-w-xl p-5 flex flex-col gap-4"
        data-testid="subscriber-edit-dialog"
      >
        <header className="flex items-center justify-between gap-2">
          <h2 id="subscriber-edit-title" className="text-ep-lg font-semibold flex items-center gap-2">
            <Pencil width={16} height={16} /> Edit subscriber
          </h2>
          <span className="inline-flex items-center gap-1 mono text-ep-xs text-text-secondary">
            <KeyRound width={11} height={11} /> {slot}
          </span>
        </header>
        <p className="text-ep-xs text-text-secondary">
          Identity and authentication material stay <strong>PROTECTED</strong>: the UI never reads K or OPc back from the server.
        </p>

        {detail.isLoading ? (
          <div className="text-ep-sm text-text-secondary">Loading…</div>
        ) : detail.error ? (
          <div className="ep-badge border-danger/40 text-danger">
            {(detail.error as Error).message}
          </div>
        ) : null}

        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-text-secondary">SST</span>
            <select
              value={sst}
              onChange={(event) => setSst(Number(event.target.value))}
              data-testid="subscriber-edit-sst"
              className="ep-input"
            >
              {LAB_SST_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-text-secondary">SD</span>
            <select
              value={sdInput || 'absent'}
              onChange={(event) => setSdInput(event.target.value === 'absent' ? '' : event.target.value)}
              data-testid="subscriber-edit-sd"
              className="ep-input"
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
          <legend className="text-text-secondary">DNNs</legend>
          <div className="flex flex-wrap gap-2" data-testid="subscriber-edit-dnns">
            {dnnOptions.map((name) => (
              <label key={name} className="inline-flex items-center gap-1 ep-badge border-border">
                <input
                  type="checkbox"
                  checked={selectedDnns.includes(name)}
                  onChange={() => toggleDnn(name)}
                />
                <span className="mono">{name}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-text-secondary">AMBR uplink (bps)</span>
            <input
              type="number"
              min={1}
              value={uplink}
              onChange={(event) => setUplink(Math.max(1, Number(event.target.value)))}
              data-testid="subscriber-edit-uplink"
              className="ep-input"
            />
          </label>
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-text-secondary">AMBR downlink (bps)</span>
            <input
              type="number"
              min={1}
              value={downlink}
              onChange={(event) => setDownlink(Math.max(1, Number(event.target.value)))}
              data-testid="subscriber-edit-downlink"
              className="ep-input"
            />
          </label>
        </div>

        <section className="ep-card bg-surface-raised p-3 flex flex-col gap-2" data-testid="subscriber-edit-keys">
          <label className="inline-flex items-center gap-2 text-ep-sm">
            <input
              type="checkbox"
              checked={rotateKeys}
              onChange={(event) => setRotateKeys(event.target.checked)}
            />
            <Lock width={13} height={13} />
            <span>Rotate authentication material (write-only)</span>
          </label>
          {rotateKeys ? (
            <div className="grid gap-2 md:grid-cols-2">
              <label className="flex flex-col gap-1 text-ep-sm">
                <span className="text-text-secondary">K (32 hex chars)</span>
                <input
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={k}
                  onChange={(event) => setK(event.target.value)}
                  placeholder="PROTECTED — write-only"
                  data-testid="subscriber-edit-k"
                  className="ep-input mono"
                />
              </label>
              <label className="flex flex-col gap-1 text-ep-sm">
                <span className="text-text-secondary">OPc (32 hex chars)</span>
                <input
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={opc}
                  onChange={(event) => setOpc(event.target.value)}
                  placeholder="PROTECTED — write-only"
                  data-testid="subscriber-edit-opc"
                  className="ep-input mono"
                />
              </label>
            </div>
          ) : (
            <p className="text-ep-xs text-text-secondary">
              K and OPc remain unchanged. Enable rotation to write new 32-hex values.
            </p>
          )}
        </section>

        {error ? (
          <div className="ep-badge border-danger/40 text-danger" data-testid="subscriber-edit-error">
            {error}
          </div>
        ) : null}

        <footer className="flex items-center justify-end gap-2 pt-1">
          <button type="button" className="ep-button ep-button-sm" onClick={onCancel} disabled={mutation.isPending}>
            Cancel
          </button>
          <button
            type="button"
            className="ep-button ep-button-sm ep-button-primary"
            onClick={onSave}
            disabled={mutation.isPending || !detail.data}
            data-testid="subscriber-edit-save"
          >
            {mutation.isPending ? 'Saving…' : 'Save'}
          </button>
        </footer>
      </div>
    </div>
  );
}
