import { useEffect, useRef, useState } from 'react';
import { Lock, Sparkles } from 'lucide-react';
import { useDnns, useGenerateSubscribers } from '@/data/queries';
import type { WireGeneratedSlot } from '@/data/profileApi';
import {
  LAB_AMBR_DEFAULT,
  LAB_DEFAULT_DNNS,
  LAB_DEFAULT_SD,
  LAB_DEFAULT_SST,
  LAB_SD_OPTIONS,
  LAB_SST_OPTIONS,
  sanitizeSd,
} from './subscriberOptions';

/** Bulk subscriber generation dialog for `POST /subscribers/generate`.
 *
 * The UI always sends sst, sd and dnns explicitly (pre-filled with the lab
 * defaults). K and OPc are generated server-side via CSPRNG; they are never
 * displayed, logged or stored by the browser.
 */
export function GenerateSubscribersDialog({
  open,
  onCancel,
  onGenerated,
}: {
  open: boolean;
  onCancel: () => void;
  onGenerated: (slots: WireGeneratedSlot[]) => void;
}) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const mutation = useGenerateSubscribers();
  const dnns = useDnns();

  const [count, setCount] = useState<number>(1);
  const [sst, setSst] = useState<number>(LAB_DEFAULT_SST);
  const [sdInput, setSdInput] = useState<string>(LAB_DEFAULT_SD ?? '');
  const [selectedDnns, setSelectedDnns] = useState<string[]>([...LAB_DEFAULT_DNNS]);
  const [uplink, setUplink] = useState<number>(LAB_AMBR_DEFAULT.uplink);
  const [downlink, setDownlink] = useState<number>(LAB_AMBR_DEFAULT.downlink);
  const [error, setError] = useState<string | null>(null);
  const [generated, setGenerated] = useState<WireGeneratedSlot[] | null>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    setGenerated(null);
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

  if (!open) return null;

  const dnnOptions = dnns.data?.items ?? [...LAB_DEFAULT_DNNS];

  function toggleDnn(name: string) {
    setSelectedDnns((previous) =>
      previous.includes(name) ? previous.filter((item) => item !== name) : [...previous, name],
    );
  }

  function onGenerate() {
    setError(null);
    if (count < 1 || count > 1000) {
      setError('Count must be between 1 and 1000.');
      return;
    }
    if (selectedDnns.length === 0) {
      setError('At least one DNN is required.');
      return;
    }
    mutation.mutate(
      {
        count,
        sst,
        sd: sanitizeSd(sdInput),
        dnns: selectedDnns,
        ambr: { uplink, downlink },
      },
      {
        onSuccess: (result) => {
          setGenerated(result.slots);
          onGenerated(result.slots);
        },
        onError: (err) => setError((err as Error).message ?? 'GENERATE_FAILED'),
      },
    );
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="subscriber-generate-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        className="ep-card w-full max-w-xl p-5 flex flex-col gap-4"
        data-testid="subscriber-generate-dialog"
      >
        <header className="flex items-center justify-between gap-2">
          <h2 id="subscriber-generate-title" className="text-ep-lg font-semibold flex items-center gap-2">
            <Sparkles width={16} height={16} /> Generate subscribers
          </h2>
          <span className="inline-flex items-center gap-1 mono text-ep-xs text-text-secondary">
            <Lock width={11} height={11} /> K/OPc · CSPRNG
          </span>
        </header>
        <p className="text-ep-xs text-text-secondary">
          Fresh IMSIs in <strong>001/01</strong> are allocated by the backend (lowest free MSIN first). K and
          OPc are generated server-side and never leave the server; the response only exposes the opaque slot id.
        </p>

        <div className="grid gap-3 md:grid-cols-3">
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-text-secondary">Count</span>
            <input
              type="number"
              min={1}
              max={1000}
              value={count}
              onChange={(event) => setCount(Math.max(1, Math.min(1000, Number(event.target.value) || 1)))}
              data-testid="subscriber-generate-count"
              className="ep-input"
            />
          </label>
          <label className="flex flex-col gap-1 text-ep-sm">
            <span className="text-text-secondary">SST</span>
            <select
              value={sst}
              onChange={(event) => setSst(Number(event.target.value))}
              data-testid="subscriber-generate-sst"
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
              data-testid="subscriber-generate-sd"
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
          <div className="flex flex-wrap gap-2" data-testid="subscriber-generate-dnns">
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
              className="ep-input"
            />
          </label>
        </div>

        {error ? (
          <div className="ep-badge border-danger/40 text-danger" data-testid="subscriber-generate-error">
            {error}
          </div>
        ) : null}

        {generated ? (
          <section className="ep-card bg-surface-raised p-3 flex flex-col gap-2">
            <h3 className="text-ep-sm font-semibold">
              Generated {generated.length} subscriber{generated.length === 1 ? '' : 's'}
            </h3>
            <ul className="flex flex-col gap-1" data-testid="subscriber-generate-result">
              {generated.map((slot) => (
                <li
                  key={slot.slot}
                  className="flex items-center justify-between text-ep-xs mono"
                  data-testid={`subscriber-generate-slot-${slot.slot}`}
                >
                  <span>{slot.slot}</span>
                  <span className="ep-badge border-primary/40 text-primary">{slot.state}</span>
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <footer className="flex items-center justify-end gap-2 pt-1">
          <button type="button" className="ep-button ep-button-sm" onClick={onCancel} disabled={mutation.isPending}>
            Close
          </button>
          <button
            type="button"
            className="ep-button ep-button-sm ep-button-primary"
            onClick={onGenerate}
            disabled={mutation.isPending}
            data-testid="subscriber-generate-run"
          >
            {mutation.isPending ? 'Generating…' : 'Generate'}
          </button>
        </footer>
      </div>
    </div>
  );
}
