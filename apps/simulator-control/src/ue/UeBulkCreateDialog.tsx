import { useEffect, useMemo, useState } from 'react';
import { X } from 'lucide-react';
import {
  generateBulk,
  MAX_PROFILES,
  type BulkCreateSpec,
  type UeProfileDraft,
} from './profileModel';

const DEFAULT_SPEC: BulkCreateSpec = {
  count: 50,
  prefix: 'ue-',
  startIndex: 1,
  padWidth: 5,
  owner: 'ops',
  servingGnb: 'gnb-01',
  plmn: '20899',
  apn: 'internet',
  imsiBase: '208990000000000',
};

export function UeBulkCreateDialog({
  open,
  existingCount,
  busy,
  onSubmit,
  onCancel,
}: {
  open: boolean;
  existingCount: number;
  busy?: boolean;
  onSubmit: (profiles: UeProfileDraft[]) => Promise<void> | void;
  onCancel: () => void;
}) {
  const [spec, setSpec] = useState<BulkCreateSpec>(DEFAULT_SPEC);
  const [serverError, setServerError] = useState('');

  useEffect(() => {
    if (!open) return;
    setSpec(DEFAULT_SPEC);
    setServerError('');
  }, [open]);

  const preview = useMemo(() => generateBulk({ ...spec, count: Math.min(spec.count, 5) }), [spec]);

  const remainingSlots = Math.max(0, MAX_PROFILES - existingCount);
  const capacityError =
    spec.count > remainingSlots
      ? `Only ${remainingSlots.toLocaleString()} profile slot(s) left; capped at ${MAX_PROFILES.toLocaleString()} per browser.`
      : '';

  if (!open) return null;

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const result = generateBulk(spec);
    if (result.errors.length > 0) {
      setServerError(result.errors.join(' · '));
      return;
    }
    if (capacityError) {
      setServerError(capacityError);
      return;
    }
    try {
      await onSubmit(result.profiles);
    } catch (error) {
      setServerError((error as Error).message);
    }
  }

  function set<K extends keyof BulkCreateSpec>(key: K, value: BulkCreateSpec[K]) {
    setSpec((prev) => ({ ...prev, [key]: value }));
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ue-bulk-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      data-testid="ue-bulk-dialog"
    >
      <form
        className="ep-card w-full max-w-2xl p-5 flex flex-col gap-3"
        onSubmit={handleSubmit}
      >
        <header className="flex items-center justify-between">
          <h2 id="ue-bulk-title" className="text-ep-lg font-semibold">
            Bulk create UE profiles
          </h2>
          <button type="button" className="ep-button ep-button-sm" onClick={onCancel} aria-label="Close">
            <X width={13} height={13} />
          </button>
        </header>

        <p className="text-ep-xs text-text-secondary">
          Generates sequential profiles stored in the browser. Capacity is limited to
          <span className="mono"> {MAX_PROFILES.toLocaleString()}</span> profiles total per browser.
          Currently stored: <span className="mono">{existingCount.toLocaleString()}</span>.
        </p>

        <div className="grid grid-cols-3 gap-3">
          <Field label="Count">
            <input
              type="number"
              min={1}
              max={MAX_PROFILES}
              className="ep-input mono"
              value={spec.count}
              onChange={(event) => set('count', Number(event.target.value))}
              required
              data-testid="bulk-count"
            />
          </Field>
          <Field label="ID prefix" hint="Example: ue-">
            <input
              className="ep-input mono"
              value={spec.prefix}
              onChange={(event) => set('prefix', event.target.value)}
              required
              data-testid="bulk-prefix"
            />
          </Field>
          <Field label="Start index">
            <input
              type="number"
              min={0}
              className="ep-input mono"
              value={spec.startIndex}
              onChange={(event) => set('startIndex', Number(event.target.value))}
              required
            />
          </Field>
          <Field label="Pad width" hint="Zero-pads the suffix (e.g. 5 → 00001)">
            <input
              type="number"
              min={1}
              max={10}
              className="ep-input mono"
              value={spec.padWidth}
              onChange={(event) => set('padWidth', Number(event.target.value))}
              required
            />
          </Field>
          <Field label="Owner">
            <input
              className="ep-input"
              value={spec.owner}
              onChange={(event) => set('owner', event.target.value)}
              required
            />
          </Field>
          <Field label="Serving gNB">
            <input
              className="ep-input"
              value={spec.servingGnb}
              onChange={(event) => set('servingGnb', event.target.value)}
              required
            />
          </Field>
          <Field label="PLMN">
            <input
              className="ep-input mono"
              value={spec.plmn ?? ''}
              onChange={(event) => set('plmn', event.target.value)}
            />
          </Field>
          <Field label="APN">
            <input
              className="ep-input"
              value={spec.apn ?? ''}
              onChange={(event) => set('apn', event.target.value)}
            />
          </Field>
          <Field label="IMSI base" hint="Suffix is appended, truncated to 15 digits">
            <input
              className="ep-input mono"
              value={spec.imsiBase ?? ''}
              onChange={(event) => set('imsiBase', event.target.value)}
            />
          </Field>
        </div>

        <section className="border border-border rounded-md p-3 bg-canvas/50">
          <p className="text-ep-xs uppercase tracking-wider text-text-secondary mb-1">
            Preview (first {preview.profiles.length})
          </p>
          <ul className="text-ep-xs mono flex flex-col gap-0.5" data-testid="bulk-preview">
            {preview.profiles.map((profile) => (
              <li key={profile.id}>
                {profile.id} · owner={profile.owner} · gnb={profile.servingGnb}
                {profile.imsi ? ` · imsi=${profile.imsi}` : ''}
              </li>
            ))}
            {preview.profiles.length === 0 && (
              <li className="text-text-secondary">(no preview — fix validation first)</li>
            )}
          </ul>
          {preview.errors.length > 0 && (
            <p className="text-ep-xs text-error mt-2">{preview.errors.join(' · ')}</p>
          )}
        </section>

        {(serverError || capacityError) && (
          <p className="text-ep-sm text-error" data-testid="bulk-error">
            {serverError || capacityError}
          </p>
        )}

        <footer className="flex justify-end gap-2 pt-1 border-t border-border mt-1">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onCancel}
            disabled={busy}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="ep-button ep-button-sm ep-button-primary"
            disabled={busy}
            data-testid="bulk-submit"
          >
            {busy
              ? 'Creating…'
              : `Create ${spec.count.toLocaleString()} profile${spec.count === 1 ? '' : 's'}`}
          </button>
        </footer>
      </form>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1 text-ep-sm">
      <span className="text-ep-xs uppercase tracking-wider text-text-secondary">{label}</span>
      {children}
      {hint && <span className="text-ep-xs text-text-secondary">{hint}</span>}
    </label>
  );
}
