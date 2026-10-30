import { useEffect, useMemo, useRef, useState } from 'react';
import { X } from 'lucide-react';
import {
  emptyProfile,
  validateProfile,
  type ProfileIssue,
  type UeProfileDraft,
} from './profileModel';
import { nextFreeImsiFor } from './imsiHelpers';

export type ProfileFormMode = 'create' | 'edit' | 'clone';

const FIELD_LABELS: Record<keyof UeProfileDraft, string> = {
  id: 'UE ID',
  owner: 'Owner',
  servingGnb: 'Serving gNB',
  imsi: 'IMSI',
  plmn: 'PLMN',
  apn: 'APN',
  ueIp: 'UE IP',
  notes: 'Notes',
};

const FIELD_HINTS: Partial<Record<keyof UeProfileDraft, string>> = {
  id: 'Unique identifier (letters, digits, _ . : -)',
  // 0.10.2 (#41) — The hint flags the lab-fictive 999... prefix so
  // operators never paste a real IMSI into the form.
  imsi: '14–16 digits. Default = next free lab IMSI (999010000000NNN).',
  plmn: 'Optional. 5 or 6 digits.',
  ueIp: 'Optional. IPv4 (set by backend when PDU session is up).',
  apn: 'Optional. Access Point Name used for PDU establishment.',
};

export function UeProfileFormDialog({
  mode,
  initial,
  open,
  busy,
  onSubmit,
  onCancel,
}: {
  mode: ProfileFormMode;
  initial?: UeProfileDraft;
  open: boolean;
  busy?: boolean;
  onSubmit: (draft: UeProfileDraft) => Promise<void> | void;
  onCancel: () => void;
}) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const [draft, setDraft] = useState<UeProfileDraft>(() => initial ?? emptyProfile());
  const [serverError, setServerError] = useState('');

  useEffect(() => {
    if (!open) return;
    setDraft(initial ?? emptyProfile());
    setServerError('');
    dialogRef.current?.focus();
  }, [open, initial]);

  // 0.10.2 (#41) — Prefill the IMSI field with the next free lab IMSI
  // derived from the UE id as the operator types it. Only applied when
  // the field is currently empty, so a manual override is sticky.
  const defaultImsiForId = useMemo(() => nextFreeImsiFor(draft.id ?? ''), [draft.id]);
  useEffect(() => {
    if (!open) return;
    if (!defaultImsiForId) return;
    if (draft.imsi && draft.imsi.trim().length > 0) return;
    setDraft((prev) => ({ ...prev, imsi: defaultImsiForId.replace(/^imsi-/, '') }));
  }, [open, defaultImsiForId, draft.imsi]);

  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCancel();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onCancel]);

  if (!open) return null;

  const issues = validateProfile(draft);
  const issuesByField = indexIssues(issues);
  const title =
    mode === 'create'
      ? 'Add UE profile'
      : mode === 'edit'
        ? 'Edit UE profile'
        : 'Clone UE profile';

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (issues.length > 0) return;
    try {
      setServerError('');
      await onSubmit(draft);
    } catch (error) {
      setServerError((error as Error).message);
    }
  }

  function set<K extends keyof UeProfileDraft>(key: K, value: UeProfileDraft[K]) {
    setDraft((prev) => ({ ...prev, [key]: value }));
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ue-profile-form-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      data-testid="ue-profile-form"
    >
      <form
        ref={dialogRef as unknown as React.RefObject<HTMLFormElement>}
        tabIndex={-1}
        onSubmit={handleSubmit}
        className="ep-card w-full max-w-xl p-5 flex flex-col gap-3"
      >
        <header className="flex items-center justify-between">
          <h2 id="ue-profile-form-title" className="text-ep-lg font-semibold">
            {title}
          </h2>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onCancel}
            aria-label="Close"
          >
            <X width={13} height={13} />
          </button>
        </header>

        <div className="grid grid-cols-2 gap-3">
          <Field
            label={FIELD_LABELS.id}
            hint={FIELD_HINTS.id}
            error={issuesByField.id}
            required
          >
            <input
              className="ep-input mono"
              value={draft.id}
              onChange={(event) => set('id', event.target.value)}
              autoFocus
              disabled={busy}
              data-testid="profile-field-id"
            />
          </Field>
          <Field label={FIELD_LABELS.owner} error={issuesByField.owner} required>
            <input
              className="ep-input"
              value={draft.owner}
              onChange={(event) => set('owner', event.target.value)}
              disabled={busy}
              data-testid="profile-field-owner"
            />
          </Field>
          <Field label={FIELD_LABELS.servingGnb} error={issuesByField.servingGnb} required>
            <input
              className="ep-input"
              value={draft.servingGnb}
              onChange={(event) => set('servingGnb', event.target.value)}
              disabled={busy}
              data-testid="profile-field-servingGnb"
            />
          </Field>
          <Field label={FIELD_LABELS.plmn} hint={FIELD_HINTS.plmn} error={issuesByField.plmn}>
            <input
              className="ep-input mono"
              value={draft.plmn ?? ''}
              onChange={(event) => set('plmn', event.target.value)}
              disabled={busy}
            />
          </Field>
          <Field label={FIELD_LABELS.imsi} hint={FIELD_HINTS.imsi} error={issuesByField.imsi}>
            <input
              className="ep-input mono"
              value={draft.imsi ?? ''}
              onChange={(event) => set('imsi', event.target.value)}
              disabled={busy}
            />
          </Field>
          <Field label={FIELD_LABELS.apn} hint={FIELD_HINTS.apn} error={issuesByField.apn}>
            <input
              className="ep-input"
              value={draft.apn ?? ''}
              onChange={(event) => set('apn', event.target.value)}
              disabled={busy}
            />
          </Field>
          <Field label={FIELD_LABELS.ueIp} hint={FIELD_HINTS.ueIp} error={issuesByField.ueIp}>
            <input
              className="ep-input mono"
              value={draft.ueIp ?? ''}
              onChange={(event) => set('ueIp', event.target.value)}
              disabled={busy}
            />
          </Field>
          <Field label={FIELD_LABELS.notes}>
            <input
              className="ep-input"
              value={draft.notes ?? ''}
              onChange={(event) => set('notes', event.target.value)}
              disabled={busy}
            />
          </Field>
        </div>

        {serverError && (
          <p className="text-ep-sm text-error" data-testid="profile-form-server-error">
            {serverError}
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
            disabled={busy || issues.length > 0}
            data-testid="profile-form-submit"
          >
            {busy ? 'Saving…' : mode === 'edit' ? 'Save changes' : 'Create profile'}
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

function indexIssues(issues: ProfileIssue[]): Partial<Record<keyof UeProfileDraft, string>> {
  const map: Partial<Record<keyof UeProfileDraft, string>> = {};
  for (const issue of issues) {
    if (!map[issue.path]) map[issue.path] = issue.message;
  }
  return map;
}
