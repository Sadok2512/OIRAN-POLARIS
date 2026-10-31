// 0.11.1 (#46) — "Autoriser le live" dialog.
//
// Flow:
//   * Operator clicks the header button → dialog opens.
//   * Pick one or more UEs (defaults to the current catalog's
//     configured UEs). The identity material (IMSI etc.) is not
//     touched here — only the opaque UE ids.
//   * Pick a duration (15 / 30 / 60 minutes). 60 is the server-side
//     cap enforced by `LIVE_GRANT_MAX_MINUTES`.
//   * Submit → POST /live/grant. The response adds a grant to the
//     list; the UeManager header countdown chip immediately picks
//     it up via useLiveGrants.
//
// Errors surface in plain French; the technical code is kept
// trailing so engineers can grep.

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Shield, X } from 'lucide-react';
import { ApiError } from '@shared/api';
import { useCreateLiveGrant } from '@/data/liveGrantApi';

const DURATION_PRESETS = [15, 30, 60] as const;

export interface LiveGrantDialogProps {
  open: boolean;
  availableUeIds: string[];
  defaultSelectedUeIds?: string[];
  onClose: () => void;
  onCreated?: (grantId: string) => void;
}

export function LiveGrantDialog({
  open,
  availableUeIds,
  defaultSelectedUeIds,
  onClose,
  onCreated,
}: LiveGrantDialogProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [duration, setDuration] = useState<number>(30);
  const [error, setError] = useState<string | null>(null);
  const create = useCreateLiveGrant();

  // Seed selection whenever the dialog opens. Priority:
  //   1. caller-supplied defaults (e.g. prefilled from a 423 click);
  //   2. the first UE id when the catalog is non-empty;
  //   3. empty (operator must pick something before Submit enables).
  useEffect(() => {
    if (!open) return;
    const seeds =
      defaultSelectedUeIds && defaultSelectedUeIds.length > 0
        ? defaultSelectedUeIds
        : availableUeIds.slice(0, 1);
    setSelected(new Set(seeds));
    setDuration(30);
    setError(null);
  }, [open, availableUeIds, defaultSelectedUeIds]);

  const canSubmit = useMemo(
    () => selected.size > 0 && !create.isPending,
    [selected.size, create.isPending],
  );

  if (!open) return null;

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    setError(null);
    try {
      const grant = await create.mutateAsync({
        ue_ids: Array.from(selected),
        duration_minutes: duration,
      });
      onCreated?.(grant.id);
      onClose();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(humaniseLiveGrantError(err));
      } else {
        setError((err as Error).message || 'Erreur inconnue.');
      }
    }
  }

  function toggle(ueId: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(ueId)) next.delete(ueId);
      else next.add(ueId);
      return next;
    });
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="live-grant-dialog-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4"
      data-testid="live-grant-dialog"
    >
      <form
        onSubmit={handleSubmit}
        className="ep-card w-full max-w-xl p-5 flex flex-col gap-3 my-4"
      >
        <header className="flex items-center justify-between">
          <h2
            id="live-grant-dialog-title"
            className="text-ep-lg font-semibold flex items-center gap-2"
          >
            <Shield width={16} height={16} aria-hidden="true" />
            Autoriser le live
          </h2>
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onClose}
            aria-label="Close"
            data-testid="live-grant-dialog-close"
          >
            <X width={13} height={13} />
          </button>
        </header>

        <p className="text-ep-xs text-text-secondary">
          Ouvre une fenêtre Live bornée sur les UE sélectionnées. Pendant
          la durée choisie, Start et Run n'exigeront plus l'autorisation
          par UE. Vous pouvez révoquer la fenêtre à tout moment.
        </p>

        <fieldset className="flex flex-col gap-1">
          <legend className="text-ep-xs uppercase tracking-wider text-text-secondary">
            Durée
          </legend>
          <div
            className="inline-flex rounded-md border border-border overflow-hidden"
            role="radiogroup"
            aria-label="Durée du grant"
            data-testid="live-grant-duration-group"
          >
            {DURATION_PRESETS.map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={duration === option}
                className={`ep-button ep-button-sm rounded-none border-0 ${
                  duration === option ? 'ep-button-primary' : ''
                }`}
                onClick={() => setDuration(option)}
                data-testid={`live-grant-duration-${option}`}
              >
                {option} min
              </button>
            ))}
          </div>
        </fieldset>

        <fieldset className="flex flex-col gap-1">
          <legend className="text-ep-xs uppercase tracking-wider text-text-secondary">
            UEs couverts ({selected.size} / {availableUeIds.length})
          </legend>
          {availableUeIds.length === 0 ? (
            <p className="text-ep-sm text-text-secondary">
              Aucun UE provisionné. Ajoute un UE depuis le gestionnaire
              avant d'ouvrir le live.
            </p>
          ) : (
            <div
              className="grid grid-cols-2 md:grid-cols-3 gap-1 max-h-64 overflow-y-auto border border-border rounded-md p-2"
              data-testid="live-grant-ue-list"
            >
              {availableUeIds.map((ueId) => {
                const checked = selected.has(ueId);
                return (
                  <label
                    key={ueId}
                    className="flex items-center gap-2 text-ep-sm mono"
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggle(ueId)}
                      data-testid={`live-grant-ue-${ueId}`}
                    />
                    {ueId}
                  </label>
                );
              })}
            </div>
          )}
        </fieldset>

        {error && (
          <p
            role="alert"
            className="text-ep-sm text-error flex items-start gap-1"
            data-testid="live-grant-error"
          >
            <AlertTriangle width={13} height={13} className="mt-0.5 shrink-0" />
            {error}
          </p>
        )}

        <footer className="flex items-center justify-end gap-2 pt-2 border-t border-border">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onClose}
            disabled={create.isPending}
          >
            Annuler
          </button>
          <button
            type="submit"
            className="ep-button ep-button-sm ep-button-primary"
            disabled={!canSubmit}
            data-testid="live-grant-submit"
          >
            {create.isPending ? 'Ouverture…' : 'Autoriser le live'}
          </button>
        </footer>
      </form>
    </div>
  );
}

/**
 * 0.11.1 — Plain-French mapping for the backend error codes the Grant
 * flow can produce. Keeps the technical code trailing for grep.
 */
export function humaniseLiveGrantError(error: ApiError): string {
  const code = error.code ?? 'LIVE_GRANT_ERROR';
  const headline = (() => {
    switch (code) {
      case 'LIVE_GRANT_UE_IDS_REQUIRED':
        return 'Sélectionne au moins un UE à couvrir.';
      case 'LIVE_GRANT_DURATION_INVALID':
        return 'Durée invalide (1 à 60 min).';
      case 'LIVE_GRANT_DUPLICATE_UE_IDS':
        return 'La liste d\'UE contient un doublon.';
      case 'OPERATOR_PERMISSION_REQUIRED':
        return 'Rôle operator requis pour ouvrir le live.';
      case 'LIVE_GRANT_STORE_UNAVAILABLE':
        return 'Le registre des grants est indisponible côté backend.';
      default:
        return error.message || 'Création du grant refusée.';
    }
  })();
  return `${headline} · ${code}`;
}
