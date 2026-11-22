import { useEffect, useRef } from 'react';

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel = 'Cancel',
  tone = 'primary',
  onConfirm,
  onCancel,
  busy,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: 'primary' | 'danger';
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
}) {
  const dialogRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
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
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        className="ep-card max-w-md w-full p-5 flex flex-col gap-3"
        data-testid="confirm-dialog"
      >
        <h2
          id="confirm-dialog-title"
          className="text-ep-lg font-semibold text-text-primary"
        >
          {title}
        </h2>
        <p className="text-ep-sm text-text-secondary">{description}</p>
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            className="ep-button ep-button-sm"
            onClick={onCancel}
            disabled={busy}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            className={`ep-button ep-button-sm ${
              tone === 'danger' ? 'ep-button-danger' : 'ep-button-primary'
            }`}
            onClick={onConfirm}
            disabled={busy}
            data-testid="confirm-dialog-confirm"
          >
            {busy ? 'Working…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
