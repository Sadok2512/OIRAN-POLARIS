import { AlertTriangle, Inbox, Loader2 } from 'lucide-react';

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div
      className="ep-card p-8 flex flex-col items-center text-center gap-2"
      data-testid="empty-state"
    >
      <Inbox className="text-text-secondary" width={28} height={28} aria-hidden="true" />
      <p className="text-ep-md font-medium text-text-primary">{title}</p>
      {description && (
        <p className="text-ep-sm text-text-secondary max-w-md">{description}</p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorState({
  title,
  detail,
  onRetry,
}: {
  title: string;
  detail?: string;
  onRetry?: () => void;
}) {
  return (
    <div
      className="ep-card border-error/30 p-6 flex flex-col gap-2"
      data-testid="error-state"
    >
      <div className="flex items-center gap-2">
        <AlertTriangle className="text-error" width={16} height={16} aria-hidden="true" />
        <p className="text-ep-md font-semibold text-error">{title}</p>
      </div>
      {detail && (
        <p className="text-ep-sm text-text-secondary break-words">{detail}</p>
      )}
      {onRetry && (
        <button type="button" className="ep-button ep-button-sm self-start" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function LoadingSkeleton({ label = 'Loading' }: { label?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-2 text-ep-sm text-text-secondary"
      data-testid="loading-state"
    >
      <Loader2 className="animate-spin" width={14} height={14} aria-hidden="true" />
      <span>{label}…</span>
    </div>
  );
}

export function Unavailable({ reason }: { reason: string }) {
  return (
    <div
      className="ep-card border-warning/30 p-4 flex items-start gap-3"
      data-testid="unavailable-state"
    >
      <AlertTriangle className="text-warning mt-0.5" width={16} height={16} aria-hidden="true" />
      <div className="text-ep-sm">
        <p className="font-medium text-text-primary">Unavailable</p>
        <p className="text-text-secondary">{reason}</p>
      </div>
    </div>
  );
}
