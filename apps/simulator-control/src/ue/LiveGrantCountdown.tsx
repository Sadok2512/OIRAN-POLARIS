// 0.11.1 (#46) — Countdown chip rendered in the UE Manager header
// while at least one grant is active. Updates once per second so the
// MM:SS counter ticks live; refetches `/live/grant` every 10 s via
// the react-query hook so a revocation elsewhere is picked up.

import { useEffect, useState } from 'react';
import { Clock, ShieldOff } from 'lucide-react';
import {
  formatCountdown,
  pickDisplayGrant,
  useLiveGrants,
  useRevokeLiveGrant,
  type LiveGrant,
  type LiveGrantList,
} from '@/data/liveGrantApi';

export interface LiveGrantCountdownProps {
  /** When true, the Revoke button is enabled (operator role). */
  canRevoke: boolean;
}

export function LiveGrantCountdown({ canRevoke }: LiveGrantCountdownProps) {
  const grants = useLiveGrants();
  const revoke = useRevokeLiveGrant();
  const now = useLiveClock();

  const display = pickDisplayGrant(grants.data as LiveGrantList | undefined);

  if (grants.isLoading || !display) return null;

  const remaining = Math.max(0, display.expires_at_epoch_ms - now);
  const expired = remaining === 0;
  return (
    <div
      className="inline-flex items-center gap-2 ep-badge border-success/40 text-success"
      data-testid="live-grant-countdown"
      data-grant-id={display.id}
    >
      <Clock width={13} height={13} aria-hidden="true" />
      <span>Live ouvert · {display.ue_ids.length} UE</span>
      <span className="mono" data-testid="live-grant-countdown-timer">
        {formatCountdown(display.expires_at_epoch_ms, now)}
      </span>
      {canRevoke && !expired && (
        <button
          type="button"
          className="ep-button ep-button-sm ep-button-danger"
          onClick={() => void revoke.mutateAsync(display.id)}
          disabled={revoke.isPending}
          data-testid="live-grant-revoke"
          title={`Révoquer le grant ${display.id}`}
        >
          <ShieldOff width={13} height={13} aria-hidden="true" />
          <span className="ml-1">Révoquer</span>
        </button>
      )}
    </div>
  );
}

/**
 * Returns `Date.now()` updated once per second. The hook is a thin
 * wrapper around `useState + setInterval` so the countdown chip and
 * any sparkline can share a single ticking clock when they live on
 * the same page.
 */
export function useLiveClock(): number {
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    const handle = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(handle);
  }, []);
  return now;
}

export function describeGrant(grant: LiveGrant): string {
  return `grant ${grant.id} · ${grant.ue_ids.length} UE · ${grant.duration_minutes} min`;
}
