// 0.10.0 — Session expiry notice.
//
// Previously the shell silently downgraded the user to a viewer badge
// when /auth/me stopped reporting `authenticated:true`. Operators had no
// cue that their actions were being refused because the session dropped.
// This banner watches the auth query and surfaces an explicit notice as
// soon as a previously-authenticated session becomes unauthenticated or
// starts returning 401, with a direct "Reconnect" affordance that points
// back at the sign-in surface.

import { useEffect, useRef, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { ApiError } from '@shared/api';
import { useAuth } from '@/data/queries';

export function SessionExpiredBanner() {
  const auth = useAuth();
  const wasAuthenticated = useRef(false);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (auth.data?.authenticated) {
      wasAuthenticated.current = true;
      setVisible(false);
      return;
    }
    const expired =
      wasAuthenticated.current &&
      (auth.data?.authenticated === false ||
        (auth.error instanceof ApiError && auth.error.status === 401));
    if (expired) setVisible(true);
  }, [auth.data?.authenticated, auth.error]);

  if (!visible) return null;

  return (
    <div
      role="alert"
      aria-live="assertive"
      className="ep-card border-warning/40 bg-warning/5 px-4 py-2 mb-3 flex items-center justify-between gap-3"
      data-testid="session-expired-banner"
    >
      <div className="flex items-center gap-2 text-ep-sm">
        <AlertTriangle width={14} height={14} className="shrink-0 text-warning" aria-hidden="true" />
        <span>
          <strong>Session expirée</strong> — se reconnecter pour reprendre les actions opérateur.
        </span>
      </div>
      <div className="flex items-center gap-2">
        <a
          href="/polaris-api/v1/auth/login"
          className="ep-button ep-button-sm ep-button-primary"
          data-testid="session-expired-reconnect"
        >
          Se reconnecter
        </a>
        <button
          type="button"
          className="ep-button ep-button-sm"
          onClick={() => setVisible(false)}
          data-testid="session-expired-dismiss"
          aria-label="Dismiss"
        >
          Fermer
        </button>
      </div>
    </div>
  );
}
