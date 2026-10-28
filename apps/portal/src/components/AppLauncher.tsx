import { ExternalLink } from 'lucide-react';
import type { AppWithHealth } from '@/config/usePortalConfig';
import { StatusDot } from './StatusDot';

interface AppLauncherProps {
  app: AppWithHealth;
  loading: boolean;
}

const ACCENT_RING: Record<AppWithHealth['accent'], string> = {
  blue: 'bg-primary/10 text-primary ring-primary/20',
  purple: 'bg-[rgba(139,92,246,0.1)] text-[#7C3AED] ring-[rgba(139,92,246,0.25)] dark:text-[#A78BFA]',
  teal: 'bg-[rgba(13,148,136,0.08)] text-[#0F766E] ring-[rgba(13,148,136,0.25)] dark:text-[#2DD4BF]',
};

export function AppLauncher({ app, loading }: AppLauncherProps) {
  const { Icon } = app;
  const healthLabel = loading ? 'Checking service…' : app.health.detail;
  // Build the exact GET path probed by `probeHealth()` so the footer line
  // matches what the browser actually sends. An anonymous fetch (no token)
  // is enforced in usePortalConfig.
  const healthUrl = app.healthEndpoint
    ? `${app.healthEndpoint.base ?? app.apiBase}${app.healthEndpoint.path}`
    : null;

  return (
    <article
      className="ep-card p-5 flex flex-col gap-4 transition-transform hover:-translate-y-[1px]"
      data-testid={`app-card-${app.id}`}
    >
      <header className="flex items-start justify-between gap-3">
        <div
          className={`inline-flex items-center justify-center h-11 w-11 rounded-md ring-1 ${ACCENT_RING[app.accent]}`}
          aria-hidden="true"
        >
          <Icon width={20} height={20} />
        </div>
        <StatusDot state={app.health.state} />
      </header>
      <div className="flex-1 flex flex-col gap-2">
        <div>
          <p className="text-ep-xs font-medium uppercase tracking-wider text-text-secondary">
            {app.tagline}
          </p>
          <h2 className="text-ep-xl font-semibold text-text-primary mt-0.5">
            {app.name}
          </h2>
        </div>
        <p className="text-ep-sm text-text-secondary">{app.description}</p>
        <ul
          className="flex flex-wrap gap-1.5 mt-1"
          aria-label="Scope"
          data-testid={`app-scope-${app.id}`}
        >
          {app.scope.map((chip) => (
            <li key={chip}>
              <span className="ep-badge text-ep-xs text-text-secondary">{chip}</span>
            </li>
          ))}
        </ul>
      </div>
      <footer className="flex items-center justify-between gap-3 pt-1 border-t border-border">
        <span className="text-ep-xs text-text-secondary min-w-0 flex flex-col leading-tight">
          <span
            className="truncate"
            data-testid={`app-health-${app.id}`}
          >
            {healthLabel}
          </span>
          {healthUrl && (
            <span
              className="mono truncate opacity-80"
              data-testid={`app-health-route-${app.id}`}
            >
              GET {healthUrl}
            </span>
          )}
        </span>
        <a
          className="ep-button ep-button-primary h-9 px-3 text-ep-sm shrink-0"
          href={app.openUrl}
          target="_blank"
          rel="noopener noreferrer"
          data-testid={`app-open-${app.id}`}
        >
          Open application
          <ExternalLink width={14} height={14} aria-hidden="true" />
        </a>
      </footer>
    </article>
  );
}
