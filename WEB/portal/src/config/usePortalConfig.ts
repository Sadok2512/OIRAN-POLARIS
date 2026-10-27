import { useQueries } from '@tanstack/react-query';
import { api, ApiError } from '@shared/api';
import { APPS, type AppDescriptor } from './apps';

export type AppHealth =
  | { state: 'ok'; latencyMs: number; detail?: string }
  | { state: 'degraded'; latencyMs: number; detail: string }
  | { state: 'unknown'; detail: string };

export type AppWithHealth = Omit<AppDescriptor, 'health'> & {
  healthEndpoint: AppDescriptor['health'];
  health: AppHealth;
};

async function probeHealth(app: AppDescriptor): Promise<AppHealth> {
  if (!app.health) return { state: 'unknown', detail: 'No health endpoint configured' };
  const started = performance.now();
  try {
    await api<unknown>(app.health.path, { base: app.health.base });
    return { state: 'ok', latencyMs: Math.round(performance.now() - started) };
  } catch (error) {
    const latencyMs = Math.round(performance.now() - started);
    if (error instanceof ApiError) {
      // Status 401/403 means the service is reachable but unauthenticated —
      // report it as reachable rather than as a hard failure.
      if (error.status === 401 || error.status === 403) {
        return {
          state: 'degraded',
          latencyMs,
          detail: `Reachable, authentication required (${error.status})`,
        };
      }
      return {
        state: 'degraded',
        latencyMs,
        detail: `HTTP ${error.status} ${error.code}`,
      };
    }
    return {
      state: 'unknown',
      detail: error instanceof Error ? error.message : 'Unreachable',
    };
  }
}

export function usePortalConfig() {
  const queries = useQueries({
    queries: APPS.map((app) => ({
      queryKey: ['app-health', app.id],
      queryFn: () => probeHealth(app),
      refetchInterval: 15_000,
      staleTime: 10_000,
    })),
  });

  const apps: AppWithHealth[] = APPS.map((app, index) => {
    const { health: healthEndpoint, ...rest } = app;
    return {
      ...rest,
      healthEndpoint,
      health: queries[index].data ?? { state: 'unknown', detail: 'Checking…' },
    };
  });

  return {
    apps,
    loading: queries.some((q) => q.isLoading),
    error: queries.find((q) => q.error)?.error as Error | undefined,
  };
}
