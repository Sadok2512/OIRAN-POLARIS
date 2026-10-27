import { useQueries } from '@tanstack/react-query';
import { ApiError, classifyHttpStatus } from '@shared/api';
import { APPS, type AppDescriptor } from './apps';

/**
 * Portal health classification — strict separation between HTTP transport
 * reachability and *application* health. Per PR #2 review Section 3:
 *   - 2xx must still be interpreted from the response body
 *   - 401/403 means reachable but authentication is required/denied
 *   - 5xx means degraded / unhealthy
 *   - Network error means unavailable/unknown
 */
export type AppHealth =
  | {
      state: 'ok';
      latencyMs: number;
      httpStatus: number;
      appStatus?: string;
      detail: string;
    }
  | {
      state: 'auth-required';
      latencyMs: number;
      httpStatus: number;
      detail: string;
    }
  | {
      state: 'degraded';
      latencyMs: number;
      httpStatus: number;
      appStatus?: string;
      detail: string;
    }
  | { state: 'unknown'; detail: string };

export type AppWithHealth = Omit<AppDescriptor, 'health'> & {
  healthEndpoint: AppDescriptor['health'];
  health: AppHealth;
};

/** Parse a health response body and extract its advertised status, if any. */
function extractAppStatus(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const candidate =
    (body as Record<string, unknown>).status ??
    (body as Record<string, { status?: unknown } | undefined>).data?.status;
  return typeof candidate === 'string' ? candidate : undefined;
}

function isPositiveHealthWord(value: string | undefined): boolean {
  if (!value) return false;
  return ['ok', 'healthy', 'up', 'ready', 'running'].includes(
    value.toLowerCase(),
  );
}

async function probeHealth(app: AppDescriptor): Promise<AppHealth> {
  if (!app.health) {
    return { state: 'unknown', detail: 'No health endpoint configured' };
  }
  const base = app.health.base ?? app.apiBase;
  const url = `${base}${app.health.path}`;
  const started = performance.now();
  try {
    // Explicitly NO Authorization header: the portal must never send
    // another app's token to a sibling origin. We bypass the shared
    // `api()` helper here so the request is guaranteed to be anonymous.
    const response = await fetch(url, {
      method: 'GET',
      credentials: 'omit',
    });
    const latencyMs = Math.round(performance.now() - started);
    const httpClass = classifyHttpStatus(response.status);

    if (httpClass === 'auth-required') {
      return {
        state: 'auth-required',
        latencyMs,
        httpStatus: response.status,
        detail: `Reachable, authentication required (${response.status})`,
      };
    }

    if (httpClass === 'degraded') {
      return {
        state: 'degraded',
        latencyMs,
        httpStatus: response.status,
        detail: `HTTP ${response.status}`,
      };
    }

    // 2xx: interpret the body before claiming "ok".
    const body = await response.json().catch(() => null);
    const appStatus = extractAppStatus(body);
    if (appStatus === undefined) {
      return {
        state: 'ok',
        latencyMs,
        httpStatus: response.status,
        detail: `Reachable · ${latencyMs} ms (no status field in body)`,
      };
    }
    if (isPositiveHealthWord(appStatus)) {
      return {
        state: 'ok',
        latencyMs,
        httpStatus: response.status,
        appStatus,
        detail: `${appStatus} · ${latencyMs} ms`,
      };
    }
    return {
      state: 'degraded',
      latencyMs,
      httpStatus: response.status,
      appStatus,
      detail: `Backend reports status "${appStatus}"`,
    };
  } catch (error) {
    const latencyMs = Math.round(performance.now() - started);
    if (error instanceof ApiError) {
      return {
        state: 'degraded',
        latencyMs,
        httpStatus: error.status,
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
