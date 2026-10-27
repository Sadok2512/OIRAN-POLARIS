// Shared cross-application API client.
//
// Authentication boundaries (see docs/contracts/AUTHENTICATION_BOUNDARIES.md):
// Each application owns its own authentication scope. The client NEVER
// attaches a token unless the caller explicitly names the scope that owns
// the token, and the scope matches the request's base. This prevents the
// OIRAN access token from being leaked to a Simulator Control (POLARIS)
// origin — the issue flagged by the PR #2 review.
import type { ApiEnvelope } from './types';

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

const DEFAULT_BASE =
  (typeof import.meta !== 'undefined' &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  '/api/v1';

/**
 * Known authentication scopes. Each application owns its own session
 * storage key; the shared client refuses to attach a token when the
 * request's scope does not match.
 */
export type AuthScope = 'oiran' | 'polaris' | 'probe-manager';

const SCOPE_STORAGE_KEYS: Record<AuthScope, string> = {
  oiran: 'oiran.access_token',
  polaris: 'polaris.access_token',
  'probe-manager': 'probe-manager.access_token',
};

/** @deprecated kept for backward compatibility with the first PR. Prefer `scopeStorageKey('oiran')`. */
export const AUTH_TOKEN_KEY = SCOPE_STORAGE_KEYS.oiran;

export function scopeStorageKey(scope: AuthScope): string {
  return SCOPE_STORAGE_KEYS[scope];
}

export function getAccessToken(scope: AuthScope = 'oiran'): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  return sessionStorage.getItem(scopeStorageKey(scope));
}

export function setAccessToken(scope: AuthScope, token: string | null): void {
  if (typeof sessionStorage === 'undefined') return;
  const key = scopeStorageKey(scope);
  if (token) sessionStorage.setItem(key, token);
  else sessionStorage.removeItem(key);
}

export function clearAllTokens(): void {
  if (typeof sessionStorage === 'undefined') return;
  for (const key of Object.values(SCOPE_STORAGE_KEYS)) {
    sessionStorage.removeItem(key);
  }
}

export interface ApiOptions extends RequestInit {
  /** Base URL. Default is the Vite proxy `/api/v1`. */
  base?: string;
  /**
   * Authentication scope that owns the request. The client only attaches
   * `Authorization: Bearer <token>` when `authScope` is set AND a token
   * exists under the matching scope key AND the base is same-origin or
   * relative. Omit (or set to `null`) to send an unauthenticated request.
   */
  authScope?: AuthScope | null;
}

function isSameOriginBase(base: string): boolean {
  // Relative paths and same-origin absolute URLs may carry a token.
  if (!/^https?:/i.test(base)) return true;
  if (typeof window === 'undefined') return false;
  try {
    const url = new URL(base);
    return url.origin === window.location.origin;
  } catch {
    return false;
  }
}

export async function api<T>(
  path: string,
  options: ApiOptions = {},
): Promise<ApiEnvelope<T>> {
  const base = options.base ?? DEFAULT_BASE;
  const headers = new Headers(options.headers);
  if (options.authScope) {
    const token = getAccessToken(options.authScope);
    if (token && isSameOriginBase(base)) {
      headers.set('Authorization', `Bearer ${token}`);
    }
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const response = await fetch(`${base}${path}`, { ...options, headers });
  const body = await response.json().catch(() => ({
    error: { code: 'INVALID_RESPONSE', message: 'Invalid API response' },
  }));
  if (!response.ok) {
    const err = (body as { error?: { code?: string; message?: string } }).error;
    throw new ApiError(
      response.status,
      err?.code ?? 'REQUEST_FAILED',
      err?.message ?? response.statusText,
    );
  }
  return body as ApiEnvelope<T>;
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

/** HTTP reachability + health classification used by the Portal and the
 * probe-manager Overview. Separates transport reachability from
 * application health per PR #2 review Section 3. */
export type HealthClass =
  | 'ok'
  | 'auth-required'
  | 'degraded'
  | 'unknown';

export function classifyHttpStatus(status: number): HealthClass {
  if (status === 401 || status === 403) return 'auth-required';
  if (status >= 500) return 'degraded';
  if (status >= 200 && status < 300) return 'ok';
  return 'degraded';
}
