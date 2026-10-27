// Shared cross-application API client.
//
// Authentication boundaries (see docs/contracts/AUTHENTICATION_BOUNDARIES.md):
// Each application owns its own authentication scope. The client NEVER
// attaches a token unless the caller explicitly names the scope that owns
// the token AND the request's base URL is one of the bases ALLOWLISTED
// for that scope. Same-origin alone is not enough — PR #2 final review:
// a same-origin request to a *different service* (e.g. /polaris-api/v1
// from the oiran scope) must never leak the OIRAN token.
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
 * storage key AND an immutable base allowlist.
 */
export type AuthScope = 'oiran' | 'polaris' | 'probe-manager';

const SCOPE_STORAGE_KEYS: Record<AuthScope, string> = {
  oiran: 'oiran.access_token',
  polaris: 'polaris.access_token',
  'probe-manager': 'probe-manager.access_token',
};

/**
 * Bases that each authentication scope is allowed to send its token to.
 * Normalized form (no trailing slash). A request's base must *start*
 * with an allowlisted base string for the token to be attached.
 *
 * The probe-manager app shares the OIRAN control-plane API, so both
 * scopes may target /api/v1. The POLARIS scope is strictly bound to the
 * POLARIS Control API.
 */
const SCOPE_BASE_ALLOWLIST: Record<AuthScope, readonly string[]> = {
  oiran: ['/api/v1'],
  'probe-manager': ['/api/v1'],
  polaris: ['/polaris-api/v1'],
};

/** @deprecated kept for backward compatibility with the first PR. */
export const AUTH_TOKEN_KEY = SCOPE_STORAGE_KEYS.oiran;

export function scopeStorageKey(scope: AuthScope): string {
  return SCOPE_STORAGE_KEYS[scope];
}

export function allowedBasesForScope(scope: AuthScope): readonly string[] {
  return SCOPE_BASE_ALLOWLIST[scope];
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
  /** Base URL. Defaults to `/api/v1` when unspecified. */
  base?: string;
  /**
   * Authentication scope that owns the request. The client only
   * attaches `Authorization: Bearer <token>` when ALL conditions hold:
   *   1. `authScope` is set.
   *   2. A token exists under `scopeStorageKey(authScope)`.
   *   3. The request's resolved base is same-origin (or relative).
   *   4. The resolved base's pathname begins with an allowlisted base
   *      for the scope (see `SCOPE_BASE_ALLOWLIST`).
   */
  authScope?: AuthScope | null;
}

/** Strip a trailing slash so comparisons are stable. */
function normalizeBase(base: string): string {
  return base.replace(/\/+$/, '');
}

function resolveBaseUrl(base: string): URL | null {
  // Relative bases are same-origin by construction. We synthesize a URL
  // from a fake origin so the pathname check still works in tests
  // running outside a browser.
  const origin =
    typeof window !== 'undefined'
      ? window.location.origin
      : 'http://local.invalid';
  try {
    return /^https?:/i.test(base) ? new URL(base) : new URL(base, origin);
  } catch {
    return null;
  }
}

function isSameOrigin(url: URL): boolean {
  if (typeof window === 'undefined') {
    // Tests without a window treat relative bases as same-origin.
    return url.origin === 'http://local.invalid';
  }
  return url.origin === window.location.origin;
}

/**
 * Decide whether `base` is authorized to carry a token issued under
 * `scope`. Separate from any network call so UI code can preflight the
 * decision (e.g. decide whether to render an authenticated download
 * button).
 */
export function isBaseAuthorizedForScope(
  base: string,
  scope: AuthScope,
): boolean {
  const resolved = resolveBaseUrl(base);
  if (!resolved) return false;
  if (!isSameOrigin(resolved)) return false;
  const allowlist = SCOPE_BASE_ALLOWLIST[scope];
  const normalizedPath = normalizeBase(resolved.pathname);
  return allowlist.some((candidate) => {
    const expected = normalizeBase(candidate);
    return normalizedPath === expected || normalizedPath.startsWith(`${expected}/`);
  });
}

/**
 * Attach `Authorization: Bearer <token>` to `headers` iff policy allows.
 * Returns the token actually attached (for test introspection) or null.
 */
export function applyAuthHeader(
  headers: Headers,
  scope: AuthScope | null | undefined,
  base: string,
): string | null {
  if (!scope) return null;
  const token = getAccessToken(scope);
  if (!token) return null;
  if (!isBaseAuthorizedForScope(base, scope)) return null;
  headers.set('Authorization', `Bearer ${token}`);
  return token;
}

export async function api<T>(
  path: string,
  options: ApiOptions = {},
): Promise<ApiEnvelope<T>> {
  const base = options.base ?? DEFAULT_BASE;
  const headers = new Headers(options.headers);
  applyAuthHeader(headers, options.authScope ?? null, base);
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

/**
 * Authenticated binary download. Issues a GET with the correct
 * `Authorization` header (never in the URL), buffers the response as a
 * Blob, and returns an object URL plus a `revoke()` function. UI
 * callers typically pass the URL to an anchor click + revoke on
 * completion to avoid leaking memory.
 *
 * Rejects with ApiError on non-2xx responses. Never attaches a token
 * when the scope is not allowlisted for the base.
 */
export interface AuthenticatedDownload {
  /** Blob object URL safe to assign to anchor.href. */
  objectUrl: string;
  /** Suggested filename extracted from Content-Disposition, if any. */
  filename: string | null;
  /** Content-Type returned by the backend. */
  mimeType: string;
  /** Revoke the object URL — call once the download has been triggered. */
  revoke: () => void;
}

export async function authenticatedDownload(
  path: string,
  options: ApiOptions = {},
): Promise<AuthenticatedDownload> {
  const base = options.base ?? DEFAULT_BASE;
  const headers = new Headers(options.headers);
  const attached = applyAuthHeader(headers, options.authScope ?? null, base);
  if (options.authScope && !attached) {
    throw new ApiError(
      401,
      'MISSING_OR_UNAUTHORIZED_TOKEN',
      'No authorized token available for this scope and base',
    );
  }
  const response = await fetch(`${base}${path}`, {
    ...options,
    method: options.method ?? 'GET',
    headers,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const err = (body as { error?: { code?: string; message?: string } } | null)?.error;
    throw new ApiError(
      response.status,
      err?.code ?? 'DOWNLOAD_FAILED',
      err?.message ?? response.statusText,
    );
  }
  const blob = await response.blob();
  const mimeType = response.headers.get('content-type') ?? 'application/octet-stream';
  const disposition = response.headers.get('content-disposition');
  const filename = parseFilename(disposition);
  const objectUrl = URL.createObjectURL(blob);
  return {
    objectUrl,
    filename,
    mimeType,
    revoke: () => URL.revokeObjectURL(objectUrl),
  };
}

function parseFilename(contentDisposition: string | null): string | null {
  if (!contentDisposition) return null;
  // RFC 5987 extended form: filename*=UTF-8''name
  const star = /filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/i.exec(contentDisposition);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim().replace(/^"|"$/g, ''));
    } catch {
      /* fall through */
    }
  }
  const simple = /filename\s*=\s*"?([^";]+)"?/i.exec(contentDisposition);
  return simple ? simple[1].trim() : null;
}
