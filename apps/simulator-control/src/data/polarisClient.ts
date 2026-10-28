// Single POLARIS HTTP client shared by every simulator data module.
//
// POLARIS Control (Rust/axum) answers with RAW JSON bodies — e.g.
// `{"items":[...],"total":1}` — and errors as `{"error":"CODE"}`. It does
// NOT use the OIRAN `{data, meta}` envelope. Reading `envelope.data` on a
// raw body silently yields `undefined`, which is what every POLARIS query
// did before this module. `unwrapPolarisBody` accepts both shapes so the
// existing `{data, meta}` test fixtures keep working while production
// reads the real raw body.

import { api, type ApiOptions } from '@shared/api';

const CSRF_KEY = 'polaris.csrf_token';

export function readCsrf(): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  return sessionStorage.getItem(CSRF_KEY);
}

export function writeCsrf(value: string | null): void {
  if (typeof sessionStorage === 'undefined') return;
  if (value) sessionStorage.setItem(CSRF_KEY, value);
  else sessionStorage.removeItem(CSRF_KEY);
}

export const POLARIS_SCOPE: ApiOptions = {
  authScope: 'polaris',
  base: '/polaris-api/v1',
};

function isOiranEnvelope(body: unknown): body is { data: unknown; meta: unknown } {
  return (
    typeof body === 'object' &&
    body !== null &&
    !Array.isArray(body) &&
    'data' in body &&
    'meta' in body &&
    Object.keys(body).length === 2
  );
}

export function unwrapPolarisBody<T>(body: unknown): T {
  return (isOiranEnvelope(body) ? body.data : body) as T;
}

export async function polarisApi<T>(
  path: string,
  extra: Omit<ApiOptions, 'authScope' | 'base'> = {},
): Promise<T> {
  const method = (extra.method ?? 'GET').toUpperCase();
  const headers = new Headers(extra.headers);
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = readCsrf();
    if (csrf) headers.set('x-csrf-token', csrf);
  }
  const body = await api<T>(path, { ...POLARIS_SCOPE, ...extra, headers });
  return unwrapPolarisBody<T>(body);
}
