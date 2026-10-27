// Shared OIRAN v1 API client. Mirrors OIRAN/apps/web/src/services/api.ts so
// the two new apps can be deployed independently without reaching into the
// existing OIRAN workspace.
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

export const AUTH_TOKEN_KEY = 'oiran.access_token';

export function getAccessToken(): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  return sessionStorage.getItem(AUTH_TOKEN_KEY);
}

export function setAccessToken(token: string | null): void {
  if (typeof sessionStorage === 'undefined') return;
  if (token) sessionStorage.setItem(AUTH_TOKEN_KEY, token);
  else sessionStorage.removeItem(AUTH_TOKEN_KEY);
}

export interface ApiOptions extends RequestInit {
  base?: string;
}

export async function api<T>(
  path: string,
  options: ApiOptions = {},
): Promise<ApiEnvelope<T>> {
  const base = options.base ?? DEFAULT_BASE;
  const headers = new Headers(options.headers);
  const token = getAccessToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
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
