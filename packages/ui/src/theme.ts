// React-free theme helpers (storage + resolution). Each app wraps these in a
// hook using its local React copy so the shared folder stays dependency-free.

export type ThemePreference = 'light' | 'dark' | 'system';

export const THEME_STORAGE_KEY = 'telecom.theme';

export function readStoredPreference(): ThemePreference {
  if (typeof localStorage === 'undefined') return 'system';
  const value = localStorage.getItem(THEME_STORAGE_KEY) as ThemePreference | null;
  return value ?? 'system';
}

export function writeStoredPreference(preference: ThemePreference): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(THEME_STORAGE_KEY, preference);
}

export function resolveTheme(preference: ThemePreference): 'light' | 'dark' {
  if (preference !== 'system') return preference;
  if (typeof window === 'undefined') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches
    ? 'dark'
    : 'light';
}

export function applyTheme(theme: 'light' | 'dark'): void {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
}
