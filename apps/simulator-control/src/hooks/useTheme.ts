import { useEffect, useState } from 'react';
import {
  applyTheme,
  readStoredPreference,
  resolveTheme,
  writeStoredPreference,
  type ThemePreference,
} from '@shared/theme';

export function useTheme() {
  const [preference, setPreference] =
    useState<ThemePreference>(readStoredPreference);

  useEffect(() => {
    writeStoredPreference(preference);
    applyTheme(resolveTheme(preference));
    if (preference !== 'system') return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const listener = () => applyTheme(resolveTheme('system'));
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, [preference]);

  return {
    preference,
    setPreference,
    resolved: resolveTheme(preference),
  };
}
