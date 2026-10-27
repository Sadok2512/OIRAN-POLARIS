// Enterprise Precision design tokens.
// These values are the single source of truth for both the Portal and the
// Probe Manager applications. Tailwind configs import this file and expose
// the same tokens as CSS variables and theme values.

export const colors = {
  light: {
    background: '#F5F7FA',
    surface: '#FFFFFF',
    sidebar: '#F0F4F9',
    textPrimary: '#17283F',
    textSecondary: '#66758B',
    border: '#DEE5ED',
    primary: '#2563EB',
    success: '#059669',
    warning: '#D97706',
    error: '#DC2626',
  },
  dark: {
    background: '#0B1220',
    surface: '#152238',
    sidebar: '#101B2C',
    textPrimary: '#E7F0FF',
    textSecondary: '#94A3B8',
    border: '#30415C',
    primary: '#3B82F6',
    success: '#10B981',
    warning: '#F59E0B',
    error: '#EF4444',
  },
} as const;

export type ColorScheme = keyof typeof colors;

export const spacing = {
  base: 4,
  controlHeight: 40,
  radius: {
    sm: 6,
    md: 8,
    lg: 12,
  },
} as const;

export const typography = {
  fontFamily:
    'Inter, "Geist", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  fontFamilyMono:
    '"JetBrains Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
  size: {
    xs: 11,
    sm: 12,
    base: 13,
    md: 14,
    lg: 15,
    xl: 18,
    h2: 22,
    h1: 26,
  },
  weight: {
    normal: 400,
    medium: 500,
    semibold: 600,
    bold: 700,
  },
} as const;
