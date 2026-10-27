import { colors, spacing, typography } from '../../packages/ui/src/tokens.ts';

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{ts,tsx,html}',
    '../../packages/ui/src/**/*.{ts,tsx}',
  ],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        canvas: {
          light: colors.light.background,
          dark: colors.dark.background,
          DEFAULT: 'var(--c-background)',
        },
        surface: 'var(--c-surface)',
        sidebar: 'var(--c-sidebar)',
        border: 'var(--c-border)',
        'text-primary': 'var(--c-text-primary)',
        'text-secondary': 'var(--c-text-secondary)',
        primary: 'var(--c-primary)',
        success: 'var(--c-success)',
        warning: 'var(--c-warning)',
        error: 'var(--c-error)',
      },
      borderRadius: {
        sm: `${spacing.radius.sm}px`,
        md: `${spacing.radius.md}px`,
        lg: `${spacing.radius.lg}px`,
      },
      fontFamily: {
        sans: [typography.fontFamily],
        mono: [typography.fontFamilyMono],
      },
      fontSize: {
        'ep-xs': [`${typography.size.xs}px`, { lineHeight: '1.4' }],
        'ep-sm': [`${typography.size.sm}px`, { lineHeight: '1.5' }],
        'ep-base': [`${typography.size.base}px`, { lineHeight: '1.55' }],
        'ep-md': [`${typography.size.md}px`, { lineHeight: '1.55' }],
        'ep-lg': [`${typography.size.lg}px`, { lineHeight: '1.55' }],
        'ep-xl': [`${typography.size.xl}px`, { lineHeight: '1.4' }],
        'ep-h2': [`${typography.size.h2}px`, { lineHeight: '1.3' }],
        'ep-h1': [`${typography.size.h1}px`, { lineHeight: '1.25' }],
      },
      spacing: {
        control: `${spacing.controlHeight}px`,
      },
    },
  },
  plugins: [],
};
