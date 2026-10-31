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
        line: 'var(--c-border)',
        'text-primary': 'var(--c-text-primary)',
        'text-secondary': 'var(--c-text-secondary)',
        ink: 'var(--c-text-primary)',
        mute: 'var(--c-text-secondary)',
        primary: 'var(--c-primary)',
        brand: 'var(--c-primary)',
        'brand-soft': 'var(--c-primary-soft)',
        success: 'var(--c-success)',
        ok: 'var(--c-success)',
        'ok-soft': 'var(--c-success-soft)',
        warning: 'var(--c-warning)',
        warn: 'var(--c-warning)',
        'warn-soft': 'var(--c-warning-soft)',
        error: 'var(--c-error)',
        bad: 'var(--c-error)',
        'bad-soft': 'var(--c-error-soft)',
        vio: 'var(--c-violet)',
        'vio-soft': 'var(--c-violet-soft)',
        track: 'var(--c-track)',
      },
      boxShadow: {
        e1: 'var(--shadow-elev-1)',
        e2: 'var(--shadow-elev-2)',
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
