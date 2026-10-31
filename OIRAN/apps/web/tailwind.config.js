/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx,html}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        // 2.4.0 mockup palette (Enterprise Precision + soft tones + violet
        // + track). Backed by CSS variables set in src/styles/index.css so
        // the dark theme and `prefers-color-scheme` fallback keep working.
        canvas: 'var(--c-background)',
        surface: 'var(--c-surface)',
        sidebar: 'var(--c-sidebar)',
        line: 'var(--c-border)',
        ink: 'var(--c-text-primary)',
        mute: 'var(--c-text-secondary)',
        brand: 'var(--c-primary)',
        'brand-soft': 'var(--c-primary-soft)',
        ok: 'var(--c-success)',
        'ok-soft': 'var(--c-success-soft)',
        warn: 'var(--c-warning)',
        'warn-soft': 'var(--c-warning-soft)',
        bad: 'var(--c-error)',
        'bad-soft': 'var(--c-error-soft)',
        vio: 'var(--c-violet)',
        'vio-soft': 'var(--c-violet-soft)',
        track: 'var(--c-track)',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"SF Mono"', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        xs2: ['11px', '1.4'],
        sm2: ['12px', '1.5'],
        base2: ['13px', '1.55'],
        md2: ['14px', '1.55'],
        xl2: ['18px', '1.4'],
        h2: ['22px', '1.3'],
        h1: ['26px', '1.25'],
      },
      boxShadow: {
        e1: 'var(--shadow-1)',
        e2: 'var(--shadow-2)',
      },
    },
  },
  plugins: [],
};
