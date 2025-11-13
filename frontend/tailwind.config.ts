import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        background: '#0f1419',
        surface: '#1a1f2e',
        primary: '#3b82f6',
        secondary: '#8b5cf6',
        accent: '#f59e0b',
        critical: '#dc2626',
        high: '#f97316',
        medium: '#f59e0b',
        low: '#10b981',
        fixable: '#22c55e',
      },
    },
  },
  plugins: [],
} satisfies Config;
