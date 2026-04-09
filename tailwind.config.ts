import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        dark: {
          deepest: '#0a0a1a',
          base: '#1a1a2e',
          card: '#16213e',
          border: '#2a2a4a',
        },
        text: {
          primary: '#ccd6f6',
          secondary: '#8892b0',
        },
        accent: {
          teal: '#64ffda',
          orange: '#f97316',
          purple: '#a78bfa',
          green: '#34d399',
          blue: '#60a5fa',
          pink: '#f472b6',
          yellow: '#fbbf24',
        },
      },
      fontFamily: {
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'sans-serif',
        ],
      },
    },
  },
  plugins: [],
};

export default config;
