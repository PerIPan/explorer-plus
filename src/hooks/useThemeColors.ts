import { useMemo } from 'react';
import { useTheme } from '../contexts/ThemeContext';

/** Resolved theme color values for JS/D3/chart usage (not Tailwind classes) */
export function useThemeColors() {
  const { theme } = useTheme();

  return useMemo(() => {
    const dark = theme === 'dark';
    return {
      surfaceDeep: dark ? '#0a0a1a' : '#f0f2f8',
      surfaceBase: dark ? '#1a1a2e' : '#e4e7f0',
      surfaceCard: dark ? '#16213e' : '#ffffff',
      borderColor: dark ? '#2a2a4a' : '#c9cfe0',
      textPrimary: dark ? '#ccd6f6' : '#1e2137',
      textSecondary: dark ? '#8892b0' : '#5a6380',
      accentTeal: dark ? '#64ffda' : '#0d9488',
      accentOrange: dark ? '#f97316' : '#ea580c',
      accentPurple: dark ? '#a78bfa' : '#7c3aed',
      accentBlue: dark ? '#60a5fa' : '#2563eb',
      accentGreen: dark ? '#34d399' : '#059669',
      accentPink: dark ? '#f472b6' : '#db2777',
      accentYellow: dark ? '#fbbf24' : '#b45309',
      accentNeutral: dark ? '#94a3b8' : '#64748b',
    };
  }, [theme]);
}
