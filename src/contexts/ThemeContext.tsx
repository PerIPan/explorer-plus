'use client';
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';

type Theme = 'light' | 'dark';

interface ThemeContextValue {
  theme: Theme;
  toggle: () => void;
}

/**
 * Not 'theme'. The old implementation wrote that key on every mount, whether
 * or not anyone touched the toggle, so the stored values record the old dark
 * default rather than a preference anybody expressed. Reading them would pin
 * every returning visitor to dark for good and make this default meaningless.
 * The new key is written only by toggle(), so it always means a real choice.
 */
const STORAGE_KEY = 'mx-theme';

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'light',
  toggle: () => {},
});

export function useTheme() {
  return useContext(ThemeContext);
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>('light');

  // Sync from localStorage on mount (SSR-safe — layout.tsx blocking script
  // already sets the CSS class, so there's no flash). Light is the default;
  // only an explicit stored preference overrides it.
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
      if (stored === 'light' || stored === 'dark') {
        setTheme(stored);
      }
    } catch { /* private mode / storage disabled — stay on the default */ }
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark');
    root.classList.toggle('light', theme === 'light');
  }, [theme]);

  // Persist here rather than in the effect above: writing on every mount is
  // what turned the previous default into a sticky preference nobody chose.
  const toggle = useCallback(() => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem(STORAGE_KEY, next); } catch { /* ignore */ }
    setTheme(next);
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}
