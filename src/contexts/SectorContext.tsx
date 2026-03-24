import { createContext, useContext, useCallback, useMemo, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';

interface SectorContextValue {
  /** Active sector slug, or null for "All Sectors" */
  sector: string | null;
  /** Set the active sector (null to clear) */
  setSector: (slug: string | null) => void;
  /** Spread into API params: { sector: slug } or {} */
  sectorParam: Record<string, string>;
}

const Ctx = createContext<SectorContextValue>({
  sector: null,
  setSector: () => {},
  sectorParam: {},
});

const EMPTY_PARAM: Record<string, string> = {};
const STORAGE_KEY = 'mitre-sector';

export function SectorProvider({ children }: { children: ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlSector = searchParams.get('sector') || null;

  // Derive sector: URL takes priority, sessionStorage as fallback
  // Use a useState initializer so sessionStorage is read only once on mount
  const [storedSector, setStoredSector] = useState<string | null>(() =>
    typeof window !== 'undefined' ? sessionStorage.getItem(STORAGE_KEY) : null
  );
  const sector = urlSector ?? storedSector;

  // Persist to sessionStorage when URL sector changes
  useEffect(() => {
    if (urlSector) {
      sessionStorage.setItem(STORAGE_KEY, urlSector);
    }
  }, [urlSector]);

  // Re-inject sector into URL when navigating to a page that lost it
  useEffect(() => {
    if (sector && !urlSector) {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('sector', sector);
        return next;
      }, { replace: true });
    }
  }, [sector, urlSector, setSearchParams]);

  const setSector = useCallback(
    (slug: string | null) => {
      if (slug) {
        sessionStorage.setItem(STORAGE_KEY, slug);
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
      setStoredSector(slug);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (slug) {
          next.set('sector', slug);
        } else {
          next.delete('sector');
        }
        return next;
      });
    },
    [setSearchParams],
  );

  const sectorParam = useMemo<Record<string, string>>(
    () => (sector ? { sector } : EMPTY_PARAM),
    [sector],
  );

  const value = useMemo(
    () => ({ sector, setSector, sectorParam }),
    [sector, setSector, sectorParam],
  );

  return (
    <Ctx.Provider value={value}>
      {children}
    </Ctx.Provider>
  );
}

export function useSector() {
  return useContext(Ctx);
}
