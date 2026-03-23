import { createContext, useContext, useCallback, useMemo, useRef, useEffect, type ReactNode } from 'react';
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

  // Persist sector in sessionStorage so it survives navigation
  const sectorRef = useRef<string | null>(
    urlSector ?? sessionStorage.getItem(STORAGE_KEY),
  );

  // Sync ref when URL has sector
  if (urlSector) {
    sectorRef.current = urlSector;
  }

  const sector = sectorRef.current;

  // Persist to sessionStorage and re-inject into URL on navigation
  useEffect(() => {
    if (urlSector) {
      sessionStorage.setItem(STORAGE_KEY, urlSector);
    }
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
      sectorRef.current = slug;
      if (slug) {
        sessionStorage.setItem(STORAGE_KEY, slug);
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
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
