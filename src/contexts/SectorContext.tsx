import { createContext, useContext, useCallback, useMemo, type ReactNode } from 'react';
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

export function SectorProvider({ children }: { children: ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const sector = searchParams.get('sector') || null;

  const setSector = useCallback(
    (slug: string | null) => {
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
