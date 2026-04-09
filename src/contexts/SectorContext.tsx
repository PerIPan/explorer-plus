'use client';
import { createContext, useContext, useCallback, useMemo, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';

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
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const urlSector = searchParams.get('sector') || null;

  // Track stored sector — initialized as null to match server, synced from sessionStorage on mount
  const [storedSector, setStoredSector] = useState<string | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    if (stored) setStoredSector(stored);
  }, []);
  const sector = urlSector ?? storedSector;

  // Persist to sessionStorage when URL sector changes
  useEffect(() => {
    if (urlSector) {
      sessionStorage.setItem(STORAGE_KEY, urlSector);
    }
  }, [urlSector]);

  // NOTE: "re-inject sector into URL" effect removed — handled by UrlSyncEffect
  // in providers.tsx to avoid race conditions with DomainContext

  const setSector = useCallback(
    (slug: string | null) => {
      if (slug) {
        sessionStorage.setItem(STORAGE_KEY, slug);
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
      setStoredSector(slug);

      const params = new URLSearchParams(searchParams.toString());
      if (slug) {
        params.set('sector', slug);
      } else {
        params.delete('sector');
      }
      const qs = params.toString();
      router.push(qs ? `${pathname}?${qs}` : pathname);
    },
    [searchParams, router, pathname],
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
