'use client';
import { createContext, useContext, useCallback, useMemo, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';

interface SectorContextValue {
  /** Active sector slug, or null for "All Sectors" */
  sector: string | null;
  /** Set the active sector (null to clear) */
  setSector: (slug: string | null) => void;
  /**
   * Update the cached sector (and its sessionStorage backing) WITHOUT
   * touching the router. For a caller that is about to issue its own single
   * `router.replace` covering multiple contexts at once (see
   * useProfileState.ts's `applyProfile`) — calling `setSector` there would
   * mean two `router.push`/`replace` calls racing from two render-time
   * closures (app/providers.tsx:10-45 documents why that's unsafe). Without
   * this, such a caller could update the URL directly but leave `storedSector`
   * stale, and `sector` (below) falls back to that stale cache whenever the
   * URL has no `?sector=` param.
   */
  syncStoredSector: (slug: string | null) => void;
  /** Spread into API params: { sector: slug } or {} */
  sectorParam: Record<string, string>;
}

const Ctx = createContext<SectorContextValue>({
  sector: null,
  setSector: () => {},
  syncStoredSector: () => {},
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

  // State-only counterpart to setSector: same sessionStorage write/remove,
  // no router call. Lets a caller that owns its own single router.replace
  // (useProfileState.ts's applyProfile) keep `storedSector` coherent with
  // what it just put in the URL/sessionStorage, instead of leaving this
  // context's cache stale until the next full mount.
  const syncStoredSector = useCallback((slug: string | null) => {
    try {
      if (slug) {
        sessionStorage.setItem(STORAGE_KEY, slug);
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
    } catch { /* private mode / storage disabled — cache below still updates for this session */ }
    setStoredSector(slug);
  }, []);

  const sectorParam = useMemo<Record<string, string>>(
    () => (sector ? { sector } : EMPTY_PARAM),
    [sector],
  );

  const value = useMemo(
    () => ({ sector, setSector, syncStoredSector, sectorParam }),
    [sector, setSector, syncStoredSector, sectorParam],
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
