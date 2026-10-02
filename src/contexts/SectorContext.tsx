'use client';
import { createContext, useContext, useCallback, useMemo, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';
import { resolveSector, ALL_SECTORS_PARAM } from '../lib/sector-scope.mjs';

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

/**
 * A link declaring that its list is deliberately NOT sector-scoped.
 *
 * Carrying the last sector across a link that omitted it is usually the helpful
 * thing to do, and that is what both this context and `UrlSyncEffect` do. It is
 * the wrong thing for a link whose number was computed without any sector
 * scope: the Threat Profile's evidence counts count every CVE on a technique,
 * and inheriting a sector made each one land on a strictly smaller list — 29
 * CVEs linking to a page headed "1-17 of 17" (see `EvidenceCount`).
 *
 * `?sector=` cannot express this. An empty value reads as absent here, so it
 * falls straight back to the stored sector, and it would be the one spelling
 * that silently depends on that. A named parameter says what it means, in the
 * URL, where someone sharing the link can see it.
 *
 * Re-exported so consumers have one import for the sector rule; the definition
 * and its tests live in src/lib/sector-scope.mjs.
 */
export { ALL_SECTORS_PARAM };

export function SectorProvider({ children }: { children: ReactNode }) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const urlSector = searchParams.get('sector') || null;
  // An explicit opt-out beats both the URL and the cache: a link that says
  // "no sector scope" is answering for the page it points at.
  const allSectors = searchParams.has(ALL_SECTORS_PARAM);

  // Track stored sector — initialized as null to match server, synced from sessionStorage on mount
  const [storedSector, setStoredSector] = useState<string | null>(null);

  useEffect(() => {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEY);
      if (stored) setStoredSector(stored);
    } catch { /* private mode / storage disabled — stay on the null default */ }
  }, []);
  const sector = resolveSector({ urlSector, storedSector, allSectors });

  // Persist to sessionStorage when URL sector changes
  useEffect(() => {
    if (urlSector) {
      try {
        sessionStorage.setItem(STORAGE_KEY, urlSector);
      } catch { /* private mode / storage disabled — sector still works from the URL this render */ }
    }
  }, [urlSector]);

  // NOTE: "re-inject sector into URL" effect removed — handled by UrlSyncEffect
  // in providers.tsx to avoid race conditions with DomainContext

  const setSector = useCallback(
    (slug: string | null) => {
      try {
        if (slug) {
          sessionStorage.setItem(STORAGE_KEY, slug);
        } else {
          sessionStorage.removeItem(STORAGE_KEY);
        }
      } catch { /* private mode / storage disabled — in-memory state below still updates */ }
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
