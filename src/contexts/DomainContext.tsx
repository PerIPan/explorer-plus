'use client';
import { createContext, useContext, useCallback, useMemo, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';

export interface DomainOption {
  value: string;
  label: string;
  short: string;
}

const DOMAINS: DomainOption[] = [
  { value: 'enterprise-attack', label: 'Enterprise', short: 'Enterprise' },
  { value: 'mobile-attack',     label: 'Mobile',     short: 'Mobile'     },
  { value: 'ics-attack',        label: 'ICS',         short: 'ICS'        },
  { value: 'atlas-attack',      label: 'ATLAS',       short: 'ATLAS'      },
  { value: 'all',               label: 'All Domains', short: 'All'        },
];

export const DEFAULT_DOMAIN = 'enterprise-attack';
const STORAGE_KEY = 'mitre-domain';

interface DomainContextValue {
  /** Active domain slug — always set, never null */
  domain: string;
  /** Set the active domain */
  setDomain: (slug: string) => void;
  /**
   * Update the cached domain (and its sessionStorage backing) WITHOUT
   * touching the router. Mirrors SectorContext's `syncStoredSector` for the
   * same reason: a caller issuing its own single `router.replace` across
   * multiple contexts (useProfileState.ts's `applyProfile`) must not call
   * `setDomain`, which would push a second time from a stale closure — but
   * skipping it entirely would leave `storedDomain` stale, and `domain`
   * (below) falls back to that stale cache whenever the URL has no
   * `?domain=` param.
   */
  syncStoredDomain: (slug: string) => void;
  /** Spread into API params: { domain: 'enterprise-attack' } */
  domainParam: Record<string, string>;
  /** Static list of available domains */
  domains: DomainOption[];
}

const Ctx = createContext<DomainContextValue>({
  domain: DEFAULT_DOMAIN,
  setDomain: () => {},
  syncStoredDomain: () => {},
  domainParam: { domain: DEFAULT_DOMAIN },
  domains: DOMAINS,
});

export function DomainProvider({ children }: { children: ReactNode }) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const urlDomain = searchParams.get('domain') ?? null;

  // Track stored domain — initialized as null to match server, synced from sessionStorage on mount
  const [storedDomain, setStoredDomain] = useState<string | null>(null);

  useEffect(() => {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEY);
      if (stored) setStoredDomain(stored);
    } catch { /* private mode / storage disabled — stay on the DEFAULT_DOMAIN fallback below */ }
  }, []);

  const domain = urlDomain ?? storedDomain ?? DEFAULT_DOMAIN;

  // Persist to sessionStorage when URL domain changes
  useEffect(() => {
    if (urlDomain) {
      try {
        sessionStorage.setItem(STORAGE_KEY, urlDomain);
      } catch { /* private mode / storage disabled — domain still works from the URL this render */ }
      setStoredDomain(urlDomain);
    }
  }, [urlDomain]);

  // NOTE: "re-inject domain into URL" effect removed — handled by UrlSyncEffect
  // in providers.tsx to avoid race conditions with SectorContext

  const setDomain = useCallback(
    (slug: string) => {
      try {
        sessionStorage.setItem(STORAGE_KEY, slug);
      } catch { /* private mode / storage disabled — in-memory state below still updates */ }
      setStoredDomain(slug);

      const params = new URLSearchParams(searchParams.toString());
      if (slug === DEFAULT_DOMAIN) {
        // Don't clutter the URL with the default value
        params.delete('domain');
      } else {
        params.set('domain', slug);
      }
      const qs = params.toString();
      router.push(qs ? `${pathname}?${qs}` : pathname);
    },
    [searchParams, router, pathname],
  );

  // State-only counterpart to setDomain: same sessionStorage write, no
  // router call. setDomain always writes an explicit value (including the
  // default — see above), so this mirrors that unconditionally too.
  const syncStoredDomain = useCallback((slug: string) => {
    try {
      sessionStorage.setItem(STORAGE_KEY, slug);
    } catch { /* private mode / storage disabled — cache below still updates for this session */ }
    setStoredDomain(slug);
  }, []);

  const domainParam = useMemo<Record<string, string>>(
    () => (domain === 'all' ? {} as Record<string, string> : { domain }),
    [domain],
  );

  const value = useMemo(
    () => ({ domain, setDomain, syncStoredDomain, domainParam, domains: DOMAINS }),
    [domain, setDomain, syncStoredDomain, domainParam],
  );

  return (
    <Ctx.Provider value={value}>
      {children}
    </Ctx.Provider>
  );
}

export function useDomain() {
  return useContext(Ctx);
}
