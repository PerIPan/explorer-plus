import { createContext, useContext, useCallback, useMemo, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';

export interface DomainOption {
  value: string;
  label: string;
  short: string;
}

const DOMAINS: DomainOption[] = [
  { value: 'enterprise-attack', label: 'Enterprise', short: 'Enterprise' },
  { value: 'mobile-attack',     label: 'Mobile',     short: 'Mobile'     },
  { value: 'ics-attack',        label: 'ICS',         short: 'ICS'        },
];

const DEFAULT_DOMAIN = 'enterprise-attack';
const STORAGE_KEY = 'mitre-domain';

interface DomainContextValue {
  /** Active domain slug — always set, never null */
  domain: string;
  /** Set the active domain */
  setDomain: (slug: string) => void;
  /** Spread into API params: { domain: 'enterprise-attack' } */
  domainParam: Record<string, string>;
  /** Static list of available domains */
  domains: DomainOption[];
}

const Ctx = createContext<DomainContextValue>({
  domain: DEFAULT_DOMAIN,
  setDomain: () => {},
  domainParam: { domain: DEFAULT_DOMAIN },
  domains: DOMAINS,
});

export function DomainProvider({ children }: { children: ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlDomain = searchParams.get('domain') ?? null;

  // Read sessionStorage only once on mount
  const [storedDomain] = useState<string | null>(() =>
    typeof window !== 'undefined' ? sessionStorage.getItem(STORAGE_KEY) : null
  );

  const domain = urlDomain ?? storedDomain ?? DEFAULT_DOMAIN;

  // Persist to sessionStorage when URL domain changes
  useEffect(() => {
    if (urlDomain) {
      sessionStorage.setItem(STORAGE_KEY, urlDomain);
    }
  }, [urlDomain]);

  // Re-inject domain into URL when navigating to a page that lost it
  useEffect(() => {
    if (domain !== DEFAULT_DOMAIN && !urlDomain) {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('domain', domain);
        return next;
      }, { replace: true });
    }
  }, [domain, urlDomain, setSearchParams]);

  const setDomain = useCallback(
    (slug: string) => {
      sessionStorage.setItem(STORAGE_KEY, slug);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (slug === DEFAULT_DOMAIN) {
          // Don't clutter the URL with the default value
          next.delete('domain');
        } else {
          next.set('domain', slug);
        }
        return next;
      });
    },
    [setSearchParams],
  );

  const domainParam = useMemo<Record<string, string>>(
    () => ({ domain }),
    [domain],
  );

  const value = useMemo(
    () => ({ domain, setDomain, domainParam, domains: DOMAINS }),
    [domain, setDomain, domainParam],
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
