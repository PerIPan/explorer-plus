'use client';

import { useState, Suspense, useEffect } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '../src/contexts/ThemeContext';
import { DomainProvider, DEFAULT_DOMAIN } from '../src/contexts/DomainContext';
import { SectorProvider } from '../src/contexts/SectorContext';
import { DiamondLoader } from '../src/components/shared/FoldingDiamond';
import { AppShell } from '../src/components/layout/AppShell';
import { Analytics } from '@vercel/analytics/react';

/**
 * Merged URL-sync effect for domain + sector.
 * Both contexts store their value in sessionStorage on change. On fresh
 * navigation (e.g. clicking a link that drops query params), this single
 * effect re-injects both values in one router.replace() call, preventing
 * the race condition that would occur with two separate router.push() calls.
 */
function UrlSyncEffect() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const params = new URLSearchParams(searchParams.toString());
    let changed = false;

    const storedDomain = sessionStorage.getItem('mitre-domain');
    if (storedDomain && storedDomain !== DEFAULT_DOMAIN && !params.has('domain')) {
      params.set('domain', storedDomain);
      changed = true;
    }

    const storedSector = sessionStorage.getItem('mitre-sector');
    if (storedSector && !params.has('sector')) {
      params.set('sector', storedSector);
      changed = true;
    }

    if (changed) {
      router.replace(`${pathname}?${params.toString()}`);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5 * 60 * 1000,
        gcTime: 30 * 60 * 1000,
        retry: 2,
      },
    },
  }));

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <Suspense fallback={<DiamondLoader text="Loading..." />}>
          <DomainProvider>
            <SectorProvider>
              <UrlSyncEffect />
              <AppShell>{children}</AppShell>
            </SectorProvider>
          </DomainProvider>
        </Suspense>
      </ThemeProvider>
      <Analytics />
    </QueryClientProvider>
  );
}
