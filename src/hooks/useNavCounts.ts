'use client';

import { useQuery } from '@tanstack/react-query';

/** The corpus sizes /api/v1/nav-counts returns. `cves`, `iocs` and `advisories` are estimates. */
export interface NavCounts {
  applications: number;
  icsAssets: number;
  ecosystems: number;
  packages: number;
  reports: number;
  frameworks: number;
  cves: number;
  iocs: number;
  advisories: number;
}

/**
 * Fetched ONCE for the whole shell and handed down, rather than called per nav
 * row: React Query would dedupe the requests, but not the twenty subscriptions
 * re-rendering every sidebar row whenever the entry settles.
 *
 * An hour of staleTime against an hour of CDN cache, so a session normally
 * costs one request. A failure is silent by design — `retry: false` and the
 * sidebar simply renders without numbers. A nav label is not worth a retry
 * storm, and it must never be worth an error state.
 */
export function useNavCounts() {
  const { data } = useQuery<NavCounts>({
    queryKey: ['nav-counts'],
    queryFn: async ({ signal }) => {
      const res = await fetch('/api/v1/nav-counts', { signal });
      if (!res.ok) throw new Error(`nav-counts: HTTP ${res.status}`);
      return (await res.json()).data as NavCounts;
    },
    staleTime: 60 * 60 * 1000,
    gcTime: 2 * 60 * 60 * 1000,
    retry: false,
  });
  return data;
}

/**
 * Sidebar-width formatting. Anything four digits or more is abbreviated, which
 * is also the honest presentation for the estimated fields — "110K" claims
 * exactly the precision the planner statistics can support, where "109,130"
 * would claim more than they can.
 */
export function formatCount(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${Math.round(n / 1000)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
