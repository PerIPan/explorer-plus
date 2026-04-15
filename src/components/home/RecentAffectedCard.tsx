import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { formatDate } from '../../lib/formatDate';
import { Badge } from '../shared/Badge';

interface RecentAffected {
  days: number;
  applications: Array<{
    normalized: string;
    vendor: string;
    product: string;
    cveCount: number;
    latestPublished: string;
  }>;
  packages: Array<{
    ecosystem: string;
    packageName: string;
    advisoryCount: number;
    latestPublished: string;
  }>;
}

/**
 * Landing-page teaser showing two side-by-side columns:
 *   - Applications affected by CVEs in the last 10 days
 *   - Packages affected by GHSAs in the last 10 days
 * Silently hides when both lists are empty.
 */
export function RecentAffectedCard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['home-recent-affected', 10],
    queryFn: () => apiFetch<RecentAffected>('/home/recent-affected', { days: '10' }),
  });

  if (isLoading || error) return null;
  const apps = data?.applications ?? [];
  const pkgs = data?.packages ?? [];
  if (apps.length === 0 && pkgs.length === 0) return null;

  return (
    <section
      aria-label="Recently affected applications and packages"
      className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6 min-w-0"
    >
      {/* Applications */}
      {apps.length > 0 && (
        <div className="min-w-0">
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
              Affected Applications
              <span className="ml-2 font-normal normal-case tracking-normal text-[var(--text-secondary)]">
                — last 10 days
              </span>
            </h2>
            <Link
              href="/applications"
              className="text-xs text-[var(--accent-teal)] hover:underline shrink-0"
            >
              View all →
            </Link>
          </div>
          <div className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] divide-y divide-[var(--border-color)]">
            {apps.map((a) => (
              <Link
                key={a.normalized}
                href={`/?entity=${encodeURIComponent(a.normalized)}&tab=application-map`}
                className="flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--hover-subtle)] transition-colors min-w-0"
              >
                <span className="flex-1 min-w-0 text-xs text-[var(--text-primary)] truncate">
                  <span className="text-[var(--text-secondary)]">{a.vendor}</span>
                  <span className="mx-1 text-[var(--text-secondary)] opacity-60">/</span>
                  <span>{a.product}</span>
                </span>
                <Badge label={`${a.cveCount} CVE${a.cveCount === 1 ? '' : 's'}`} variant="pink" />
                <span className="text-[10px] text-[var(--text-secondary)] shrink-0 hidden sm:inline">
                  {formatDate(a.latestPublished)}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Packages */}
      {pkgs.length > 0 && (
        <div className="min-w-0">
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
              Affected Packages
              <span className="ml-2 font-normal normal-case tracking-normal text-[var(--text-secondary)]">
                — last 10 days
              </span>
            </h2>
            <Link
              href="/packages"
              className="text-xs text-[var(--accent-teal)] hover:underline shrink-0"
            >
              View all →
            </Link>
          </div>
          <div className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] divide-y divide-[var(--border-color)]">
            {pkgs.map((p) => (
              <Link
                key={`${p.ecosystem}/${p.packageName}`}
                href={`/packages/${p.ecosystem}/${encodeURIComponent(p.packageName)}`}
                className="flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--hover-subtle)] transition-colors min-w-0"
              >
                <Badge label={p.ecosystem} variant="blue" />
                <span className="flex-1 min-w-0 text-xs text-[var(--text-primary)] font-mono truncate">
                  {p.packageName}
                </span>
                <Badge
                  label={`${p.advisoryCount} GHSA${p.advisoryCount === 1 ? '' : 's'}`}
                  variant="pink"
                />
                <span className="text-[10px] text-[var(--text-secondary)] shrink-0 hidden sm:inline">
                  {formatDate(p.latestPublished)}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
