import Link from 'next/link';
import { useCves } from '../../hooks/useApi';
import { formatDate } from '../../lib/formatDate';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

function daysAgoISO(days: number): string {
  return new Date(Date.now() - days * 86400000).toISOString().split('T')[0];
}

/**
 * Landing-page CVE teaser.
 * Shows up to 7 recent CVEs (last 3 days) sorted by CVSS desc.
 * Rendered only when no entity is selected; silently hides on empty/error.
 */
export function RecentCvesCard() {
  const since = daysAgoISO(3);
  const { data, isLoading, error } = useCves({ limit: '7', since });

  if (isLoading || error) return null;
  const rows = data?.data ?? [];
  if (rows.length === 0) return null;

  return (
    <section
      aria-label="Recent vulnerabilities from the last 3 days"
      className="min-w-0"
    >
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
          Recent Vulnerabilities
          <span className="ml-2 font-normal text-[var(--text-secondary)] normal-case tracking-normal">
            — last 3 days
          </span>
        </h2>
        <Link
          href="/cti/cves"
          className="text-xs text-[var(--accent-teal)] hover:underline shrink-0"
        >
          View all →
        </Link>
      </div>

      <div className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] divide-y divide-[var(--border-color)]">
        {rows.map((cve) => {
          const severityClass =
            cve.cvssSeverity && SEVERITY_COLORS[cve.cvssSeverity]
              ? SEVERITY_COLORS[cve.cvssSeverity]
              : 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
          const isKev = cve.sources?.includes('cisa_kev');
          return (
            <Link
              key={cve.cveId}
              href={`/cti/cves/${cve.cveId}`}
              className="flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--hover-subtle)] transition-colors min-w-0"
            >
              <span className="font-mono text-xs text-[var(--accent-teal)] w-32 shrink-0">
                {cve.cveId}
              </span>
              {cve.cvssSeverity ? (
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border shrink-0 ${severityClass}`}
                  title={cve.cvssScore != null ? `CVSS ${cve.cvssScore.toFixed(1)}` : undefined}
                >
                  {cve.cvssSeverity}
                </span>
              ) : (
                <span className="text-[10px] text-[var(--text-secondary)] w-[70px] shrink-0">—</span>
              )}
              {cve.cvssScore != null && (
                <span className="font-mono text-[10px] text-[var(--text-secondary)] w-10 shrink-0">
                  {cve.cvssScore.toFixed(1)}
                </span>
              )}
              {isKev && (
                <span className="inline-flex items-center px-1.5 py-px rounded-full text-[10px] font-medium border bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)] shrink-0">
                  KEV
                </span>
              )}
              <span className="flex-1 min-w-0 text-xs text-[var(--text-secondary)] truncate leading-relaxed">
                {cve.description ?? '—'}
              </span>
              {cve.publishedAt && (
                <span className="text-[10px] text-[var(--text-secondary)] shrink-0 hidden sm:inline">
                  {formatDate(cve.publishedAt)}
                </span>
              )}
            </Link>
          );
        })}
      </div>
    </section>
  );
}
