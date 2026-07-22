import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { formatDate } from '../../lib/formatDate';
import { Badge } from '../shared/Badge';
import { TechniquePopover } from '../shared/TechniquePopover';
import { isSafeUrl } from '../../lib/urlSafety';

interface Report {
  id: string;
  title: string;
  summary: string | null;
  url: string | null;
  source: string | null;
  published_at: string | null;
  technique_count: number;
}

// otx -> OTX, microsoft_security -> Microsoft Security
function sourceLabel(s: string | null): string {
  if (!s) return 'Report';
  if (s.toLowerCase() === 'otx') return 'OTX';
  return s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Landing-page teaser: the 4 latest CTI reports, full width above the
 * affected-applications / affected-packages columns. Each row shows source,
 * title + as much of the summary as fits on one line (truncated), and the
 * published date at the end. The whole row links to the source report.
 * Silently hides when there are no reports.
 */
export function RecentReportsCard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['home-recent-reports', 4],
    queryFn: () => apiFetch<{ data: Report[] }>('/feed/reports', { limit: '4' }),
  });

  if (isLoading || error) return null;
  const reports = data?.data ?? [];
  if (reports.length === 0) return null;

  return (
    <section aria-label="Latest CTI reports" className="min-w-0 mb-8 md:mb-10">
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
          Latest CTI Reports
        </h2>
        <Link href="/cti/reports" className="text-xs text-[var(--accent-teal)] hover:underline shrink-0">
          View all →
        </Link>
      </div>
      <div className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] divide-y divide-[var(--border-color)]">
        {reports.map((r) => {
          const titleContent = (
            <>
              <span className="font-medium text-[var(--text-primary)]">{r.title}</span>
              {r.summary && (
                <span className="text-[var(--text-secondary)]"> — {r.summary}</span>
              )}
            </>
          );
          const safeUrl = r.url && isSafeUrl(r.url) ? r.url : null;
          return (
            <div
              key={r.id}
              className="group flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--hover-subtle)] transition-colors min-w-0"
            >
              <Badge label={sourceLabel(r.source)} variant="neutral" />
              {safeUrl ? (
                <a
                  href={safeUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 min-w-0 truncate text-xs group-hover:underline"
                  title={r.summary ?? r.title}
                >
                  {titleContent}
                </a>
              ) : (
                <span className="flex-1 min-w-0 truncate text-xs" title={r.summary ?? r.title}>
                  {titleContent}
                </span>
              )}
              {/* technique-count bubble — before the date; click for the linked techniques */}
              {r.technique_count > 0 && (
                <TechniquePopover reportId={r.id} count={r.technique_count} />
              )}
              <span className="text-[10px] text-[var(--text-secondary)] shrink-0 tabular-nums">
                {formatDate(r.published_at)}
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
