import { useCallback } from 'react';
import { usePageTitle } from '../hooks/usePageTitle';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

interface Analytic {
  analyticId: string;
  name: string;
  description: string | null;
  platforms: string[];
}

interface DetectionStrategy {
  detId: string;
  name: string;
  attackTechniqueId: string | null;
  analytics: Analytic[];
}

interface PaginatedResponse {
  data: DetectionStrategy[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

export function DetectionStrategies() {
  usePageTitle('Detection Strategies');

  const [searchParams, setSearchParams] = useSearchParams();
  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const search = searchParams.get('search') ?? '';
  const technique = searchParams.get('technique') ?? '';

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) {
          next.set(key, value);
        } else {
          next.delete(key);
        }
        if (key !== 'page') next.set('page', '1');
        return next;
      });
    },
    [setSearchParams],
  );

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.search = search;
  if (technique) params.technique = technique;

  const { data, isLoading } = useQuery({
    queryKey: ['detection-strategies', params],
    queryFn: () => apiFetch<PaginatedResponse>('/frameworks/detection', params),
  });

  const strategies = data?.data ?? [];
  const pagination = data?.pagination;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Detection Strategies"
        subtitle="ATT&CK v18 detection strategies and analytics — platform-specific detection guidance"
      />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search strategies..."
          value={search}
          onChange={(e) => setParam('search', e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        {technique && (
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-[var(--text-secondary)]">Technique:</span>
            <Badge label={technique} variant="teal" />
            <button
              type="button"
              onClick={() => setParam('technique', '')}
              className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xs"
            >
              clear
            </button>
          </div>
        )}
      </div>

      {/* Loading */}
      {isLoading && (
        <DiamondLoader text="Loading..." />
      )}

      {/* Strategies list */}
      {!isLoading && strategies.length > 0 && (
        <div className="space-y-2">
          {strategies.map((ds) => (
            <details key={ds.detId} className="group rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] overflow-hidden">
              <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-[var(--teal-ghost)] transition-colors">
                <svg
                  className="w-3 h-3 text-[var(--text-secondary)] transition-transform group-open:rotate-90 shrink-0"
                  fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
                <a
                  href={`https://attack.mitre.org/detectionstrategies/${ds.detId}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="font-mono text-xs text-[var(--accent-teal)] hover:underline shrink-0"
                >
                  {ds.detId}
                </a>
                <span className="text-sm text-[var(--text-primary)] flex-1 truncate">
                  {ds.name.replace(/^Detection Strategy for /, '')}
                </span>
                {ds.attackTechniqueId && (
                  <span className="font-mono text-[10px] text-[var(--accent-blue)] shrink-0">{ds.attackTechniqueId}</span>
                )}
                {ds.analytics.length > 0 && (
                  <Badge label={`${ds.analytics.length} analytics`} variant="blue" />
                )}
              </summary>
              {ds.analytics.length > 0 && (
                <div className="px-4 pb-3 pt-1 border-t border-[var(--border-color)] space-y-2">
                  {ds.analytics.map((an) => (
                    <div key={an.analyticId} className="py-2 px-3 rounded-md bg-[var(--surface-alt)] border border-[var(--border-color)]">
                      <div className="flex items-center gap-2 mb-1">
                        <a
                          href={`https://attack.mitre.org/detectionstrategies/${ds.detId}/#${an.analyticId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-[10px] text-[var(--accent-blue)] hover:underline shrink-0"
                        >
                          {an.analyticId}
                        </a>
                        <span className="text-xs text-[var(--text-primary)] font-medium">{an.name}</span>
                        {an.platforms?.map((p) => (
                          <Badge key={p} label={p} variant="neutral" />
                        ))}
                      </div>
                      {an.description && (
                        <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed line-clamp-3">
                          {an.description}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </details>
          ))}
        </div>
      )}

      {/* Empty */}
      {!isLoading && strategies.length === 0 && (
        <p className="text-sm text-[var(--text-secondary)] text-center py-8">
          No detection strategies found. Run sync-detection-strategies.mjs to populate.
        </p>
      )}

      {/* Pagination */}
      {pagination && pagination.totalPages > 1 && (
        <div className="flex items-center justify-between text-xs text-[var(--text-secondary)]">
          <span>{(page - 1) * pagination.limit + 1}–{Math.min(page * pagination.limit, pagination.total)} of {pagination.total}</span>
          <div className="flex gap-1">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setParam('page', String(page - 1))}
              className="px-2.5 py-1.5 rounded-md border border-[var(--border-color)] disabled:opacity-40 hover:border-[var(--teal-dim)] transition-colors"
            >
              Prev
            </button>
            <button
              type="button"
              disabled={page >= pagination.totalPages}
              onClick={() => setParam('page', String(page + 1))}
              className="px-2.5 py-1.5 rounded-md border border-[var(--border-color)] disabled:opacity-40 hover:border-[var(--teal-dim)] transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
