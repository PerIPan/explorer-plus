import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';
import { Pagination } from '../components/shared/Pagination';

interface AtomicTest {
  id: string;
  name: string;
  test_number: number;
  description: string | null;
  platforms: string[] | null;
  executor_type: string | null;
  executor_command: string | null;
  cleanup_command: string | null;
  technique_attack_id: string | null;
  technique_name: string | null;
}

interface AtomicResponse {
  data: AtomicTest[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

const EXECUTOR_COLORS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink' | 'neutral'> = {
  powershell: 'blue',
  command_prompt: 'orange',
  sh: 'green',
  bash: 'green',
  manual: 'neutral',
};

const PLATFORMS = ['windows', 'linux', 'macos'];

export function AtomicTests() {

  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get('q') ?? '';
  const platform = searchParams.get('platform') ?? '';
  const page = parseInt(searchParams.get('page') ?? '1', 10) || 1;

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value); else next.delete(key);
        if (key !== 'page') next.set('page', '1');
        return next;
      });
    },
    [setSearchParams],
  );

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (q) params.q = q;
  if (platform) params.platform = platform;

  const { data, isLoading } = useQuery({
    queryKey: ['atomic-tests', params],
    queryFn: () => apiFetch<AtomicResponse>('/feed/atomic', params),
  });

  const tests = data?.data ?? [];
  const pagination = data?.pagination;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Atomic Red Team"
        subtitle="Validation tests mapped to ATT&CK techniques — run these to test your defenses"
        actions={
          <span className="text-sm text-[var(--text-secondary)]">
            {pagination?.total ?? '...'} tests
          </span>
        }
      />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search tests or technique IDs..."
          value={q}
          onChange={(e) => setParam('q', e.target.value)}
          className="min-w-[200px] px-3 py-2 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)] focus:ring-1 focus:ring-[var(--accent-teal)]"
        />
        <select
          value={platform}
          onChange={(e) => setParam('platform', e.target.value)}
          aria-label="Filter by platform"
          className="px-3 py-2 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)] focus:ring-1 focus:ring-[var(--accent-teal)]"
        >
          <option value="">All Platforms</option>
          {PLATFORMS.map((p) => (
            <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
          ))}
        </select>
      </div>

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="h-14 rounded-lg bg-[var(--border-color)] animate-pulse" />
          ))}
        </div>
      )}

      {!isLoading && tests.length === 0 && (
        <div className="text-center py-16 text-[var(--text-secondary)]">
          No tests found{q ? ` matching "${q}"` : ''}.
        </div>
      )}

      {!isLoading && tests.length > 0 && (
        <div className="space-y-1">
          {tests.map((test) => (
            <details
              key={test.id}
              className="group rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] overflow-hidden"
            >
              <summary className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-[var(--teal-ghost)] transition-colors">
                <svg className="w-3 h-3 text-[var(--text-secondary)] transition-transform group-open:rotate-90 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
                {test.technique_attack_id && (
                  <EntityLink
                    type="technique"
                    attackId={test.technique_attack_id}
                    name={test.technique_name ?? test.technique_attack_id}
                    useMap
                  />
                )}
                <span className="text-sm text-[var(--text-primary)] flex-1 truncate">{test.name}</span>
                {test.executor_type && (
                  <Badge label={test.executor_type} variant={EXECUTOR_COLORS[test.executor_type] ?? 'neutral'} />
                )}
                {test.platforms && test.platforms.map((p) => (
                  <span key={p} className="text-[9px] text-[var(--text-secondary)] px-1.5 py-0.5 rounded border border-[var(--border-color)] bg-[var(--surface-alt)] shrink-0">{p}</span>
                ))}
              </summary>
              <div className="px-4 pb-4 pt-2 border-t border-[var(--border-color)] space-y-3">
                {test.description && (
                  <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{test.description}</p>
                )}
                {test.executor_command && (
                  <div>
                    <h4 className="text-[10px] font-semibold text-[var(--accent-orange)] uppercase tracking-wider mb-1">Attack Command</h4>
                    <pre className="text-xs text-[var(--text-primary)] bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-md p-3 overflow-x-auto whitespace-pre-wrap font-mono">
                      {test.executor_command}
                    </pre>
                  </div>
                )}
                {test.cleanup_command && (
                  <div>
                    <h4 className="text-[10px] font-semibold text-[var(--accent-green)] uppercase tracking-wider mb-1">Cleanup Command</h4>
                    <pre className="text-xs text-[var(--text-primary)] bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-md p-3 overflow-x-auto whitespace-pre-wrap font-mono">
                      {test.cleanup_command}
                    </pre>
                  </div>
                )}
                {test.technique_attack_id && (
                  <a
                    href={`https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${test.technique_attack_id}/${test.technique_attack_id}.md`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-[var(--accent-teal)] hover:underline"
                  >
                    View on GitHub ↗
                  </a>
                )}
              </div>
            </details>
          ))}
        </div>
      )}

      {pagination && pagination.totalPages > 1 && (
        <Pagination
          page={pagination.page}
          limit={pagination.limit}
          total={pagination.total}
          totalPages={pagination.totalPages}
          onPageChange={(p) => setParam('page', String(p))}
        />
      )}
    </div>
  );
}
