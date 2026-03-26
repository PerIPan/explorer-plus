import { useCallback } from 'react';
import { usePageTitle } from '../hooks/usePageTitle';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';

interface DetectionStrategy {
  detId: string;
  name: string;
  attackTechniqueId: string | null;
  analyticCount: number;
}

interface PaginatedResponse {
  data: DetectionStrategy[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

const columns: ColumnDef<DetectionStrategy>[] = [
  {
    key: 'detId',
    header: 'ID',
    tooltip: 'ATT&CK detection strategy identifier',
    width: '100px',
    render: (row) => (
      <a
        href={`https://attack.mitre.org/detectionstrategies/${row.detId}/`}
        target="_blank"
        rel="noopener noreferrer"
        className="font-mono text-xs text-[var(--accent-teal)] hover:underline"
      >
        {row.detId}
      </a>
    ),
  },
  {
    key: 'name',
    header: 'Name',
    tooltip: 'Detection strategy name',
    render: (row) => (
      <span className="text-xs text-[var(--text-primary)]">
        {row.name.replace(/^Detection Strategy for /, '')}
      </span>
    ),
  },
  {
    key: 'attackTechniqueId',
    header: 'Technique',
    tooltip: 'Primary ATT&CK technique this strategy detects',
    width: '120px',
    render: (row) =>
      row.attackTechniqueId ? (
        <EntityLink type="technique" attackId={row.attackTechniqueId} name={row.attackTechniqueId} useMap />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'analyticCount',
    header: 'Analytics',
    tooltip: 'Number of detection analytics in this strategy',
    width: '90px',
    align: 'center',
    render: (row) =>
      row.analyticCount > 0 ? (
        <Badge label={String(row.analyticCount)} variant="blue" />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
];

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

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.detId}
        emptyMessage="No detection strategies found. Run sync-detection-strategies.mjs to populate."
      />
    </div>
  );
}
