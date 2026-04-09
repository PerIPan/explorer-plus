'use client';
import { useCallback } from 'react';
import { useSearchParams } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useSigmaRules } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import type { SigmaRule } from '../lib/types';
import { sigmaRuleUrl } from '../lib/urlSafety';


const LEVEL_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'green' | 'neutral'> = {
  critical: 'pink',
  high: 'orange',
  medium: 'yellow',
  low: 'blue',
  informational: 'green',
};

function LevelBadge({ level }: { level: string | null }) {
  if (!level) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  return <Badge label={level} variant={LEVEL_VARIANTS[level.toLowerCase()] ?? 'neutral'} />;
}

const LEVELS = ['critical', 'high', 'medium', 'low', 'informational'];

const columns: ColumnDef<SigmaRule>[] = [
  {
    key: 'title',
    header: 'Title',
    sortKey: 'title',
    render: (row) => (
      <div>
        <span className="text-[var(--text-primary)]">{row.title}</span>
        <a href={sigmaRuleUrl(row.sigma_id)} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] text-xs font-mono mt-0.5 hover:underline block">{row.sigma_id} ↗</a>
      </div>
    ),
  },
  {
    key: 'technique_attack_id',
    header: 'Technique',
    width: '200px',
    render: (row) =>
      row.technique_attack_id && row.technique_name ? (
        <EntityLink
          type="technique"
          attackId={row.technique_attack_id}
          name={row.technique_name}
        />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'level',
    header: 'Level',
    width: '120px',
    render: (row) => <LevelBadge level={row.level} />,
  },
  {
    key: 'status',
    header: 'Status',
    width: '110px',
    render: (row) =>
      row.status ? (
        <Badge label={row.status} variant="neutral" />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'logsource_category',
    header: 'Log Source',
    width: '180px',
    render: (row) => {
      const parts = [row.logsource_product, row.logsource_category].filter(Boolean).join(' / ');
      return parts ? (
        <span className="text-[var(--text-secondary)] text-xs">{parts}</span>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      );
    },
  },
];

export function SigmaList() {

  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const level = searchParams.get('level') ?? '';
  const technique = searchParams.get('technique') ?? '';
  const q = searchParams.get('q') ?? '';

  const setParam = useCallback(
    (key: string, value: string) => {
      const updates: Record<string, string | null> = {
        [key]: value || null,
      };
      if (key !== 'page') updates.page = '1';
      updateParams(updates);
    },
    [updateParams],
  );

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (level) params.level = level;
  if (technique) params.technique = technique;
  if (q) params.search = q;

  const { data, isLoading } = useSigmaRules(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Sigma Detection Rules"
        subtitle="Detection rules from SigmaHQ mapped to ATT&CK techniques"
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search rules..."
          value={q}
          onChange={(e) => setParam('q', e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <div className="flex flex-col gap-1">
          <input
            type="text"
            placeholder="Technique ID (e.g. T1059)"
            value={technique}
            onChange={(e) => setParam('technique', e.target.value)}
            className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
          />
          <span className="text-[10px] text-[var(--text-secondary)]">Enter exact ID, e.g. T1059.001</span>
        </div>
        <select
          value={level}
          onChange={(e) => setParam('level', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Levels</option>
          {LEVELS.map((l) => (
            <option key={l} value={l}>{l.charAt(0).toUpperCase() + l.slice(1)}</option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.id}
        emptyMessage="No Sigma rules found. Run the GitHub Actions workflow to sync."
      />
    </div>
  );
}
