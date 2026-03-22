import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSigmaRules } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import type { SigmaRule } from '../lib/types';

const LEVEL_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  critical: 'pink',
  high: 'orange',
  medium: 'yellow' as unknown as 'orange', // Badge doesn't have yellow in original, using orange
  low: 'blue',
  informational: 'green',
};

// Override yellow specifically using className
function LevelBadge({ level }: { level: string | null }) {
  if (!level) return <span className="text-[#8892b0] text-xs">—</span>;

  const colorMap: Record<string, string> = {
    critical: 'bg-[#f472b618] text-[#f472b6] border-[#f472b633]',
    high: 'bg-[#f9731618] text-[#f97316] border-[#f9731633]',
    medium: 'bg-[#fbbf2418] text-[#fbbf24] border-[#fbbf2433]',
    low: 'bg-[#60a5fa18] text-[#60a5fa] border-[#60a5fa33]',
    informational: 'bg-[#34d39918] text-[#34d399] border-[#34d39933]',
  };

  const classes = colorMap[level.toLowerCase()] ?? 'bg-[#ffffff08] text-[#8892b0] border-[#2a2a4a]';

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}
    >
      {level}
    </span>
  );
}

const LEVELS = ['critical', 'high', 'medium', 'low', 'informational'];

const columns: ColumnDef<SigmaRule>[] = [
  {
    key: 'title',
    header: 'Title',
    sortKey: 'title',
    render: (row) => (
      <div>
        <span className="text-[#ccd6f6]">{row.title}</span>
        <div className="text-[#8892b0] text-xs font-mono mt-0.5">{row.sigma_id}</div>
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
        <span className="text-[#8892b0] text-xs">—</span>
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
        <span className="text-[#8892b0] text-xs">—</span>
      ),
  },
  {
    key: 'logsource_category',
    header: 'Log Source',
    width: '180px',
    render: (row) => {
      const parts = [row.logsource_product, row.logsource_category].filter(Boolean).join(' / ');
      return parts ? (
        <span className="text-[#8892b0] text-xs">{parts}</span>
      ) : (
        <span className="text-[#8892b0] text-xs">—</span>
      );
    },
  },
];

export function SigmaList() {
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const level = searchParams.get('level') ?? '';
  const technique = searchParams.get('technique') ?? '';
  const q = searchParams.get('q') ?? '';

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
  if (level) params.level = level;
  if (technique) params.technique = technique;
  if (q) params.q = q;

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
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
        <input
          type="text"
          placeholder="Technique ID (e.g. T1059)"
          value={technique}
          onChange={(e) => setParam('technique', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
        <select
          value={level}
          onChange={(e) => setParam('level', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
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
