import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngageActivities } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import type { EngageSummary } from '../lib/types';

const GOAL_COLORS: Record<string, string> = {
  Expose:  'bg-[#f9731618] text-[#f97316] border-[#f9731633]',
  Affect:  'bg-[#f472b618] text-[#f472b6] border-[#f472b633]',
  Elicit:  'bg-[#a78bfa18] text-[#a78bfa] border-[#a78bfa33]',
  Prepare: 'bg-[#34d39918] text-[#34d399] border-[#34d39933]',
  Understand: 'bg-[#60a5fa18] text-[#60a5fa] border-[#60a5fa33]',
};

function GoalBadge({ goal }: { goal: string | null }) {
  if (!goal) return <span className="text-[#8892b0] text-xs">—</span>;
  const classes =
    GOAL_COLORS[goal] ?? 'bg-[#ffffff08] text-[#8892b0] border-[#2a2a4a]';
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}
    >
      {goal}
    </span>
  );
}

const columns: ColumnDef<EngageSummary>[] = [
  {
    key: 'engageId',
    header: 'ID',
    width: '110px',
    render: (row) => (
      <span className="font-mono text-sm text-[#64ffda]">{row.engageId}</span>
    ),
  },
  {
    key: 'engageName',
    header: 'Activity',
    render: (row) => (
      <div>
        <div className="text-[#ccd6f6] text-sm">{row.engageName}</div>
        {row.engageDescription && (
          <div className="text-[#8892b0] text-xs mt-0.5 line-clamp-2">
            {row.engageDescription}
          </div>
        )}
      </div>
    ),
  },
  {
    key: 'goal',
    header: 'Goal',
    width: '130px',
    render: (row) => <GoalBadge goal={row.goal} />,
  },
  {
    key: 'approach',
    header: 'Approach',
    width: '180px',
    render: (row) =>
      row.approach ? (
        <Badge label={row.approach} variant="purple" />
      ) : (
        <span className="text-[#8892b0] text-xs">—</span>
      ),
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    width: '100px',
    align: 'center',
    render: (row) => (
      <span className="text-[#ccd6f6] text-sm font-medium">{row.techniqueCount}</span>
    ),
  },
];

export function EngageActivities() {
  const [searchParams, setSearchParams] = useSearchParams();
  const search = searchParams.get('search') ?? '';
  const goal   = searchParams.get('goal') ?? '';
  const page   = parseInt(searchParams.get('page') ?? '1', 10);

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.search = search;
  if (goal) params.goal = goal;

  const { data, isLoading } = useEngageActivities(params);

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        if (key !== 'page') next.delete('page');
        return next;
      });
    },
    [setSearchParams],
  );

  // Extract unique goals from current data for filter
  const uniqueGoals = Array.from(
    new Set(
      (data?.data ?? [])
        .map((r) => r.goal)
        .filter((g): g is string => Boolean(g)),
    ),
  ).sort();

  return (
    <div className="space-y-6">
      <PageHeader
        title="MITRE Engage Activities"
        subtitle={`${data?.pagination.total ?? 0} adversary engagement and deception activities`}
      />

      {/* Info banner */}
      <div className="px-4 py-3 rounded-lg bg-[#16213e] border border-[#2a2a4a] text-sm text-[#8892b0]">
        MITRE Engage is a framework for planning and discussing adversary engagement operations.
        Activities are mapped to ATT&CK techniques to enable defenders to think about
        how to expose, affect, or elicit information from adversaries.{' '}
        <a
          href="https://engage.mitre.org"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[#64ffda] hover:underline"
        >
          engage.mitre.org
        </a>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search activities..."
          value={search}
          onChange={(e) => setParam('search', e.target.value)}
          className="
            flex-1 min-w-[200px] max-w-sm px-3 py-2 rounded-md text-sm
            bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6]
            placeholder:text-[#4a5568]
            focus:outline-none focus:ring-1 focus:ring-[#64ffda] focus:border-[#64ffda]
          "
        />
        {uniqueGoals.length > 0 && (
          <select
            value={goal}
            onChange={(e) => setParam('goal', e.target.value)}
            className="
              px-3 py-2 rounded-md text-sm
              bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6]
              focus:outline-none focus:ring-1 focus:ring-[#64ffda] focus:border-[#64ffda]
            "
          >
            <option value="">All goals</option>
            {uniqueGoals.map((g) => (
              <option key={g} value={g}>{g}</option>
            ))}
          </select>
        )}
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.engageId}
        emptyMessage="No Engage activities found. Run the sync script to populate data."
      />
    </div>
  );
}
