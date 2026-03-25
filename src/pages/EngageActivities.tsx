import { useCallback, useState } from 'react';
import { usePageTitle } from '../hooks/usePageTitle';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useEngageActivities } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import type { EngageSummary } from '../lib/types';

const FUSE_KEYS = ['engageName', 'engageDescription', 'goal', 'approach'];

const GOAL_COLORS: Record<string, string> = {
  Expose:  'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  Affect:  'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  Elicit:  'bg-[var(--purple-faint)] text-[var(--accent-purple)] border-[var(--purple-dim)]',
  Prepare: 'bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]',
  Understand: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

function GoalBadge({ goal }: { goal: string | null }) {
  if (!goal) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  const classes =
    GOAL_COLORS[goal] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}
    >
      {goal}
    </span>
  );
}

function TechniquePopover({ engageId, count }: { engageId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['engage-techniques', engageId],
    queryFn: () => apiFetch<{ data: Array<{ attackId: string; name: string }> }>(`/frameworks/engage/${engageId}/techniques`),
    enabled: open,
  });

  return (
    <div className="relative">
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen(!open); }}
        className="cursor-pointer"
      >
        <Badge label={String(count)} variant="teal" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-8 z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl p-3 min-w-[240px] max-h-[300px] overflow-y-auto">
            <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-2">
              Linked Techniques ({count})
            </div>
            {isLoading && (
              <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs py-2">
                <span className="inline-block w-3 h-3 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
                Loading...
              </div>
            )}
            {data?.data && (
              <div className="flex flex-col gap-1">
                {data.data.map((t) => (
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} />
                ))}
              </div>
            )}
            {!isLoading && data?.data?.length === 0 && (
              <span className="text-xs text-[var(--text-secondary)]">No techniques found.</span>
            )}
          </div>
        </>
      )}
    </div>
  );
}

const columns: ColumnDef<EngageSummary>[] = [
  {
    key: 'engageId',
    header: 'ID',
    width: '110px',
    render: (row) => (
      <span className="font-mono text-sm text-[var(--accent-teal)]">{row.engageId}</span>
    ),
  },
  {
    key: 'engageName',
    header: 'Activity',
    render: (row) => (
      <div>
        <div className="text-[var(--text-primary)] text-sm">{row.engageName}</div>
        {row.engageDescription && (
          <div className="text-[var(--text-secondary)] text-xs mt-0.5 line-clamp-2">
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
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    width: '100px',
    align: 'center',
    render: (row) =>
      row.techniqueCount > 0 ? (
        <TechniquePopover engageId={row.engageId} count={row.techniqueCount} />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
];

export function EngageActivities() {
  usePageTitle('MITRE Engage');

  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState(searchParams.get('q') ?? '');

  const goal = searchParams.get('goal') ?? '';

  const params: Record<string, string> = { limit: '5000' };
  if (goal) params.goal = goal;

  const { data, isLoading } = useEngageActivities(params);

  const filteredData = useFuseFilter(data?.data ?? [], FUSE_KEYS, search);

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        return next;
      });
    },
    [setSearchParams],
  );

  // Extract unique goals from all loaded data for filter
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
        subtitle={`${data?.pagination?.total ?? 0} adversary engagement and deception activities`}
      />

      {/* Info banner */}
      <div className="px-4 py-3 rounded-lg bg-[var(--surface-card)] border border-[var(--border-color)] text-sm text-[var(--text-secondary)]">
        MITRE Engage is a framework for planning and discussing adversary engagement operations.
        Activities are mapped to ATT&CK techniques to enable defenders to think about
        how to expose, affect, or elicit information from adversaries.{' '}
        <a
          href="https://engage.mitre.org"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[var(--accent-teal)] hover:underline"
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
          onChange={(e) => setSearch(e.target.value)}
          className="
            flex-1 min-w-[200px] max-w-sm px-3 py-2 rounded-md text-sm
            bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]
            placeholder:text-[var(--text-secondary)]
            focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)] focus:border-[var(--accent-teal)]
          "
        />
        {uniqueGoals.length > 0 && (
          <select
            value={goal}
            onChange={(e) => setParam('goal', e.target.value)}
            className="
              px-3 py-2 rounded-md text-sm
              bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)]
              focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)] focus:border-[var(--accent-teal)]
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
        data={filteredData}
        loading={isLoading}
        rowKey={(row) => row.engageId}
        emptyMessage="No Engage activities found. Run the sync script to populate data."
      />
    </div>
  );
}
