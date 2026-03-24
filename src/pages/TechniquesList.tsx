import { useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useTechniques, useTactics } from '../hooks/useApi';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { useSector } from '../contexts/SectorContext';
import { useDomain } from '../contexts/DomainContext';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import type { Technique } from '../lib/types';

const PLATFORM_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  Windows: 'blue',
  Linux: 'teal',
  macOS: 'purple',
  Cloud: 'orange',
  Azure: 'blue',
  'Google Workspace': 'green',
  SaaS: 'pink',
};

function PlatformBadges({ platforms }: { platforms: string[] | null }) {
  if (!platforms?.length) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {platforms.slice(0, 3).map((p) => (
        <Badge
          key={p}
          label={p}
          variant={PLATFORM_VARIANTS[p] ?? 'neutral'}
        />
      ))}
      {platforms.length > 3 && (
        <Badge label={`+${platforms.length - 3}`} variant="neutral" />
      )}
    </div>
  );
}

const FUSE_KEYS = ['name', 'attackId', 'description'];

export function TechniquesList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { sectorParam } = useSector();
  const { domainParam } = useDomain();

  const tactic = searchParams.get('tactic') ?? '';
  const platform = searchParams.get('platform') ?? '';
  const sortBy = searchParams.get('sort') ?? 'attack_id';
  const sortDir = (searchParams.get('order') ?? 'asc') as 'asc' | 'desc';

  const [search, setSearch] = useState('');
  const [expandedParents, setExpandedParents] = useState<Set<string>>(new Set());

  const params: Record<string, string> = { limit: '5000', ...sectorParam, ...domainParam };
  if (tactic) params.tactic = tactic;
  if (platform) params.platform = platform;
  if (sortBy) params.sort = sortBy;
  if (sortDir) params.order = sortDir;

  const { data, isLoading } = useTechniques(params);
  const { data: tacticsData } = useTactics({ limit: '100' });

  const allItems = data?.data ?? [];
  const filtered = useFuseFilter(allItems, FUSE_KEYS, search);

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) {
          next.set(key, value);
        } else {
          next.delete(key);
        }
        return next;
      });
    },
    [setSearchParams]
  );

  function handleSort(key: string) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      const currentDir = prev.get('order') ?? 'asc';
      const currentKey = prev.get('sort') ?? 'attack_id';
      next.set('sort', key);
      next.set('order', currentKey === key && currentDir === 'asc' ? 'desc' : 'asc');
      return next;
    });
  }

  function toggleExpand(attackId: string) {
    setExpandedParents((prev) => {
      const next = new Set(prev);
      next.has(attackId) ? next.delete(attackId) : next.add(attackId);
      return next;
    });
  }

  const tacticOptions = tacticsData?.data ?? [];

  /** Flatten rows to include sub-techniques when expanded */
  const rows = filtered.flatMap((t) => {
    const main: Array<Technique & { _isSubTechnique?: boolean; _parentName?: string }> = [
      t as Technique & { _isSubTechnique?: boolean; _parentName?: string },
    ];
    if (expandedParents.has(t.attackId) && t.sub_techniques?.length) {
      t.sub_techniques.forEach((sub) => {
        main.push({
          ...sub,
          sub_techniques: [],
          _isSubTechnique: true,
          _parentName: t.name,
        } as Technique & { _isSubTechnique?: boolean; _parentName?: string });
      });
    }
    return main;
  });

  const columns: ColumnDef<Technique & { _isSubTechnique?: boolean; _parentName?: string }>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attack_id',
      width: '130px',
      render: (row) => (
        <div className="flex items-center gap-1">
          {!row._isSubTechnique && row.sub_techniques?.length > 0 && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                toggleExpand(row.attackId);
              }}
              className="text-base text-[var(--accent-teal)] hover:text-[var(--accent-teal-light)] transition-colors leading-none"
              aria-label={expandedParents.has(row.attackId) ? 'Collapse' : 'Expand'}
            >
              {expandedParents.has(row.attackId) ? '▾' : '▸'}
            </button>
          )}
          {row._isSubTechnique && <span className="w-4" />}
          <span className={`font-mono text-xs ${row._isSubTechnique ? 'text-[var(--accent-teal)]' : 'text-[var(--accent-teal)]'}`}>
            {row.attackId}
          </span>
        </div>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortKey: 'name',
      render: (row) => (
        <div className={`flex items-center gap-2 ${row._isSubTechnique ? 'pl-4' : ''}`}>
          <span className="text-[var(--text-primary)]">{row.name}</span>
          {(row.isRevoked || row.isDeprecated) && (
            <DeprecatedBadge isRevoked={row.isRevoked} />
          )}
        </div>
      ),
    },
    {
      key: 'platforms',
      header: 'Platforms',
      render: (row) => <PlatformBadges platforms={row.platforms} />,
    },
    {
      key: 'tactics',
      header: 'Tactics',
      render: (row) =>
        row.tactics?.length ? (
          <div className="flex flex-wrap gap-1">
            {row.tactics.map((tac) => (
              <Badge key={tac} label={tac} variant="yellow" />
            ))}
          </div>
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Techniques" subtitle="ATT&CK techniques and sub-techniques" />

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search techniques..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={tactic}
          onChange={(e) => setParam('tactic', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Tactics</option>
          {tacticOptions.map((t) => (
            <option key={t.attackId} value={t.attackId}>
              {t.name}
            </option>
          ))}
        </select>
        <select
          value={platform}
          onChange={(e) => setParam('platform', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Platforms</option>
          {['Windows', 'Linux', 'macOS', 'Cloud', 'Azure', 'Google Workspace', 'SaaS'].map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        data={rows}
        loading={isLoading}
        sortBy={sortBy}
        sortDir={sortDir}
        onSort={handleSort}
        onRowClick={(row) => navigate(`/techniques/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No techniques found."
      />
    </div>
  );
}
