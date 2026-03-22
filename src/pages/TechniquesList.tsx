import { useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useTechniques, useTactics } from '../hooks/useApi';
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
  if (!platforms?.length) return <span className="text-[#8892b0] text-xs">—</span>;
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

export function TechniquesList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const search = searchParams.get('q') ?? '';
  const tactic = searchParams.get('tactic') ?? '';
  const platform = searchParams.get('platform') ?? '';
  const sortBy = searchParams.get('sort') ?? 'attack_id';
  const sortDir = (searchParams.get('order') ?? 'asc') as 'asc' | 'desc';

  const [expandedParents, setExpandedParents] = useState<Set<string>>(new Set());

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.search = search;
  if (tactic) params.tactic = tactic;
  if (platform) params.platform = platform;
  if (sortBy) params.sort = sortBy;
  if (sortDir) params.order = sortDir;

  const { data, isLoading } = useTechniques(params);
  const { data: tacticsData } = useTactics({ limit: '100' });

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
    [setSearchParams]
  );

  function handleSort(key: string) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      const currentDir = prev.get('order') ?? 'asc';
      const currentKey = prev.get('sort') ?? 'attack_id';
      next.set('sort', key);
      next.set('order', currentKey === key && currentDir === 'asc' ? 'desc' : 'asc');
      next.set('page', '1');
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
  const rows = (data?.data ?? []).flatMap((t) => {
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
              className="text-[#8892b0] hover:text-[#64ffda] transition-colors"
              aria-label={expandedParents.has(row.attackId) ? 'Collapse' : 'Expand'}
            >
              {expandedParents.has(row.attackId) ? '▾' : '▸'}
            </button>
          )}
          {row._isSubTechnique && <span className="w-4" />}
          <span className={`font-mono text-xs ${row._isSubTechnique ? 'text-[#64ffda88]' : 'text-[#64ffda]'}`}>
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
          <span className="text-[#ccd6f6]">{row.name}</span>
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
          <span className="text-[#8892b0] text-xs">—</span>
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
          onChange={(e) => setParam('q', e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
        <select
          value={tactic}
          onChange={(e) => setParam('tactic', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
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
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
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
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
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
