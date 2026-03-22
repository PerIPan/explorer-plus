import { useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useGroups, useSectors } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { EntityLink } from '../components/shared/EntityLink';
import type { Group } from '../lib/types';

export function GroupsList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const search = searchParams.get('q') ?? '';
  const sector = searchParams.get('sector') ?? '';
  const sortBy = searchParams.get('sortBy') ?? 'attackId';
  const sortDir = (searchParams.get('sortDir') ?? 'asc') as 'asc' | 'desc';

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.q = search;
  if (sector) params.sector = sector;
  if (sortBy) params.sortBy = sortBy;
  if (sortDir) params.sortDir = sortDir;

  const { data, isLoading } = useGroups(params);
  const { data: sectorsData } = useSectors({ limit: '100' });

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value); else next.delete(key);
        if (key !== 'page') next.set('page', '1');
        return next;
      });
    },
    [setSearchParams]
  );

  function handleSort(key: string) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      const curKey = prev.get('sortBy') ?? 'attackId';
      const curDir = prev.get('sortDir') ?? 'asc';
      next.set('sortBy', key);
      next.set('sortDir', curKey === key && curDir === 'asc' ? 'desc' : 'asc');
      next.set('page', '1');
      return next;
    });
  }

  const columns: ColumnDef<Group>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attackId',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[#f97316]">{row.attackId}</span>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortKey: 'name',
      render: (row) => (
        <div className="flex items-center gap-2">
          <EntityLink type="group" attackId={row.attackId} name={row.name} />
          {(row.isRevoked || row.isDeprecated) && (
            <DeprecatedBadge isRevoked={row.isRevoked} />
          )}
        </div>
      ),
    },
    {
      key: 'aliases',
      header: 'Aliases',
      render: (row) =>
        row.aliases?.length ? (
          <span className="text-xs text-[#8892b0]">
            {row.aliases.slice(0, 3).join(', ')}
            {row.aliases.length > 3 ? ` +${row.aliases.length - 3}` : ''}
          </span>
        ) : (
          <span className="text-[#8892b0] text-xs">—</span>
        ),
    },
    {
      key: 'country',
      header: 'Country',
      render: (row) =>
        row.country ? (
          <Badge label={row.country} variant="orange" />
        ) : (
          <span className="text-[#8892b0] text-xs">—</span>
        ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Groups" subtitle="Threat actor groups tracked by MITRE ATT&CK" />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search groups..."
          value={search}
          onChange={(e) => setParam('q', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
        <select
          value={sector}
          onChange={(e) => setParam('sector', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
        >
          <option value="">All Sectors</option>
          {(sectorsData?.data ?? []).map((s) => (
            <option key={s.id} value={s.name}>{s.name}</option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        sortBy={sortBy}
        sortDir={sortDir}
        onSort={handleSort}
        onRowClick={(row) => navigate(`/groups/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No groups found."
      />
    </div>
  );
}
