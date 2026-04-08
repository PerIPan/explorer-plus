'use client';
import { useState, useCallback } from 'react';
import { useRouter, usePathname, useSearchParams } from 'next/navigation';
import { useGroups } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { useDomain } from '../contexts/DomainContext';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { EntityLink } from '../components/shared/EntityLink';
import type { Group } from '../lib/types';

const FUSE_KEYS = ['name', 'attackId', 'description'];

export function GroupsList() {

  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const setSearchParams = useCallback(
    (updater: (prev: URLSearchParams) => URLSearchParams) => {
      const next = updater(new URLSearchParams(searchParams.toString()));
      router.replace(`${pathname}?${next.toString()}`);
    },
    [router, pathname, searchParams],
  );
  const { sectorParam } = useSector();
  const { domainParam } = useDomain();

  const sortBy = searchParams.get('sort') ?? 'attack_id';
  const sortDir = (searchParams.get('order') ?? 'asc') as 'asc' | 'desc';

  const [search, setSearch] = useState('');

  const params: Record<string, string> = { limit: '5000', ...sectorParam, ...domainParam };
  if (sortBy) params.sort = sortBy;
  if (sortDir) params.order = sortDir;

  const { data, isLoading } = useGroups(params);

  const allItems = data?.data ?? [];
  const filtered = useFuseFilter(allItems, FUSE_KEYS, search);

  function handleSort(key: string) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      const curKey = prev.get('sort') ?? 'attack_id';
      const curDir = prev.get('order') ?? 'asc';
      next.set('sort', key);
      next.set('order', curKey === key && curDir === 'asc' ? 'desc' : 'asc');
      return next;
    });
  }

  const columns: ColumnDef<Group>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attack_id',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[var(--accent-orange)]">{row.attackId}</span>
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
          <span className="text-xs text-[var(--text-secondary)]">
            {row.aliases.slice(0, 3).join(', ')}
            {row.aliases.length > 3 ? ` +${row.aliases.length - 3}` : ''}
          </span>
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
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
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
      </div>

      <DataTable
        columns={columns}
        data={filtered}
        loading={isLoading}
        sortBy={sortBy}
        sortDir={sortDir}
        onSort={handleSort}
        onRowClick={(row) => router.push(`/groups/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No groups found."
      />
    </div>
  );
}
