'use client';
import { useState, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useSoftware } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { useDomain } from '../contexts/DomainContext';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import type { Software } from '../lib/types';

const FUSE_KEYS = ['name', 'attackId', 'description'];

export function SoftwareList() {

  const router = useRouter();
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const { sectorParam } = useSector();
  const { domainParam } = useDomain();

  const type = searchParams.get('type') ?? '';
  const sort = searchParams.get('sort') ?? 'attack_id';
  const order = (searchParams.get('order') ?? 'asc') as 'asc' | 'desc';

  const [search, setSearch] = useState('');

  const params: Record<string, string> = { limit: '5000', ...sectorParam, ...domainParam };
  if (type) params.type = type;
  if (sort) params.sort = sort;
  if (order) params.order = order;

  const { data, isLoading } = useSoftware(params);

  const allItems = data?.data ?? [];
  const filtered = useFuseFilter(allItems, FUSE_KEYS, search);

  const setParam = useCallback(
    (key: string, value: string) => {
      updateParams({ [key]: value || null });
    },
    [updateParams]
  );

  function handleSort(key: string) {
    const curKey = searchParams.get('sort') ?? 'attack_id';
    const curDir = searchParams.get('order') ?? 'asc';
    updateParams({
      sort: key,
      order: curKey === key && curDir === 'asc' ? 'desc' : 'asc',
    });
  }

  const columns: ColumnDef<Software>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attack_id',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[var(--accent-purple)]">{row.attackId}</span>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortKey: 'name',
      render: (row) => (
        <div className="flex items-center gap-2">
          <EntityLink type="software" attackId={row.attackId} name={row.name} />
          {(row.isRevoked || row.isDeprecated) && (
            <DeprecatedBadge isRevoked={row.isRevoked} />
          )}
        </div>
      ),
    },
    {
      key: 'type',
      header: 'Type',
      width: '100px',
      render: (row) => (
        <Badge
          label={row.type === 'malware' ? 'Malware' : 'Tool'}
          variant={row.type === 'malware' ? 'orange' : 'teal'}
        />
      ),
    },
    {
      key: 'platforms',
      header: 'Platforms',
      render: (row) =>
        row.platforms?.length ? (
          <div className="flex flex-wrap gap-1">
            {row.platforms.slice(0, 3).map((p) => (
              <Badge key={p} label={p} variant="blue" />
            ))}
            {row.platforms.length > 3 && (
              <Badge label={`+${row.platforms.length - 3}`} variant="neutral" />
            )}
          </div>
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
    {
      key: 'domain',
      header: 'Domain',
      width: '70px',
      align: 'center',
      render: (row) =>
        row.domain ? (
          <span className="text-[10px] text-[var(--text-secondary)] uppercase block text-center">{row.domain.replace('-attack', '')}</span>
        ) : null,
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Software" subtitle="Malware and tools tracked by MITRE ATT&CK" />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search software..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={type}
          onChange={(e) => setParam('type', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Types</option>
          <option value="malware">Malware</option>
          <option value="tool">Tool</option>
        </select>
      </div>

      <DataTable
        columns={columns}
        data={filtered}
        loading={isLoading}
        sortBy={sort}
        sortDir={order}
        onSort={handleSort}
        onRowClick={(row) => router.push(`/software/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No software found."
      />
    </div>
  );
}
