import { useState } from 'react';
import { usePageTitle } from '../hooks/usePageTitle';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useDataSources } from '../hooks/useApi';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { useDomain } from '../contexts/DomainContext';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import type { DataSource } from '../lib/types';

const FUSE_KEYS = ['name', 'attackId', 'description'];

export function DataSourcesList() {
  usePageTitle('Data Sources');

  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState('');

  const sort = searchParams.get('sort') ?? 'attack_id';
  const order = (searchParams.get('order') ?? 'asc') as 'asc' | 'desc';

  const { domainParam } = useDomain();

  const params: Record<string, string> = { limit: '5000', ...domainParam };
  if (sort) params.sort = sort;
  if (order) params.order = order;

  const { data, isLoading } = useDataSources(params);

  const filteredData = useFuseFilter(data?.data ?? [], FUSE_KEYS, search);

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

  const columns: ColumnDef<DataSource>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attack_id',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[var(--accent-pink)]">{row.attackId}</span>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortKey: 'name',
      render: (row) => (
        <EntityLink type="data_source" attackId={row.attackId} name={row.name} />
      ),
    },
    {
      key: 'components',
      header: 'Component Count',
      align: 'center',
      width: '160px',
      render: (row) => {
        const count = row.componentCount ?? 0;
        const colorClass = count > 3 ? 'text-[var(--accent-pink)]' : 'text-[var(--text-secondary)]';
        return (
          <span className={`text-sm font-semibold tabular-nums ${colorClass}`}>
            {count}
          </span>
        );
      },
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
      <PageHeader title="Data Sources" subtitle="Data sources and components for detection" />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search data sources..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
      </div>

      <DataTable
        columns={columns}
        data={filteredData}
        loading={isLoading}
        sortBy={sort}
        sortDir={order}
        onSort={handleSort}
        onRowClick={(row) => navigate(`/data-sources/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No data sources found."
      />
    </div>
  );
}
