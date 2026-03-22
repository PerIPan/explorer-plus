import { useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useDataSources } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import type { DataSource } from '../lib/types';

export function DataSourcesList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const search = searchParams.get('q') ?? '';
  const sortBy = searchParams.get('sortBy') ?? 'attackId';
  const sortDir = (searchParams.get('sortDir') ?? 'asc') as 'asc' | 'desc';

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.search = search;
  if (sortBy) params.sortBy = sortBy;
  if (sortDir) params.sortDir = sortDir;

  const { data, isLoading } = useDataSources(params);

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

  const columns: ColumnDef<DataSource>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attackId',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[#f472b6]">{row.attackId}</span>
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
      render: (row) => (
        <span className="text-sm font-semibold text-[#f472b6] tabular-nums">
          {row.components?.length ?? 0}
        </span>
      ),
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
          onChange={(e) => setParam('q', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
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
        onRowClick={(row) => navigate(`/data-sources/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No data sources found."
      />
    </div>
  );
}
