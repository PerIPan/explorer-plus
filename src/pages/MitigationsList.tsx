import { useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMitigations } from '../hooks/useApi';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import type { Mitigation } from '../lib/types';

const FUSE_KEYS = ['name', 'attackId', 'description'];

export function MitigationsList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const sort = searchParams.get('sort') ?? 'attack_id';
  const order = (searchParams.get('order') ?? 'asc') as 'asc' | 'desc';

  const [search, setSearch] = useState('');

  const params: Record<string, string> = { limit: '5000' };
  if (sort) params.sort = sort;
  if (order) params.order = order;

  const { data, isLoading } = useMitigations(params);

  const allItems = data?.data ?? [];
  const filtered = useFuseFilter(allItems, FUSE_KEYS, search);

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value); else next.delete(key);
        return next;
      });
    },
    [setSearchParams]
  );

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

  const columns: ColumnDef<Mitigation>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attack_id',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[#34d399]">{row.attackId}</span>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortKey: 'name',
      render: (row) => (
        <div className="flex items-center gap-2">
          <EntityLink type="mitigation" attackId={row.attackId} name={row.name} />
          {(row.isRevoked || row.isDeprecated) && (
            <DeprecatedBadge isRevoked={row.isRevoked} />
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Mitigations" subtitle="Security controls mapped to ATT&CK techniques" />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search mitigations..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
      </div>

      <DataTable
        columns={columns}
        data={filtered}
        loading={isLoading}
        sortBy={sort}
        sortDir={order}
        onSort={handleSort}
        onRowClick={(row) => navigate(`/mitigations/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No mitigations found."
      />
    </div>
  );
}
