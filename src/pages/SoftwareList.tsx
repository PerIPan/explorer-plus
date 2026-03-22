import { useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useSoftware } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import type { Software } from '../lib/types';

export function SoftwareList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const search = searchParams.get('q') ?? '';
  const type = searchParams.get('type') ?? '';
  const sortBy = searchParams.get('sortBy') ?? 'attackId';
  const sortDir = (searchParams.get('sortDir') ?? 'asc') as 'asc' | 'desc';

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.q = search;
  if (type) params.type = type;
  if (sortBy) params.sortBy = sortBy;
  if (sortDir) params.sortDir = sortDir;

  const { data, isLoading } = useSoftware(params);

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

  const columns: ColumnDef<Software>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attackId',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[#a78bfa]">{row.attackId}</span>
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
          <span className="text-[#8892b0] text-xs">—</span>
        ),
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
          onChange={(e) => setParam('q', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
        <select
          value={type}
          onChange={(e) => setParam('type', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
        >
          <option value="">All Types</option>
          <option value="malware">Malware</option>
          <option value="tool">Tool</option>
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
        onRowClick={(row) => navigate(`/software/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No software found."
      />
    </div>
  );
}
