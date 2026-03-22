import { useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useCampaigns } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import type { Campaign } from '../lib/types';

function fmtDate(d: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
  });
}

export function CampaignsList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const search = searchParams.get('q') ?? '';
  const sort = searchParams.get('sort') ?? 'attack_id';
  const order = (searchParams.get('order') ?? 'asc') as 'asc' | 'desc';

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.search = search;
  if (sort) params.sort = sort;
  if (order) params.order = order;

  const { data, isLoading } = useCampaigns(params);

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
      const curKey = prev.get('sort') ?? 'attack_id';
      const curDir = prev.get('order') ?? 'asc';
      next.set('sort', key);
      next.set('order', curKey === key && curDir === 'asc' ? 'desc' : 'asc');
      next.set('page', '1');
      return next;
    });
  }

  const columns: ColumnDef<Campaign>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attack_id',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[#60a5fa]">{row.attackId}</span>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortKey: 'name',
      render: (row) => (
        <div className="flex items-center gap-2">
          <EntityLink type="campaign" attackId={row.attackId} name={row.name} />
          {(row.isRevoked || row.isDeprecated) && (
            <DeprecatedBadge isRevoked={row.isRevoked} />
          )}
        </div>
      ),
    },
    {
      key: 'first_seen',
      header: 'First Seen',
      sortKey: 'first_seen',
      width: '120px',
      render: (row) => (
        <span className="text-sm text-[#8892b0]">{fmtDate(row.firstSeen)}</span>
      ),
    },
    {
      key: 'last_seen',
      header: 'Last Seen',
      sortKey: 'last_seen',
      width: '120px',
      render: (row) => (
        <span className="text-sm text-[#8892b0]">{fmtDate(row.lastSeen)}</span>
      ),
    },
    {
      key: 'timeline',
      header: 'Timeline',
      width: '180px',
      render: (row) => {
        if (!row.firstSeen && !row.lastSeen) {
          return <span className="text-[#8892b0] text-xs">—</span>;
        }
        const now = new Date();
        const windowStart = new Date('2010-01-01').getTime();
        const windowEnd = now.getTime();
        const range = windowEnd - windowStart;
        const start = row.firstSeen ? new Date(row.firstSeen).getTime() : windowStart;
        const end = row.lastSeen ? new Date(row.lastSeen).getTime() : windowEnd;
        const left = Math.max(0, ((start - windowStart) / range) * 100);
        const width = Math.max(1, Math.min(100 - left, ((end - start) / range) * 100));
        return (
          <div className="relative h-3 rounded bg-[#0a0a1a] border border-[#2a2a4a] overflow-hidden">
            <div
              className="absolute top-0.5 bottom-0.5 rounded bg-[#60a5fa] opacity-70"
              style={{ left: `${left}%`, width: `${width}%` }}
            />
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Campaigns" subtitle="Named intrusion campaigns tracked by MITRE ATT&CK" />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search campaigns..."
          value={search}
          onChange={(e) => setParam('q', e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        sort={sort}
        order={order}
        onSort={handleSort}
        onRowClick={(row) => navigate(`/campaigns/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No campaigns found."
      />
    </div>
  );
}
