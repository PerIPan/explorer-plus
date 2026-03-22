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
  const sortBy = searchParams.get('sortBy') ?? 'attackId';
  const sortDir = (searchParams.get('sortDir') ?? 'asc') as 'asc' | 'desc';

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (search) params.q = search;
  if (sortBy) params.sortBy = sortBy;
  if (sortDir) params.sortDir = sortDir;

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
      const curKey = prev.get('sortBy') ?? 'attackId';
      const curDir = prev.get('sortDir') ?? 'asc';
      next.set('sortBy', key);
      next.set('sortDir', curKey === key && curDir === 'asc' ? 'desc' : 'asc');
      next.set('page', '1');
      return next;
    });
  }

  const columns: ColumnDef<Campaign>[] = [
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      sortKey: 'attackId',
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
      sortKey: 'firstSeen',
      width: '120px',
      render: (row) => (
        <span className="text-sm text-[#8892b0]">{fmtDate(row.first_seen)}</span>
      ),
    },
    {
      key: 'last_seen',
      header: 'Last Seen',
      sortKey: 'lastSeen',
      width: '120px',
      render: (row) => (
        <span className="text-sm text-[#8892b0]">{fmtDate(row.last_seen)}</span>
      ),
    },
    {
      key: 'timeline',
      header: 'Timeline',
      width: '180px',
      render: (row) => {
        if (!row.first_seen && !row.last_seen) {
          return <span className="text-[#8892b0] text-xs">—</span>;
        }
        const now = new Date();
        const windowStart = new Date('2010-01-01').getTime();
        const windowEnd = now.getTime();
        const range = windowEnd - windowStart;
        const start = row.first_seen ? new Date(row.first_seen).getTime() : windowStart;
        const end = row.last_seen ? new Date(row.last_seen).getTime() : windowEnd;
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
        onRowClick={(row) => navigate(`/campaigns/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No campaigns found."
      />
    </div>
  );
}
