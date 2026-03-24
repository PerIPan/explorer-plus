import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useCampaigns } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { useDomain } from '../contexts/DomainContext';
import { useFuseFilter } from '../hooks/useFuseFilter';
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

const FUSE_KEYS = ['name', 'attackId', 'description'];

export function CampaignsList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { sectorParam } = useSector();
  const { domainParam } = useDomain();

  const sort = searchParams.get('sort') ?? 'last_seen';
  const order = (searchParams.get('order') ?? 'desc') as 'asc' | 'desc';

  const [search, setSearch] = useState('');

  const params: Record<string, string> = { limit: '5000', ...sectorParam, ...domainParam };
  if (sort) params.sort = sort;
  if (order) params.order = order;

  const { data, isLoading } = useCampaigns(params);

  const allItems = data?.data ?? [];
  const filtered = useFuseFilter(allItems, FUSE_KEYS, search);

  function handleSort(key: string) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      const curKey = prev.get('sort') ?? 'last_seen';
      const curDir = prev.get('order') ?? 'desc';
      next.set('sort', key);
      next.set('order', curKey === key && curDir === 'asc' ? 'desc' : 'asc');
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
        <span className="font-mono text-xs text-[var(--accent-blue)]">{row.attackId}</span>
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
        <span className="text-sm text-[var(--text-secondary)]">{fmtDate(row.firstSeen)}</span>
      ),
    },
    {
      key: 'last_seen',
      header: 'Last Seen',
      sortKey: 'last_seen',
      width: '120px',
      render: (row) => (
        <span className="text-sm text-[var(--text-secondary)]">{fmtDate(row.lastSeen)}</span>
      ),
    },
    {
      key: 'timeline',
      header: 'Timeline',
      width: '180px',
      render: (row) => {
        if (!row.firstSeen && !row.lastSeen) {
          return <span className="text-[var(--text-secondary)] text-xs">—</span>;
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
          <div className="relative h-3 rounded bg-[var(--surface-deep)] border border-[var(--border-color)] overflow-hidden">
            <div
              className="absolute top-0.5 bottom-0.5 rounded bg-[var(--accent-blue)] opacity-70"
              style={{ left: `${left}%`, width: `${width}%` }}
            />
          </div>
        );
      },
    },
    {
      key: 'domain',
      header: 'Domain',
      width: '80px',
      render: (row) =>
        row.domain ? (
          <span className="text-[10px] text-[var(--text-secondary)] uppercase">{row.domain.replace('-attack', '')}</span>
        ) : null,
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
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
      </div>

      <DataTable
        columns={columns}
        data={filtered}
        loading={isLoading}
        sortBy={sort}
        sortDir={order}
        onSort={handleSort}
        onRowClick={(row) => navigate(`/campaigns/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No campaigns found."
      />
    </div>
  );
}
