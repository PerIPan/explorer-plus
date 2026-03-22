import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useReports } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import type { ThreatReport } from '../lib/types';

const SOURCE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  otx: 'teal',
  dfir_report: 'orange',
  unit42: 'blue',
  microsoft_security: 'blue',
  talos: 'purple',
  rss: 'green',
};

const SOURCES = [
  { value: 'otx', label: 'AlienVault OTX' },
  { value: 'dfir_report', label: 'DFIR Report' },
  { value: 'unit42', label: 'Unit 42' },
  { value: 'microsoft_security', label: 'Microsoft Security' },
  { value: 'talos', label: 'Talos' },
];

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

const columns: ColumnDef<ThreatReport>[] = [
  {
    key: 'title',
    header: 'Title',
    sortKey: 'title',
    render: (row) => (
      <a
        href={row.url}
        target="_blank"
        rel="noopener noreferrer"
        onClick={(e) => e.stopPropagation()}
        className="text-[#ccd6f6] hover:text-[#64ffda] hover:underline transition-colors"
      >
        {row.title}
      </a>
    ),
  },
  {
    key: 'source',
    header: 'Source',
    sortKey: 'source',
    width: '150px',
    render: (row) => (
      <Badge
        label={row.source}
        variant={SOURCE_VARIANTS[row.source] ?? 'neutral'}
      />
    ),
  },
  {
    key: 'published_at',
    header: 'Published',
    sortKey: 'published_at',
    width: '130px',
    render: (row) => (
      <span className="text-[#8892b0] text-xs">{formatDate(row.published_at)}</span>
    ),
  },
  {
    key: 'technique_count',
    header: 'Techniques',
    width: '100px',
    align: 'center',
    render: (row) =>
      row.technique_count > 0 ? (
        <Badge label={String(row.technique_count)} variant="teal" />
      ) : (
        <span className="text-[#8892b0] text-xs">—</span>
      ),
  },
];

export function ReportsList() {
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const source = searchParams.get('source') ?? '';
  const q = searchParams.get('q') ?? '';
  const defaultSince = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];
  const since = searchParams.get('since') ?? defaultSince;

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) {
          next.set(key, value);
        } else {
          next.delete(key);
        }
        if (key !== 'page') next.set('page', '1');
        return next;
      });
    },
    [setSearchParams],
  );

  const params: Record<string, string> = { page: String(page), limit: '50' };
  if (source) params.source = source;
  if (q) params.search = q;
  if (since) params.since = since;

  const { data, isLoading } = useReports(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Threat Reports"
        subtitle="Intelligence reports from OTX, RSS feeds, and more"
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-end">
        <input
          type="search"
          placeholder="Search reports..."
          value={q}
          onChange={(e) => setParam('q', e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
        <select
          value={source}
          onChange={(e) => setParam('source', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
        >
          <option value="">All Sources</option>
          {SOURCES.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
        <label className="flex flex-col gap-1">
          <span className="text-xs font-medium text-[#8892b0]">Since:</span>
          <input
            type="date"
            value={since}
            onChange={(e) => setParam('since', e.target.value)}
            className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
          />
        </label>
        {/* Quick date filters */}
        <div className="flex gap-1.5">
          {[
            { label: 'This week', days: 7 },
            { label: 'Last 2 weeks', days: 14 },
            { label: 'This month', days: 30 },
            { label: 'All time', days: 0 },
          ].map((f) => {
            const sinceDate = f.days > 0
              ? new Date(Date.now() - f.days * 86400000).toISOString().split('T')[0]
              : '';
            const isActive = since === sinceDate;
            return (
              <button
                key={f.label}
                type="button"
                onClick={() => setParam('since', sinceDate)}
                className={`px-2.5 py-1.5 text-xs rounded-md border transition-colors ${
                  isActive
                    ? 'border-[#64ffda] text-[#64ffda] bg-[#64ffda14]'
                    : 'border-[#2a2a4a] text-[#8892b0] hover:text-[#ccd6f6] hover:border-[#4a4a6a]'
                }`}
              >
                {f.label}
              </button>
            );
          })}
        </div>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.id}
        emptyMessage="No reports found. Trigger a feed sync to populate data."
      />
    </div>
  );
}
