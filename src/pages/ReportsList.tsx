import { useCallback, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { isSafeUrl } from '../lib/urlSafety';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useReports } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { apiFetch } from '../lib/api';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import type { ThreatReport } from '../lib/types';

const FUSE_KEYS = ['title', 'source', 'url'];

/** Clickable technique count that shows linked techniques in a dropdown */
function TechniquePopover({ reportId, count }: { reportId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['report-techniques', reportId],
    queryFn: () => apiFetch<{ data: Array<{ attackId: string; name: string }> }>(`/feed/reports/${reportId}/techniques`),
    enabled: open,
    staleTime: 5 * 60 * 1000,
  });

  const btnRef = useRef<HTMLButtonElement>(null);
  const rect = open && btnRef.current ? btnRef.current.getBoundingClientRect() : null;

  return (
    <span>
      <button
        ref={btnRef}
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen((prev) => !prev); }}
        aria-label={`Show ${count} linked techniques`}
        aria-expanded={open}
        className="cursor-pointer"
      >
        <Badge label={String(count)} variant="teal" />
      </button>
      {open && rect && createPortal(
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
            onKeyDown={(e) => { if (e.key === 'Escape') setOpen(false); }}
            role="button"
            aria-label="Close popover"
            tabIndex={-1}
          />
          <div
            className="fixed z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl p-3 min-w-[240px] max-h-[300px] overflow-y-auto"
            style={{ top: rect.bottom + 4, left: Math.max(8, rect.right - 240) }}
          >
            <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-2">
              Linked Techniques ({count})
            </div>
            {isLoading && (
              <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs py-2">
                <span className="inline-block w-3 h-3 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
                Loading...
              </div>
            )}
            {data?.data && (
              <div className="flex flex-col gap-1">
                {data.data.map((t) => (
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
                ))}
              </div>
            )}
            {!isLoading && data?.data?.length === 0 && (
              <span className="text-xs text-[var(--text-secondary)]">No techniques found.</span>
            )}
          </div>
        </>,
        document.body,
      )}
    </span>
  );
}

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

const columns: ColumnDef<ThreatReport>[] = [
  {
    key: 'title',
    header: 'Title',
    sortKey: 'title',
    render: (row) =>
      isSafeUrl(row.url) ? (
        <a
          href={row.url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="text-[var(--text-primary)] hover:text-[var(--accent-teal)] hover:underline transition-colors"
        >
          {row.title}
        </a>
      ) : (
        <span className="text-[var(--text-primary)]">{row.title}</span>
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
      <span className="text-[var(--text-secondary)] text-xs">{formatDate(row.published_at)}</span>
    ),
  },
  {
    key: 'technique_count',
    header: 'Techniques',
    width: '100px',
    align: 'center',
    render: (row) =>
      row.technique_count > 0 ? (
        <TechniquePopover reportId={row.id} count={row.technique_count} />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
];

export function ReportsList() {

  const [searchParams, setSearchParams] = useSearchParams();
  const { sectorParam } = useSector();
  const [q, setQ] = useState(searchParams.get('q') ?? '');

  const source = searchParams.get('source') ?? '';
  const defaultSince = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];
  const since = searchParams.has('since') ? (searchParams.get('since') ?? '') : defaultSince;

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) {
          next.set(key, value);
        } else if (key === 'since') {
          next.set(key, ''); // keep empty to represent "all time"
        } else {
          next.delete(key);
        }
        return next;
      });
    },
    [setSearchParams],
  );

  const params: Record<string, string> = { limit: '5000', ...sectorParam };
  if (source) params.source = source;
  if (since) params.since = since;

  const { data, isLoading } = useReports(params);

  const filteredData = useFuseFilter(data?.data ?? [], FUSE_KEYS, q);

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
          onChange={(e) => setQ(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={source}
          onChange={(e) => setParam('source', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Sources</option>
          {SOURCES.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
        <label className="flex flex-col gap-1">
          <span className="text-xs font-medium text-[var(--text-secondary)]">Since:</span>
          <input
            type="date"
            value={since}
            onChange={(e) => setParam('since', e.target.value)}
            className="px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
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
                    ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-faint)]'
                    : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-hover)]'
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
        data={filteredData}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyMessage="No reports found. Trigger a feed sync to populate data."
      />
    </div>
  );
}
