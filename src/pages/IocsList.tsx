import { useCallback, useEffect, useRef, useState } from 'react';
import { isSafeUrl } from '../lib/urlSafety';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useIocs } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { apiFetch } from '../lib/api';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';
import { VtLookupModal, VtButton } from '../components/shared/VtLookupModal';
import type { IocEntry } from '../lib/types';

/** Clipboard copy button with brief "Copied!" feedback */
function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {/* silent fail */});
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      title="Copy to clipboard"
      className={`ml-1.5 flex-shrink-0 transition-colors duration-150 ${copied ? 'text-[var(--accent-teal)]' : 'text-[var(--text-secondary)] hover:text-[var(--accent-teal)]'}`}
      aria-label="Copy value"
    >
      {copied ? (
        <span className="text-[10px] font-medium">Copied!</span>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-4 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
    </button>
  );
}

const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email'];
const SOURCES = ['otx', 'threatfox', 'malwarebazaar', 'cisa_kev'];

const TYPE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  ip: 'orange',
  domain: 'teal',
  url: 'blue',
  hash: 'purple',
  email: 'green',
};

const SOURCE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  otx: 'teal',
  threatfox: 'orange',
  malwarebazaar: 'purple',
  cisa_kev: 'blue',
};


/** Generate OTX indicator URL from IOC type and value */
function otxUrl(type: string, value: string): string | null {
  const map: Record<string, string> = {
    cve: 'cve', ip: 'IPv4', domain: 'domain', url: 'url', hash: 'file', email: 'email',
  };
  const otxType = map[type];
  return otxType ? `https://otx.alienvault.com/indicator/${otxType}/${encodeURIComponent(value)}` : null;
}

/** Clickable technique count with popover showing linked techniques */
function TechniquePopover({ iocId, count }: { iocId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['ioc-techniques', iocId],
    queryFn: () => apiFetch<{ data: Array<{ attackId: string; name: string }> }>(`/feed/iocs/${iocId}/techniques`),
    enabled: open,
  });

  return (
    <div className="relative">
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen(!open); }}
        className="cursor-pointer"
      >
        <Badge label={String(count)} variant="teal" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-8 z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl p-3 min-w-[240px] max-h-[300px] overflow-y-auto">
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
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} />
                ))}
              </div>
            )}
            {!isLoading && data?.data?.length === 0 && (
              <span className="text-xs text-[var(--text-secondary)]">No techniques found.</span>
            )}
          </div>
        </>
      )}
    </div>
  );
}


// ── Columns + Page ─────────────────────────────────────────────────────────────

export function IocsList() {

  const [searchParams, setSearchParams] = useSearchParams();
  const { sectorParam } = useSector();
  const [vtHash, setVtHash] = useState<string | null>(null);

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const type = searchParams.get('type') ?? '';
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

  const [qInput, setQInput] = useState(q);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => { setQInput(q); }, [q]);
  const handleQChange = useCallback((value: string) => {
    setQInput(value);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => setParam('q', value), 300);
  }, [setParam]);
  useEffect(() => () => clearTimeout(debounceRef.current), []);

  const params: Record<string, string> = { page: String(page), limit: '100', ...sectorParam };
  if (type) params.type = type;
  if (source) params.source = source;
  if (q) params.q = q;
  if (since) params.since = since;

  const { data, isLoading } = useIocs(params);

  const columns: ColumnDef<IocEntry>[] = [
    {
      key: 'type',
      header: 'Type',
      width: '90px',
      render: (row) => (
        <Badge label={row.type} variant={TYPE_VARIANTS[row.type] ?? 'neutral'} />
      ),
    },
    {
      key: 'value',
      header: 'Value',
      render: (row) => {
        const link = otxUrl(row.type, row.value);
        const showDesc = row.type === 'cve' && row.description;
        const isHash = row.type === 'hash';
        return (
          <div className={showDesc ? 'flex flex-col gap-0.5' : ''}>
            <div className="flex items-center gap-0.5">
              {link && isSafeUrl(link) ? (
                <a
                  href={link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-xs text-[var(--accent-teal)] hover:underline max-w-[240px] truncate"
                  title={row.value}
                >
                  {row.value}
                </a>
              ) : (
                <span
                  className="font-mono text-xs text-[var(--text-primary)] max-w-[240px] truncate"
                  title={row.value}
                >
                  {row.value}
                </span>
              )}
              <CopyButton value={row.value} />
              {isHash && <VtButton hash={row.value} onClick={() => setVtHash(row.value)} />}
            </div>
            {showDesc && (
              <span
                className="text-[11px] text-[var(--text-secondary)] max-w-[320px] truncate"
                title={row.description!}
              >
                {row.description}
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'source',
      header: 'Source',
      width: '140px',
      render: (row) => (
        <Badge label={row.source} variant={SOURCE_VARIANTS[row.source] ?? 'neutral'} />
      ),
    },
    {
      key: 'malware_family',
      header: 'Malware Family',
      width: '160px',
      render: (row) =>
        row.malware_family ? (
          <span className="text-[var(--accent-orange)] text-xs">{row.malware_family}</span>
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
    {
      key: 'first_seen_at',
      header: 'First Seen',
      width: '120px',
      render: (row) => (
        <span className="text-[var(--text-secondary)] text-xs">{formatDate(row.first_seen_at)}</span>
      ),
    },
    {
      key: 'technique_count',
      header: 'Techniques',
      width: '100px',
      align: 'center',
      render: (row) =>
        (row.technique_count ?? 0) > 0 ? (
          <TechniquePopover iocId={row.id} count={row.technique_count!} />
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Indicators of Compromise"
        subtitle="Hashes, domains, IPs, and URLs from ThreatFox, MalwareBazaar, and OTX"
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search IOCs..."
          value={qInput}
          onChange={(e) => handleQChange(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={type}
          onChange={(e) => setParam('type', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Types</option>
          {IOC_TYPES.map((t) => (
            <option key={t} value={t}>{t.toUpperCase()}</option>
          ))}
        </select>
        <select
          value={source}
          onChange={(e) => setParam('source', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Sources</option>
          {SOURCES.map((s) => (
            <option key={s} value={s}>{s}</option>
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
        <div className="flex gap-1.5 items-end">
          {[
            { label: 'This week', days: 7 },
            { label: 'This month', days: 30 },
            { label: '6 months', days: 180 },
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
                    : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--teal-dim)]'
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
        emptyMessage="No IOCs found. Trigger a feed sync to populate data."
      />

      {/* VT Lookup Modal */}
      {vtHash && <VtLookupModal hash={vtHash} onClose={() => setVtHash(null)} />}
    </div>
  );
}
