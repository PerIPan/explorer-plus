import { useCallback, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useIocs } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { Badge } from '../components/shared/Badge';
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
      className={`ml-1.5 flex-shrink-0 transition-colors duration-150 ${copied ? 'text-[#64ffda]' : 'text-[#8892b0] hover:text-[#64ffda]'}`}
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

const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'cve', 'email'];
const SOURCES = ['otx', 'threatfox', 'malwarebazaar', 'cisa_kev'];

const TYPE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  ip: 'orange',
  domain: 'teal',
  url: 'blue',
  hash: 'purple',
  cve: 'pink',
  email: 'green',
};

const SOURCE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  otx: 'teal',
  threatfox: 'orange',
  malwarebazaar: 'purple',
  cisa_kev: 'blue',
};

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

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
    render: (row) => (
      <div className="flex items-center gap-0.5">
        <span
          className="font-mono text-xs text-[#ccd6f6] max-w-[240px] truncate"
          title={row.value}
        >
          {row.value}
        </span>
        <CopyButton value={row.value} />
      </div>
    ),
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
        <span className="text-[#f97316] text-xs">{row.malware_family}</span>
      ) : (
        <span className="text-[#8892b0] text-xs">—</span>
      ),
  },
  {
    key: 'first_seen_at',
    header: 'First Seen',
    width: '120px',
    render: (row) => (
      <span className="text-[#8892b0] text-xs">{formatDate(row.first_seen_at)}</span>
    ),
  },
];

export function IocsList() {
  const [searchParams, setSearchParams] = useSearchParams();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const type = searchParams.get('type') ?? '';
  const source = searchParams.get('source') ?? '';
  const q = searchParams.get('q') ?? '';

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

  const params: Record<string, string> = { page: String(page), limit: '100' };
  if (type) params.type = type;
  if (source) params.source = source;
  if (q) params.search = q;

  const { data, isLoading } = useIocs(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Indicators of Compromise"
        subtitle="IOCs from ThreatFox, MalwareBazaar, OTX, and CISA KEV"
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search IOCs..."
          value={q}
          onChange={(e) => setParam('q', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
        />
        <select
          value={type}
          onChange={(e) => setParam('type', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
        >
          <option value="">All Types</option>
          {IOC_TYPES.map((t) => (
            <option key={t} value={t}>{t.toUpperCase()}</option>
          ))}
        </select>
        <select
          value={source}
          onChange={(e) => setParam('source', e.target.value)}
          className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
        >
          <option value="">All Sources</option>
          {SOURCES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
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
    </div>
  );
}
