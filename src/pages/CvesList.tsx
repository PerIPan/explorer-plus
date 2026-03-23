import { useCallback, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useCves } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';
import type { CveEntry } from '../lib/types';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SOURCES = ['otx', 'cisa_kev'];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

const SOURCE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  otx: 'teal',
  cisa_kev: 'blue',
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  const classes = SEVERITY_COLORS[severity] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}>
      {severity}
    </span>
  );
}

/** Clipboard copy button */
function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {/* silent */});
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

/** Clickable technique count with popover */
function TechniquePopover({ cveId, count }: { cveId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['cve-detail', cveId],
    queryFn: () => apiFetch<{ techniques: Array<{ attackId: string; name: string }> }>(`/cves/${cveId}`),
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
            {data?.techniques && (
              <div className="flex flex-col gap-1">
                {data.techniques.map((t) => (
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} />
                ))}
              </div>
            )}
            {!isLoading && data?.techniques?.length === 0 && (
              <span className="text-xs text-[var(--text-secondary)]">No techniques found.</span>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

const columns: ColumnDef<CveEntry>[] = [
  {
    key: 'cvssSeverity',
    header: 'Severity',
    width: '100px',
    render: (row) => <SeverityBadge severity={row.cvssSeverity} />,
  },
  {
    key: 'cveId',
    header: 'CVE ID',
    render: (row) => (
      <div className="flex items-center gap-0.5">
        <Link
          to={`/cti/cves/${row.cveId}`}
          className="font-mono text-xs text-[var(--accent-teal)] hover:underline"
        >
          {row.cveId}
        </Link>
        <CopyButton value={row.cveId} />
      </div>
    ),
  },
  {
    key: 'description',
    header: 'Description',
    render: (row) =>
      row.description ? (
        <span
          className="text-xs text-[var(--text-secondary)] max-w-[320px] truncate block"
          title={row.description}
        >
          {row.description}
        </span>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'cvssScore',
    header: 'CVSS',
    width: '70px',
    render: (row) => (
      <span className="text-xs text-[var(--text-primary)] font-mono">
        {row.cvssScore != null ? row.cvssScore.toFixed(1) : '—'}
      </span>
    ),
  },
  {
    key: 'cweId',
    header: 'CWE',
    width: '90px',
    render: (row) =>
      row.cweId ? (
        <span className="text-xs text-[var(--accent-blue)] font-mono">{row.cweId}</span>
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
  {
    key: 'sources',
    header: 'Sources',
    width: '140px',
    render: (row) => (
      <div className="flex flex-wrap gap-1">
        {row.sources.map((s) => (
          <Badge key={s} label={s} variant={SOURCE_VARIANTS[s] ?? 'neutral'} />
        ))}
      </div>
    ),
  },
  {
    key: 'techniqueCount',
    header: 'Techniques',
    width: '100px',
    align: 'center',
    render: (row) =>
      row.techniqueCount > 0 ? (
        <TechniquePopover cveId={row.cveId} count={row.techniqueCount} />
      ) : (
        <span className="text-[var(--text-secondary)] text-xs">—</span>
      ),
  },
];

export function CvesList() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { sectorParam } = useSector();

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const severity = searchParams.get('severity') ?? '';
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

  const params: Record<string, string> = { page: String(page), limit: '100', ...sectorParam };
  if (severity) params.severity = severity;
  if (source) params.source = source;
  if (q) params.q = q;

  const { data, isLoading } = useCves(params);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Vulnerabilities"
        subtitle="Known CVEs from OTX and CISA KEV, enriched with NVD metadata"
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search CVEs..."
          value={q}
          onChange={(e) => setParam('q', e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={severity}
          onChange={(e) => setParam('severity', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
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
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.cveId}
        emptyMessage="No CVEs found. Trigger a feed sync to populate data."
      />
    </div>
  );
}
